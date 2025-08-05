#![no_std]
extern crate std;

use core::time::Duration;
use core::{cmp, ptr};

use nginx_sys::{
    ngx_conf_t, ngx_cycle_t, ngx_http_add_variable, ngx_http_module_t, ngx_int_t, ngx_module_t,
    ngx_uint_t, NGX_HTTP_MODULE, NGX_LOG_ERR, NGX_LOG_INFO, NGX_LOG_NOTICE, NGX_LOG_WARN,
};
use ngx::allocator::AllocError;
use ngx::core::Status;
use ngx::http::{HttpModule, HttpModuleMainConf, HttpModuleServerConf};
use ngx::log::ngx_cycle_log;
use ngx::{ngx_log_debug, ngx_log_error};
use openssl::x509::X509;
use time::TimeRange;
use zeroize::Zeroizing;

use crate::acme::AcmeClient;
use crate::conf::{AcmeMainConfig, AcmeServerConfig, NGX_HTTP_ACME_COMMANDS};
use crate::net::http::NgxHttpClient;
use crate::time::Time;
use crate::util::{ngx_process, NgxProcess};
use crate::variables::NGX_HTTP_ACME_VARS;

mod acme;
mod conf;
mod jws;
mod net;
mod state;
mod time;
mod util;
mod variables;

#[derive(Debug)]
struct HttpAcmeModule;

static NGX_HTTP_ACME_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(HttpAcmeModule::preconfiguration),
    postconfiguration: Some(HttpAcmeModule::postconfiguration),
    create_main_conf: Some(HttpAcmeModule::create_main_conf),
    init_main_conf: Some(HttpAcmeModule::init_main_conf),
    create_srv_conf: Some(HttpAcmeModule::create_srv_conf),
    merge_srv_conf: Some(HttpAcmeModule::merge_srv_conf),
    create_loc_conf: None,
    merge_loc_conf: None,
};

#[cfg(feature = "export-modules")]
// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
ngx::ngx_modules!(ngx_http_acme_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_acme_module: ngx_module_t = ngx_module_t {
    ctx: ptr::addr_of!(NGX_HTTP_ACME_MODULE_CTX).cast_mut().cast(),
    commands: unsafe { ptr::addr_of_mut!(NGX_HTTP_ACME_COMMANDS[0]) },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: Some(ngx_http_acme_init_worker),
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    ..ngx_module_t::default()
};

unsafe impl HttpModuleMainConf for HttpAcmeModule {
    type MainConf = AcmeMainConfig;
}

unsafe impl HttpModuleServerConf for HttpAcmeModule {
    type ServerConf = AcmeServerConfig;
}

impl HttpModule for HttpAcmeModule {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_acme_module) }
    }

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        for mut v in NGX_HTTP_ACME_VARS {
            let var = ngx_http_add_variable(cf, &mut v.name, v.flags);
            if var.is_null() {
                return Status::NGX_ERROR.into();
            }
            (*var).get_handler = v.get_handler;
            (*var).data = v.data;
        }
        Status::NGX_OK.into()
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cf = unsafe { &mut *cf };
        let amcf = HttpAcmeModule::main_conf_mut(cf).expect("acme main conf");

        if let Err(e) = amcf.postconfiguration(cf) {
            return e.into();
        }

        /* http-01 challenge handler */

        if let Err(err) = acme::solvers::http::postconfiguration(cf, amcf) {
            return err.into();
        };

        Status::NGX_OK.into()
    }
}

extern "C" fn ngx_http_acme_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    if !matches!(ngx_process(), NgxProcess::Single | NgxProcess::Worker(0)) {
        return Status::NGX_OK.into();
    }

    // SAFETY: cycle passed to the module callbacks is never NULL
    let cycle = unsafe { &mut *cycle };

    let amcf = HttpAcmeModule::main_conf(cycle).expect("acme main conf");

    if !amcf.is_configured() {
        ngx_log_debug!(cycle.log, "acme: not configured");
        return Status::NGX_OK.into();
    }

    if amcf.issuers.iter().all(|x| x.orders.is_empty()) {
        ngx_log_error!(NGX_LOG_NOTICE, cycle.log, "acme: no certificates");
        return Status::NGX_OK.into();
    }

    ngx::async_::spawn(ngx_http_acme_main_loop(amcf)).detach();

    Status::NGX_OK.into()
}

// TODO: configure intervals per issuer.
const ACME_MIN_INTERVAL: Duration = Duration::from_secs(30);
const ACME_MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const ACME_DEFAULT_INTERVAL: Duration = ACME_MIN_INTERVAL.saturating_mul(10);

async fn ngx_http_acme_main_loop(amcf: &AcmeMainConfig) {
    loop {
        if unsafe { ngx::ffi::ngx_terminate } != 0 || unsafe { ngx::ffi::ngx_exiting } != 0 {
            return;
        }

        let next = ngx_http_acme_update_certificates(amcf).await;
        let next = (next - Time::now()).max(ACME_MIN_INTERVAL);

        ngx_log_debug!(ngx_cycle_log().as_ptr(), "acme: next update in {next:?}");
        ngx::async_::sleep(next).await;
    }
}

async fn ngx_http_acme_update_certificates(amcf: &AcmeMainConfig) -> Time {
    let log = ngx_cycle_log();
    let now = Time::now();
    let mut next = now + ACME_MAX_INTERVAL;

    ngx_log_debug!(log.as_ptr(), "acme: updating certificates");

    for issuer in &amcf.issuers[..] {
        if !issuer.is_valid() {
            continue;
        }

        let issuer_next = match ngx_http_acme_update_certificates_for_issuer(amcf, issuer).await {
            Ok(x) => x,
            Err(err) => {
                // Check if the server rejected this ACME account configuration.
                if err
                    .downcast_ref::<acme::types::Problem>()
                    .is_some_and(|err| {
                        matches!(err.category(), acme::types::ProblemCategory::Account)
                    })
                {
                    ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "acme issuer \"{}\" is not valid: {}",
                        issuer.name,
                        err
                    );

                    issuer.set_invalid(err.as_ref());
                    continue;
                }

                ngx_log_error!(
                    NGX_LOG_INFO,
                    log.as_ptr(),
                    "update failed for acme issuer \"{}\": {}",
                    issuer.name,
                    err
                );
                now + ACME_DEFAULT_INTERVAL
            }
        };
        next = cmp::min(next, issuer_next);
    }

    next
}

async fn ngx_http_acme_update_certificates_for_issuer(
    amcf: &AcmeMainConfig,
    issuer: &conf::issuer::Issuer,
) -> anyhow::Result<Time> {
    let log = ngx_cycle_log();
    let http = NgxHttpClient::new(
        log,
        issuer.resolver.unwrap(),
        issuer.resolver_timeout,
        issuer.ssl.as_ref(),
        issuer.ssl_verify != 0,
    );
    let mut client = AcmeClient::new(http, issuer, log)?;

    let amsh = amcf.data.expect("acme shared data");

    let http_solver = acme::solvers::http::Http01Solver::new(&amsh.http_01_state);
    client.add_solver(http_solver);

    let mut next = Time::MAX;

    for (order, cert) in issuer.orders.iter() {
        let Some(cert) = cert.as_ref() else {
            continue;
        };

        {
            let locked = cert.read();

            if !locked.is_renewable() {
                ngx_log_debug!(
                    log.as_ptr(),
                    "acme: certificate \"{}/{}\" is not renewable",
                    issuer.name,
                    order.cache_key()
                );
                next = cmp::min(locked.next, next);
                continue;
            }
        }

        if !client.is_ready() {
            client.new_account().await?;
        }

        let alloc = crate::util::OwnedPool::new(nginx_sys::NGX_DEFAULT_POOL_SIZE as _, log)
            .map_err(|_| AllocError)?;

        // Acme client wants &str and we already validated that the identifiers are valid UTF-8.
        let str_order = order.to_str_order(&*alloc);
        let res = client.new_certificate(&str_order).await;

        let cert_next = match res {
            Ok(ref val) => {
                let pkey = Zeroizing::new(val.pkey.private_key_to_pem_pkcs8()?);
                let x509 = X509::from_pem(&val.chain)?;

                let valid =
                    TimeRange::from_x509(&x509).unwrap_or(TimeRange::new(Time::now(), Time::now()));

                let next = match cert.write().set(&val.chain, &pkey, valid) {
                    Ok(x) => x,
                    Err(err) => {
                        ngx_log_error!(
                            NGX_LOG_WARN,
                            log.as_ptr(),
                            "acme certificate \"{}/{}\" request failed: {}",
                            issuer.name,
                            order.cache_key(),
                            err
                        );
                        Time::now() + ACME_MIN_INTERVAL
                    }
                };

                let _ =
                    issuer.write_state_file(std::format!("{}.crt", order.cache_key()), &val.chain);

                if !matches!(order.key, conf::pkey::PrivateKey::File(_)) {
                    let _ =
                        issuer.write_state_file(std::format!("{}.key", order.cache_key()), &pkey);
                }

                next
            }
            Err(ref err) => {
                if let Some(err) = err.downcast_ref::<acme::types::Problem>() {
                    if matches!(
                        err.category(),
                        acme::types::ProblemCategory::Malformed
                            | acme::types::ProblemCategory::Order
                    ) {
                        ngx_log_error!(
                            NGX_LOG_ERR,
                            log.as_ptr(),
                            "acme certificate \"{}/{}\" request is not valid: {}",
                            issuer.name,
                            order.cache_key(),
                            err
                        );
                        cert.write().set_invalid(&err);
                        continue;
                    }
                }

                cert.write().set_error(err.as_ref())
            }
        };

        next = cmp::min(cert_next, next);

        if let Err(e) = res {
            ngx_log_error!(
                NGX_LOG_WARN,
                log.as_ptr(),
                "acme certificate \"{}/{}\" request failed: {}",
                issuer.name,
                order.cache_key(),
                e
            );
        }
    }
    Ok(next)
}
