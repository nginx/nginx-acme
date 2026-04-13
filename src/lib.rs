// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

#![no_std]
extern crate std;

use core::ffi::{c_char, c_void};
use core::time::Duration;
use core::{cmp, ptr};

use nginx_sys::{
    ngx_conf_t, ngx_cycle_t, ngx_http_add_variable, ngx_http_module_t, ngx_int_t, ngx_module_t,
    ngx_uint_t, NGX_HTTP_MODULE,
};
use ngx::core::{Status, NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::{HttpModule, HttpModuleMainConf, HttpModuleServerConf, Merge};
use ngx::log::ngx_cycle_log;
use time::Interval;
use zeroize::Zeroizing;

use crate::acme::error::{NewAccountError, RequestError};
use crate::acme::AcmeClient;
use crate::conf::{AcmeMainConfig, AcmeServerConfig, NGX_HTTP_ACME_COMMANDS};
use crate::net::http::NgxHttpClient;
use crate::state::certificate::{CertificateIdentifier, SharedCertificateContext};
use crate::time::Timestamp;
use crate::util::{ngx_process, NgxProcess};
use crate::variables::NGX_HTTP_ACME_VARS;

#[macro_use]
mod log;

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

    unsafe extern "C" fn merge_srv_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: HttpModuleServerConf,
        <Self as HttpModuleServerConf>::ServerConf: Merge,
    {
        let prev = &*prev.cast::<AcmeServerConfig>();
        let conf = &mut *conf.cast::<AcmeServerConfig>();

        if conf.merge(prev).is_err() {
            return NGX_CONF_ERROR;
        }

        let cf = unsafe { &mut *cf };

        if acme::solvers::tls_alpn::merge_srv_conf(cf).is_err() {
            return NGX_CONF_ERROR;
        }

        NGX_CONF_OK
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

        /* tls-alpn-01 challenge handler */

        if let Err(err) = acme::solvers::tls_alpn::postconfiguration(cf, amcf) {
            return err.into();
        }

        Status::NGX_OK.into()
    }
}

extern "C" fn ngx_http_acme_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    if !matches!(ngx_process(), NgxProcess::Single | NgxProcess::Worker(0)) {
        return Status::NGX_OK.into();
    }

    // SAFETY: cycle passed to the module callbacks is never NULL
    let cycle = unsafe { &mut *cycle };

    let Some(amcf) = HttpAcmeModule::main_conf(cycle) else {
        return Status::NGX_OK.into();
    };

    if !amcf.is_configured() {
        debug!(cycle.log, "acme: not configured");
        return Status::NGX_OK.into();
    }

    if amcf.issuers.iter().all(|x| x.orders.is_empty()) {
        notice!(cycle.log, "acme: no certificates");
        return Status::NGX_OK.into();
    }

    let task = ngx::async_::spawn(ngx_http_acme_main_loop(amcf));

    // Move task handle to the cycle pool to ensure that it is dropped with the cycle.
    let pool = unsafe { ngx::core::Pool::from_ngx_pool(cycle.pool) };
    if pool.allocate(task).is_null() {
        return Status::NGX_ERROR.into();
    }

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
        let next = (next - Timestamp::now()).max(ACME_MIN_INTERVAL);

        debug!(ngx_cycle_log(), "acme: next update in {next:?}");
        ngx::async_::sleep(next).await;
    }
}

async fn ngx_http_acme_update_certificates(amcf: &AcmeMainConfig) -> Timestamp {
    let log = ngx_cycle_log();
    let now = Timestamp::now();
    let mut next = now + ACME_MAX_INTERVAL;

    for issuer in &amcf.issuers[..] {
        if !issuer.is_valid() {
            continue;
        }

        let issuer_id = issuer.name;
        debug!(log, "acme: updating certificates, acme issuer \"{issuer_id}\"");

        let issuer_next = match ngx_acme_update_certificates_for_issuer(amcf, issuer).await {
            Ok(x) => x,
            Err(err) if err.is::<NewAccountError>() => {
                match err.downcast_ref::<NewAccountError>() {
                    Some(err) if err.is_invalid() => {
                        error!(log, "{err} while creating account, acme issuer \"{issuer_id}\"");
                        issuer.set_invalid(err);
                        continue;
                    }
                    Some(NewAccountError::Request(err @ RequestError::RateLimited(x))) => {
                        warn!(log, "{err} while creating account, acme issuer \"{issuer_id}\"");
                        Timestamp::now() + *x
                    }
                    Some(err) => {
                        warn!(log, "{err} while creating account, acme issuer \"{issuer_id}\"");
                        issuer.set_error(err)
                    }
                    None => unreachable!(),
                }
            }
            Err(err) => {
                warn!(log, "{err} while processing renewals, acme issuer \"{issuer_id}\"");
                now + ACME_DEFAULT_INTERVAL
            }
        };

        next = cmp::min(next, issuer_next);
    }

    next
}

async fn ngx_acme_update_certificates_for_issuer(
    amcf: &AcmeMainConfig,
    issuer: &conf::issuer::Issuer,
) -> Result<Timestamp, ngx::allocator::Box<dyn core::error::Error>> {
    let log = ngx_cycle_log();
    let http = NgxHttpClient::new(
        log,
        issuer.resolver.unwrap(),
        issuer.resolver_timeout,
        issuer.ssl.as_ref(),
    );
    let mut client = AcmeClient::new(http, issuer, log)?;

    let amsh = amcf.data.expect("acme shared data");

    match issuer.challenge {
        Some(acme::ChallengeKind::Http01) => {
            let http_solver = acme::solvers::http::Http01Solver::new(&amsh.http_01_state);
            client.add_solver(http_solver);
        }
        Some(acme::ChallengeKind::TlsAlpn01) => {
            let tls_solver = acme::solvers::tls_alpn::TlsAlpn01Solver::new(&amsh.tls_alpn_01_state);
            client.add_solver(tls_solver);
        }
        _ => unreachable!("invalid configuration"),
    };

    let mut next = Timestamp::MAX;

    for (order, cert) in issuer.orders.iter() {
        let Some(cert) = cert.as_ref() else {
            continue;
        };

        let order_id = order.cache_key();
        let lctx = AcmeLogContext::for_order(issuer, &order_id);

        let mut state = cert.read().state;

        if state.is_invalid() {
            continue;
        }

        let pool = crate::util::OwnedPool::with_default_size(log)?;

        if state.can_update_renewal_info() {
            if client.supports_renewal_info().await? {
                let identifier = cert.read().certificate_identifier(&*pool);
                let identifier = match identifier {
                    Ok(x) => x,
                    Err(err) => {
                        warn!(log, "{err} while updating renewal info, {lctx}");
                        let ari_next = cert.write().set_error(&err);
                        next = cmp::min(next, ari_next);
                        continue;
                    }
                };

                let ari_next =
                    ngx_acme_update_renewal_info(&client, &identifier, cert, &lctx).await;

                next = cmp::min(next, ari_next);
            } else {
                // ARI is not supported; fall back to a lifetime-based renewal schedule.
                cert.write().schedule_renewal();
            }

            // ARI can mark the certificate as expired.
            state = cert.read().state;
        }

        if !state.can_update_certificate() {
            if let Some(cert_next) = state.next_update() {
                next = cmp::min(next, cert_next);
            }

            debug!(log, "acme: certificate is not due for renewal, {lctx}");
            continue;
        }

        if !client.is_ready() {
            match client.new_account().await? {
                acme::NewAccountOutput::Created(x) => {
                    info!(log, "account \"{x}\" created, {lctx}");
                    let _ = issuer.write_state_file(conf::issuer::ACCOUNT_URL_FILE, x.as_bytes());
                }
                acme::NewAccountOutput::Found(x) => {
                    debug!(log, "account \"{x}\" found, {lctx}");
                }
            }
        }

        let replaces = if client.supports_renewal_info().await? {
            cert.read().certificate_identifier(&*pool).ok()
        } else {
            None
        };

        let replaces = replaces.as_ref().map(|x| x.as_ref());

        let new_cert = match client.new_certificate(order, replaces).await {
            Ok(x) => x,
            Err(acme::error::NewCertificateError::Request(err @ RequestError::RateLimited(x))) => {
                warn!(log, "{err} while updating certificate, {lctx}");
                return Ok(Timestamp::now() + x);
            }
            Err(ref err) if err.is_invalid() => {
                error!(log, "{err} while updating certificate, {lctx}");
                cert.write().set_invalid(&err);

                // We marked the order as invalid and will stop attempting to update it until the
                // next configuration reload. It should not affect the next update schedule.

                continue;
            }
            Err(ref err) => {
                warn!(log, "{err} while updating certificate, {lctx}");
                cert.write().set_error(&err);
                continue;
            }
        };

        let now = Timestamp::now();
        let pkey = Zeroizing::new(new_cert.pkey.private_key_to_pem_pkcs8()?);
        let valid = Interval::from_x509(&new_cert.x509[0]).unwrap_or(Interval::new(now, now));

        // Write files even if we fail to update the shared zone later.

        if issuer.write_state_file(std::format!("{order_id}.crt"), &new_cert.bytes).is_err() {
            warn!(log, "writing certificate to state directory failed, {lctx}");
        } else if !matches!(order.key, conf::pkey::PrivateKey::File(_))
            && issuer.write_state_file(std::format!("{order_id}.key"), &pkey).is_err()
        {
            warn!(log, "writing private key to state directory failed, {lctx}");
        }

        let res = cert.write().set(&new_cert.bytes, &pkey, valid);
        let mut cert_next = match res {
            Ok(x) => x,
            Err(err) => {
                warn!(log, "{err} while updating certificate, {lctx}");
                next = cmp::min(next, cert.write().set_error(&err));
                continue;
            }
        };

        info!(log, "certificate issued, renewal scheduled at {cert_next}, {lctx}");

        // RFC9773 § 4.3: Clients SHOULD fetch a certificate's RenewalInfo immediately
        // after issuance.

        if client.supports_renewal_info().await? {
            // Update cert.state for correct set_error behavior.
            cert.write().schedule_renewal_info_update();

            cert_next = match CertificateIdentifier::from_x509(&new_cert.x509[0], &*pool) {
                Ok(identifier) => {
                    ngx_acme_update_renewal_info(&client, &identifier, cert, &lctx).await
                }
                Err(err) => {
                    warn!(client, "{err} while updating renewal info, {lctx}");
                    cert.write().set_error(&err)
                }
            }
        }

        next = cmp::min(next, cert_next);
    }
    Ok(next)
}

async fn ngx_acme_update_renewal_info<Http>(
    client: &AcmeClient<'_, Http>,
    identifier: &CertificateIdentifier<&ngx::core::Pool>,
    cert: &SharedCertificateContext,
    lctx: &AcmeLogContext<'_>,
) -> Timestamp
where
    Http: net::http::HttpClient,
    RequestError: From<<Http as net::http::HttpClient>::Error>,
{
    let lctx = lctx.with_identifier(identifier);

    let (info, expires) = match client.renewal_info(identifier).await {
        Ok(x) => x,
        Err(err) => {
            let next = cert.write().set_error(&err);
            warn!(client, "{err} while updating renewal info, {lctx}");
            return next;
        }
    };

    if cert.read().renewal_window != info.suggested_window {
        let win = info.suggested_window;

        if let Some(url) = info.explanation_url {
            info!(client, "CA suggested renewal window: {win}, see {url} for details, {lctx}");
        } else {
            info!(client, "CA suggested renewal window: {win}, {lctx}");
        }
    }

    let expires = Timestamp::now() + expires;
    let rc = cert.write().set_renewal_info(identifier, info.suggested_window, expires);
    rc.unwrap_or_else(|(x, err)| {
        warn!(client, "{err} while updating renewal info, {lctx}");
        x
    })
}

struct AcmeLogContext<'a> {
    issuer: nginx_sys::ngx_str_t,
    order: Option<&'a dyn core::fmt::Display>,
    identifier: Option<&'a dyn core::fmt::Display>,
}

impl core::fmt::Display for AcmeLogContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("acme issuer: \"{}\"", self.issuer))?;

        if let Some(order) = self.order {
            f.write_fmt(format_args!(", order: \"{order}\""))?;
        }

        if let Some(identifier) = self.identifier {
            f.write_fmt(format_args!(", identifier: \"{identifier}\""))?;
        }

        Ok(())
    }
}

impl<'a> AcmeLogContext<'a> {
    pub fn for_order(issuer: &'a conf::issuer::Issuer, order: &'a dyn core::fmt::Display) -> Self {
        Self { issuer: issuer.name, order: Some(order), identifier: None }
    }

    pub fn with_identifier(&self, identifier: &'a dyn core::fmt::Display) -> Self {
        Self { identifier: Some(identifier), ..*self }
    }
}
