#![no_std]
extern crate std;

use core::ptr;

use nginx_sys::{
    ngx_conf_t, ngx_http_add_variable, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_uint_t,
    NGX_HTTP_MODULE,
};
use ngx::core::Status;
use ngx::http::{HttpModule, HttpModuleMainConf, HttpModuleServerConf};

use crate::conf::{AcmeMainConfig, AcmeServerConfig, NGX_HTTP_ACME_COMMANDS};
use crate::variables::NGX_HTTP_ACME_VARS;

mod conf;
mod state;
mod time;
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
    init_process: None,
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

        Status::NGX_OK.into()
    }
}
