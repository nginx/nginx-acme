use nginx_sys::{
    ngx_http_request_t, ngx_http_variable_t, ngx_int_t, ngx_str_t, ngx_variable_value_t,
};
use ngx::core::Status;
use ngx::http::{HttpModuleMainConf, HttpModuleServerConf};
use ngx::ngx_string;

use crate::conf::{AcmeMainConfig, AcmeServerConfig};
use crate::state::certificate::SharedCertificateContext;
use crate::HttpAcmeModule;

pub(crate) static mut NGX_HTTP_ACME_VARS: [ngx_http_variable_t; 2] = [
    ngx_http_variable_t {
        name: ngx_string!("acme_certificate"),
        set_handler: None,
        get_handler: Some(acme_var_certificate),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("acme_certificate_key"),
        set_handler: None,
        get_handler: Some(acme_var_certificate_key),
        data: 0,
        flags: 0,
        index: 0,
    },
];

extern "C" fn acme_var_certificate(
    r: *mut ngx_http_request_t,
    v: *mut ngx_variable_value_t,
    _data: usize,
) -> ngx_int_t {
    let r = unsafe { &mut *r };
    let v = unsafe { &mut *v };

    let amcf = HttpAcmeModule::main_conf(r).expect("acme main conf");
    let ascf = HttpAcmeModule::server_conf(r).expect("acme server conf");

    let Some(cert_data) = lookup_certificate_data(amcf, ascf) else {
        (*v).set_not_found(1);
        return Status::NGX_OK.into();
    };

    let Some(bytes) = cert_data
        .read()
        .chain()
        .and_then(|x| unsafe { ngx_str_t::from_bytes(r.pool, x) })
    else {
        return Status::NGX_ERROR.into();
    };

    v.set_valid(1);
    v.set_no_cacheable(0);
    v.set_not_found(0);
    v.set_len(bytes.len as u32 - 1);
    v.data = bytes.data;

    Status::NGX_OK.into()
}

unsafe extern "C" fn acme_var_certificate_key(
    r: *mut ngx_http_request_t,
    v: *mut ngx_variable_value_t,
    _data: usize,
) -> ngx_int_t {
    let r = unsafe { &mut *r };
    let v = unsafe { &mut *v };

    let amcf = HttpAcmeModule::main_conf(r).expect("acme config");
    let ascf = HttpAcmeModule::server_conf(r).expect("acme server conf");

    let Some(cert_data) = lookup_certificate_data(amcf, ascf) else {
        (*v).set_not_found(1);
        return Status::NGX_OK.into();
    };

    let Some(bytes) = cert_data
        .read()
        .pkey()
        .and_then(|x| unsafe { ngx_str_t::from_bytes(r.pool, x) })
    else {
        return Status::NGX_ERROR.into();
    };

    v.set_valid(1);
    v.set_no_cacheable(0);
    v.set_not_found(0);
    v.set_len(bytes.len as u32 - 1);
    v.data = bytes.data;

    Status::NGX_OK.into()
}

fn lookup_certificate_data<'a>(
    amcf: &'a AcmeMainConfig,
    ascf: &AcmeServerConfig,
) -> Option<&'a SharedCertificateContext> {
    let order = ascf.order.as_ref()?;
    let issuer = amcf.issuer(&ascf.issuer)?;
    issuer.orders.get(order)?.as_ref()
}
