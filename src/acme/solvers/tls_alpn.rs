// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_int, c_uint, c_void, CStr};
use core::{ptr, slice};

use nginx_sys::{ngx_conf_t, NGX_LOG_ERR};
use ngx::allocator::Allocator;
use ngx::collections::RbTreeMap;
use ngx::core::{NgxString, SlabPool, Status};
use ngx::http::HttpModuleServerConf;
use ngx::sync::RwLock;
use ngx::{ngx_log_debug, ngx_log_error};
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{self, extension as x509_ext, X509};
use openssl_foreign_types::ForeignType;
use openssl_sys::SSL_CTX_set_cert_cb;
use openssl_sys::{
    SSL_CTX_set_alpn_select_cb__fixed_rust as SSL_CTX_set_alpn_select_cb, SSL_get_ex_data,
};
use openssl_sys::{SSL_TLSEXT_ERR_ALERT_FATAL, SSL_TLSEXT_ERR_OK};
use zeroize::{Zeroize, Zeroizing};

use crate::acme;
use crate::acme::types::ChallengeKind;
use crate::conf::identifier::Identifier;
use crate::conf::AcmeMainConfig;

use super::{ChallengeSolver, SolverError};

/// `openssl-sys` does not publish these constants.
#[allow(non_upper_case_globals)]
const TLSEXT_TYPE_application_layer_protocol_negotiation: c_uint = 16;

/// Registers tls-alpn-01 in the server merge configuration handler.
pub fn merge_srv_conf(cf: &mut ngx_conf_t, amcf: &mut AcmeMainConfig) -> Result<(), Status> {
    let sscf = ngx::http::NgxHttpSslModule::server_conf(cf).expect("ssl server conf");
    if sscf.ssl.ctx.is_null() {
        return Ok(());
    }

    unsafe {
        openssl_sys::SSL_CTX_set_client_hello_cb(
            sscf.ssl.ctx.cast(),
            Some(ssl_client_hello_cb),
            ptr::from_mut(amcf).cast(),
        )
    };

    Ok(())
}

/// Registers tls-alpn-01 challenge handler.
pub fn postconfiguration(_cf: &mut ngx_conf_t, amcf: &mut AcmeMainConfig) -> Result<(), Status> {
    let amcfp: *mut c_void = ptr::from_mut(amcf).cast();

    amcf.ssl.init(amcfp)?;

    let ssl_ctx: *mut openssl_sys::SSL_CTX = amcf.ssl.as_ref().ctx.cast();

    unsafe { SSL_CTX_set_cert_cb(ssl_ctx, Some(ssl_cert_cb), amcfp) };
    unsafe { SSL_CTX_set_alpn_select_cb(ssl_ctx, Some(ssl_alpn_select_cb), ptr::null_mut()) };

    Ok(())
}

pub type TlsAlpn01SolverState<A> = RbTreeMap<NgxString<A>, TlsAlpn01Response<A>, A>;

#[derive(Debug)]
pub struct TlsAlpn01Solver<'a>(&'a RwLock<TlsAlpn01SolverState<SlabPool>>);

#[derive(Debug)]
pub struct TlsAlpn01Response<A>
where
    A: Allocator + Clone,
{
    pub key_authorization: NgxString<A>,
    pub pkey: NgxString<A>,
}

impl<A> Drop for TlsAlpn01Response<A>
where
    A: Allocator + Clone,
{
    fn drop(&mut self) {
        let bytes: &mut [u8] = self.pkey.as_mut();
        bytes.zeroize();
    }
}

impl<'a> TlsAlpn01Solver<'a> {
    pub fn new(inner: &'a RwLock<TlsAlpn01SolverState<SlabPool>>) -> Self {
        Self(inner)
    }
}

impl ChallengeSolver for TlsAlpn01Solver<'_> {
    fn supports(&self, c: &ChallengeKind) -> bool {
        matches!(c, ChallengeKind::TlsAlpn01)
    }

    fn register(
        &self,
        ctx: &acme::AuthorizationContext,
        identifier: &Identifier<&str>,
        challenge: &acme::types::Challenge,
    ) -> Result<(), SolverError> {
        let alloc = self.0.read().allocator().clone();

        let mut key_authorization = NgxString::new_in(alloc.clone());
        key_authorization.try_reserve_exact(challenge.token.len() + ctx.thumbprint.len() + 1)?;
        // write to a preallocated buffer of a sufficient size should succeed
        let _ = key_authorization.append_within_capacity(challenge.token.as_bytes());
        let _ = key_authorization.append_within_capacity(b".");
        let _ = key_authorization.append_within_capacity(ctx.thumbprint);
        let pkey = Zeroizing::new(ctx.pkey.private_key_to_pem_pkcs8()?);
        let pkey = NgxString::try_from_bytes_in(pkey, alloc.clone())?;
        let resp = TlsAlpn01Response {
            key_authorization,
            pkey,
        };
        let servername = NgxString::try_from_bytes_in(identifier.value(), alloc.clone())?;
        self.0.write().try_insert(servername, resp)?;
        Ok(())
    }

    fn unregister(
        &self,
        identifier: &Identifier<&str>,
        _challenge: &acme::types::Challenge,
    ) -> Result<(), SolverError> {
        self.0.write().remove(identifier.value().as_bytes());
        Ok(())
    }
}

struct TlsAlpnIter<'a>(&'a [u8]);

impl<'a> TlsAlpnIter<'a> {
    pub fn new(buf: &'a [u8]) -> Option<TlsAlpnIter<'a>> {
        let (len, buf) = buf.split_first_chunk::<2>()?;

        if buf.len() < u16::from_be_bytes(*len).into() {
            return None;
        }

        Some(Self(buf))
    }
}

impl<'a> Iterator for TlsAlpnIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (len, mut buf) = self.0.split_first_chunk::<1>()?;

        let len = u8::from_be_bytes(*len) as usize;
        if buf.len() < len {
            return None; // error?
        }

        (buf, self.0) = buf.split_at(len);

        Some(buf)
    }
}

fn acme_ssl_get_alpn(ssl: &mut openssl_sys::SSL) -> Option<&[u8]> {
    let mut p: *const core::ffi::c_uchar = ptr::null_mut();
    let mut len = 0usize;

    let rc = unsafe {
        openssl_sys::SSL_client_hello_get0_ext(
            ssl,
            TLSEXT_TYPE_application_layer_protocol_negotiation,
            ptr::addr_of_mut!(p),
            &mut len,
        )
    };

    // XXX: len == 0 is an obvious error
    if rc == 0 || len == 0 {
        return None;
    }

    Some(unsafe { slice::from_raw_parts(p, len) })
}

unsafe extern "C" fn ssl_client_hello_cb(
    ssl: *mut openssl_sys::SSL,
    _alert: *mut c_int,
    data: *mut c_void,
) -> c_int {
    use openssl_sys::{SSL_CLIENT_HELLO_ERROR, SSL_CLIENT_HELLO_SUCCESS};

    let c: *mut ngx::ffi::ngx_connection_t =
        SSL_get_ex_data(ssl, ngx::ffi::ngx_ssl_connection_index).cast();

    let Some(alpn) = acme_ssl_get_alpn(&mut *ssl) else {
        return SSL_CLIENT_HELLO_SUCCESS;
    };

    let Some(mut iter) = TlsAlpnIter::new(alpn) else {
        ngx_log_error!(ngx::ffi::NGX_LOG_ERR, (*c).log, "invalid alpn");
        return SSL_CLIENT_HELLO_ERROR;
    };

    if iter.any(|x| x == b"acme-tls/1") {
        let Some(amcf) = data.cast::<AcmeMainConfig>().as_mut() else {
            return SSL_CLIENT_HELLO_ERROR;
        };

        if !ssl_switch_context(&mut *ssl, amcf.ssl.as_ref()) {
            ngx_log_error!(
                ngx::ffi::NGX_LOG_ERR,
                (*c).log,
                "acme: failed to switch SslContext"
            );
            return SSL_CLIENT_HELLO_ERROR;
        }
    }

    SSL_CLIENT_HELLO_SUCCESS
}

unsafe fn ssl_switch_context(ssl_conn: &mut openssl_sys::SSL, ssl: &nginx_sys::ngx_ssl_t) -> bool {
    use openssl_sys::{
        SSL_CTX_get_options, SSL_CTX_get_verify_callback, SSL_CTX_get_verify_mode,
        SSL_clear_options, SSL_get_options, SSL_set_SSL_CTX, SSL_set_options, SSL_set_verify,
    };

    if ssl.ctx.is_null() {
        return false;
    }
    let ssl_ctx: *mut openssl_sys::SSL_CTX = ssl.ctx.cast();

    if SSL_set_SSL_CTX(ssl_conn, ssl_ctx).is_null() {
        return false;
    }

    SSL_set_verify(
        ssl_conn,
        SSL_CTX_get_verify_mode(ssl_ctx),
        SSL_CTX_get_verify_callback(ssl_ctx),
    );

    SSL_clear_options(
        ssl_conn,
        SSL_get_options(ssl_conn) & !SSL_CTX_get_options(ssl_ctx),
    );
    SSL_set_options(ssl_conn, SSL_CTX_get_options(ssl_ctx));
    SSL_set_options(ssl_conn, openssl::ssl::SslOptions::NO_RENEGOTIATION.bits());

    true
}

unsafe extern "C" fn ssl_cert_cb(ssl: *mut openssl_sys::SSL, data: *mut c_void) -> c_int {
    use openssl_sys::{SSL_get_servername, SSL_use_PrivateKey, SSL_use_certificate};

    let amcf: *mut AcmeMainConfig = data.cast();

    let Some(mut c) = ptr::NonNull::<ngx::ffi::ngx_connection_t>::new(
        SSL_get_ex_data(ssl, ngx::ffi::ngx_ssl_connection_index).cast(),
    ) else {
        return 0;
    };
    let log = c.as_ref().log;

    let name = SSL_get_servername(ssl, openssl_sys::TLSEXT_NAMETYPE_host_name as _);
    if name.is_null() {
        ngx_log_error!(NGX_LOG_ERR, log, "acme/tls-alpn-01: missing server name");
        return 0;
    }

    let name = CStr::from_ptr(name);
    let Ok(name) = name.to_str() else {
        ngx_log_error!(
            NGX_LOG_ERR,
            log,
            "acme/tls-alpn-01: invalid server name: {name:?}"
        );
        return 0;
    };

    let Some(amsh) = (*amcf).data else {
        return 0;
    };

    let (pkey, auth) = if let Some(resp) = amsh.tls_alpn_01_state.read().get(name.as_bytes()) {
        (resp.pkey.clone(), resp.key_authorization.clone())
    } else {
        ngx_log_debug!(log, "acme/tls-alpn-01: no challenge registered for {name}",);
        return 0;
    };

    ngx_log_debug!(log, "acme/tls-alpn-01: challenge for {name}");

    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(auth.as_bytes());
    let auth = hasher.finish();

    let id = Identifier::Dns(name);
    // XXX: fallback to key generation
    let pkey = match PKey::private_key_from_pem(pkey.as_bytes()) {
        Ok(pkey) => pkey,
        Err(err) => {
            ngx_log_error!(NGX_LOG_ERR, log, "acme/tls-alpn-01: handler failed: {err}");
            return 0;
        }
    };

    let Ok(cert) = make_challenge_cert(&id, &auth, &pkey) else {
        return 0;
    };

    if SSL_use_certificate(ssl, cert.as_ptr()) != 1 {
        return 0;
    }

    if SSL_use_PrivateKey(ssl, pkey.as_ptr()) != 1 {
        return 0;
    }

    c.as_mut().set_close(1);
    1
}

extern "C" fn ssl_alpn_select_cb(
    _ssl: *mut openssl_sys::SSL,
    out: *mut *const u8,
    outlen: *mut u8,
    r#in: *const u8,
    inlen: core::ffi::c_uint,
    _data: *mut c_void,
) -> c_int {
    let srv = b"\x00\x0aacme-tls/1";

    match unsafe {
        openssl_sys::SSL_select_next_proto(
            out as _,
            outlen,
            srv.as_ptr(),
            srv.len() as _,
            r#in,
            inlen,
        )
    } {
        openssl_sys::OPENSSL_NPN_NEGOTIATED => SSL_TLSEXT_ERR_OK,
        _ => SSL_TLSEXT_ERR_ALERT_FATAL as _,
    }
}

pub fn make_challenge_cert(
    identifier: &Identifier<&str>,
    key_authorization: &[u8],
    pkey: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let mut x509_name = x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", identifier.value())?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(30)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(x509_ext::BasicConstraints::new().build()?)?;
    cert_builder.append_extension(
        x509_ext::KeyUsage::new()
            .critical()
            .digital_signature()
            .key_cert_sign()
            .build()?,
    )?;
    let subject_key_identifier =
        x509_ext::SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let mut subject_alt_name = x509_ext::SubjectAlternativeName::new();
    match identifier {
        Identifier::Dns(name) => {
            subject_alt_name.dns(name);
        }
        Identifier::Ip(addr) => {
            subject_alt_name.ip(addr);
        }
        _ => panic!("unsupported identifier: {identifier:?}"),
    };
    let subject_alt_name = subject_alt_name.build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_alt_name)?;

    /* RFC8737 Section 6.1, id-pe-acmeIdentifier */
    let oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.5.5.7.1.31")?;

    let mut digest = [0u8; 0x22];
    digest[0] = 0x04; // ASN1_OCTET_STRING
    digest[1] = 0x20;
    digest[2..].copy_from_slice(key_authorization);
    let digest = openssl::asn1::Asn1OctetString::new_from_bytes(&digest)?;

    let acme_identifier = x509::X509Extension::new_from_der(&oid, true, &digest)?;
    cert_builder.append_extension(acme_identifier)?;

    cert_builder.sign(pkey, MessageDigest::sha256())?;
    Ok(cert_builder.build())
}
