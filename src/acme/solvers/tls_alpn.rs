// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! ACME tls-alpn-01 challenge implementation.
//!
//! High level overview:
//!
//! A TLS listener on port 443 intercepts the handshake, checks if the "acme-tls/1" protocol
//! is advertised and diverts the handshake processing from NGINX.
//!
//! A load balancer or ngx_stream_pass_module may forward the connection to an arbitrary port or
//! server. Thus, we should not make an assumption about a listener object that receives the
//! connection, and should allow all the SSL listener objects to accept the challenge verification
//! requests instead.
//!
//! A virtual server can be configured to request client certificates or reject handshakes.
//! Also, Application-Layer Protocol Negotiation (ALPN) handler in NGINX does not have extension
//! points and cannot be instructed to accept an arbitrary protocol.
//! To bypass that, the acme module handler should register before any NGINX callbacks, i.e. as
//! soon soon as the ClientHello is parsed, and switch the `SSL_CTX` to our own one.
//! In OpenSSL this can be achieved with `SSL_CTX_set_client_hello_cb`, in BoringSSL with
//! `SSL_CTX_set_select_certificate_cb` and LibreSSL does not support such functionality.

use core::ffi::{c_int, c_uint, c_void, CStr};
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ptr;

use nginx_sys::{ngx_conf_t, ngx_connection_t, ngx_http_validate_host, ngx_str_t, NGX_LOG_WARN};
use ngx::allocator::Allocator;
use ngx::collections::RbTreeMap;
use ngx::core::{NgxString, SlabPool, Status};
use ngx::http::{HttpModuleMainConf, HttpModuleServerConf};
use ngx::sync::RwLock;
use ngx::{ngx_log_debug, ngx_log_error};
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{self, extension as x509_ext, X509};
use openssl_foreign_types::ForeignType;
use openssl_sys::{SSL_get_ex_data, SSL, SSL_CTX, SSL_TLSEXT_ERR_ALERT_FATAL, SSL_TLSEXT_ERR_OK};
use zeroize::{Zeroize, Zeroizing};

use crate::acme;
use crate::acme::types::ChallengeKind;
use crate::conf::identifier::Identifier;
use crate::conf::AcmeMainConfig;

use super::{ChallengeSolver, SolverError};

const SHA256_DIGEST_LENGTH: usize = 0x20;

/// `openssl-sys` does not publish these constants.
#[allow(non_upper_case_globals)]
const TLSEXT_TYPE_application_layer_protocol_negotiation: c_uint = 16;

/// Registers tls-alpn-01 in the server merge configuration handler.
pub fn merge_srv_conf(cf: &mut ngx_conf_t) -> Result<(), Status> {
    let sscf = ngx::http::NgxHttpSslModule::server_conf(cf).expect("ssl server conf");

    if let Some(ssl_ctx) = unsafe { sscf.ssl.ctx.cast::<SSL_CTX>().as_mut() } {
        SslClientHello::set_callback(ssl_ctx);
    }

    Ok(())
}

/// Registers tls-alpn-01 challenge handler.
pub fn postconfiguration(_cf: &mut ngx_conf_t, amcf: &mut AcmeMainConfig) -> Result<(), Status> {
    use openssl_sys::SSL_CTX_set_cert_cb;
    #[cfg(not(openssl = "openssl"))]
    use openssl_sys::{SSL_CTX_set_alpn_select_cb, SSL_CTX_set_tlsext_servername_callback};
    #[cfg(openssl = "openssl")]
    use openssl_sys::{
        SSL_CTX_set_alpn_select_cb__fixed_rust as SSL_CTX_set_alpn_select_cb,
        SSL_CTX_set_tlsext_servername_callback__fixed_rust as SSL_CTX_set_tlsext_servername_callback,
    };

    let amcfp: *mut c_void = ptr::from_mut(amcf).cast();

    amcf.ssl.init(amcfp)?;

    let ssl_ctx: *mut SSL_CTX = amcf.ssl.as_ref().ctx.cast();

    unsafe {
        /*
         * Server name callback has to be set, because otherwise `ngx_http_ssl_servername` from the
         * initial SSL_CTX will be invoked.
         */
        SSL_CTX_set_tlsext_servername_callback(ssl_ctx, Some(acme_ssl_servername_cb));
        SSL_CTX_set_cert_cb(ssl_ctx, Some(acme_ssl_cert_cb), amcfp);
        SSL_CTX_set_alpn_select_cb(ssl_ctx, Some(acme_ssl_alpn_select_cb), ptr::null_mut());
    }

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
        let servername = NgxString::try_from_bytes_in(identifier.value(), alloc)?;
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

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("no configuration")]
    Configuration,
    #[error("alpn decode error")]
    Decode,
    #[error("SSL_set_SSL_CTX() failed")]
    SetContext,
}

#[cfg(any(openssl = "openssl", openssl = "awslc"))]
struct SslClientHello(ptr::NonNull<SSL>);

#[cfg(any(openssl = "openssl", openssl = "awslc"))]
impl SslClientHello {
    pub fn set_callback(ssl_ctx: &mut SSL_CTX) {
        unsafe {
            openssl_sys::SSL_CTX_set_client_hello_cb(
                ssl_ctx,
                Some(Self::raw_handler),
                ptr::null_mut(),
            )
        };
    }

    fn extension(&self, typ: c_uint) -> Option<&[u8]> {
        let mut p: *const core::ffi::c_uchar = ptr::null_mut();
        let mut len = 0usize;

        let rc =
            unsafe { openssl_sys::SSL_client_hello_get0_ext(self.ssl(), typ, &mut p, &mut len) };
        match (rc, len) {
            (1, 0) => Some(&[]),
            (1, _) => Some(unsafe { core::slice::from_raw_parts(p, len) }),
            _ => None,
        }
    }

    fn ssl(&self) -> *mut SSL {
        self.0.as_ptr()
    }

    extern "C" fn raw_handler(ssl: *mut SSL, alert: *mut c_int, _data: *mut c_void) -> c_int {
        use openssl_sys::{SSL_CLIENT_HELLO_ERROR, SSL_CLIENT_HELLO_SUCCESS};

        let ssl = ptr::NonNull::new(ssl).expect("SSL is always valid in SSL_CTX callbacks");
        let this = Self(ssl);

        match this.handler() {
            #[cfg(ngx_ssl_client_hello_cb)]
            Ok(false) => unsafe {
                nginx_sys::ngx_ssl_client_hello_callback(this.ssl().cast(), alert, ptr::null_mut())
            },
            Ok(_) => SSL_CLIENT_HELLO_SUCCESS,
            Err(Error::Decode) => {
                unsafe { *alert = openssl_sys::SSL_AD_DECODE_ERROR };
                SSL_CLIENT_HELLO_ERROR
            }
            Err(err) => {
                ngx_log_error!(
                    NGX_LOG_WARN,
                    this.connection().log,
                    "acme/tls-alpn-01: {err}"
                );
                SSL_CLIENT_HELLO_ERROR
            }
        }
    }
}

#[cfg(openssl = "boringssl")]
#[repr(transparent)]
struct SslClientHello(openssl_sys::SSL_CLIENT_HELLO);

#[cfg(openssl = "boringssl")]
impl SslClientHello {
    pub fn set_callback(ssl_ctx: &mut SSL_CTX) {
        unsafe { openssl_sys::SSL_CTX_set_select_certificate_cb(ssl_ctx, Some(Self::raw_handler)) };
    }

    fn extension(&self, typ: c_uint) -> Option<&[u8]> {
        let mut p: *const u8 = ptr::null_mut();
        let mut len = 0usize;

        let rc = unsafe {
            openssl_sys::SSL_early_callback_ctx_extension_get(&self.0, typ as _, &mut p, &mut len)
        };
        match (rc, len) {
            (1, 0) => Some(&[]),
            (1, _) => Some(unsafe { core::slice::from_raw_parts(p, len) }),
            _ => None,
        }
    }

    fn ssl(&self) -> *mut SSL {
        self.0.ssl
    }

    extern "C" fn raw_handler(
        client_hello: *const openssl_sys::SSL_CLIENT_HELLO,
    ) -> openssl_sys::ssl_select_cert_result_t {
        // SAFETY: SslClientHello is a transparent wrapper over SSL_CLIENT_HELLO with the same
        // memory layout.
        let this = unsafe { client_hello.cast::<Self>().as_ref() }
            .expect("SSL_CLIENT_HELLO is always valid in SSL_CTX callbacks");

        match this.handler() {
            #[cfg(ngx_ssl_client_hello_cb)]
            Ok(false) => unsafe {
                nginx_sys::ngx_ssl_select_certificate(ptr::from_ref(&this.0).cast())
            },
            Ok(_) => openssl_sys::ssl_select_cert_result_t_ssl_select_cert_success,
            Err(err) => {
                ngx_log_error!(
                    NGX_LOG_WARN,
                    this.connection().log,
                    "acme/tls-alpn-01: {err}"
                );
                openssl_sys::ssl_select_cert_result_t_ssl_select_cert_error
            }
        }
    }
}

impl SslClientHello {
    fn connection(&self) -> &ngx_connection_t {
        unsafe {
            SSL_get_ex_data(self.ssl(), nginx_sys::ngx_ssl_connection_index)
                .cast::<ngx_connection_t>()
                .as_ref()
                .expect("SSL always has an associated ngx_connection_t")
        }
    }

    /// Common part of the ClientHello handler.
    fn handler(&self) -> Result<bool, Error> {
        use openssl_sys::{
            SSL_CTX_get_options, SSL_CTX_get_verify_callback, SSL_CTX_get_verify_mode,
            SSL_clear_options, SSL_get_options, SSL_set_SSL_CTX, SSL_set_options, SSL_set_verify,
        };

        if self
            .extension(TLSEXT_TYPE_application_layer_protocol_negotiation)
            .map(TlsAlpnIter::new)
            .transpose()?
            .map(|mut it| it.any(|x| x == b"acme-tls/1"))
            != Some(true)
        {
            return Ok(false);
        };

        let amcf = unsafe { get_acme_main_conf(self.connection()) }.ok_or(Error::Configuration)?;

        let ssl_ctx = amcf.ssl.as_ref().ctx.cast::<SSL_CTX>();
        if ssl_ctx.is_null() {
            return Err(Error::Configuration);
        }

        unsafe {
            let ssl = self.ssl();

            if SSL_set_SSL_CTX(self.ssl(), ssl_ctx).is_null() {
                return Err(Error::SetContext);
            }

            SSL_set_verify(
                ssl,
                SSL_CTX_get_verify_mode(ssl_ctx),
                SSL_CTX_get_verify_callback(ssl_ctx),
            );

            SSL_clear_options(ssl, SSL_get_options(ssl) & !SSL_CTX_get_options(ssl_ctx));
            SSL_set_options(ssl, SSL_CTX_get_options(ssl_ctx));
            SSL_set_options(ssl, openssl::ssl::SslOptions::NO_RENEGOTIATION.bits());
        }

        Ok(true)
    }
}

/// Gets module configuration from a connection.
///
/// # Safety
///
/// This function must not be called after ngx_http_request_t is created for the connection.
unsafe fn get_acme_main_conf(c: &ngx_connection_t) -> Option<&AcmeMainConfig> {
    unsafe {
        let hc = c.data.cast::<nginx_sys::ngx_http_connection_t>().as_ref()?;
        crate::HttpAcmeModule::main_conf(hc)
    }
}

/// Iterates over all the alpn entries in the buffer.
struct TlsAlpnIter<'a>(&'a [u8]);

impl<'a> TlsAlpnIter<'a> {
    pub fn new(buf: &'a [u8]) -> Result<TlsAlpnIter<'a>, Error> {
        let (len, buf) = buf.split_first_chunk::<2>().ok_or(Error::Decode)?;

        if buf.len() < u16::from_be_bytes(*len).into() {
            return Err(Error::Decode);
        }

        Ok(Self(buf))
    }
}

impl<'a> Iterator for TlsAlpnIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (len, mut buf) = self.0.split_first_chunk::<1>()?;

        let len = u8::from_be_bytes(*len).into();
        (buf, self.0) = buf.split_at_checked(len)?;

        Some(buf)
    }
}

unsafe extern "C" fn acme_ssl_servername_cb(
    _ssl: *mut SSL,
    _al: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    SSL_TLSEXT_ERR_OK
}

unsafe extern "C" fn acme_ssl_cert_cb(ssl: *mut SSL, arg: *mut c_void) -> c_int {
    use openssl_sys::{SSL_get_servername, SSL_use_PrivateKey, SSL_use_certificate};

    let amcf: &AcmeMainConfig = unsafe { &*arg.cast() };

    let Some(c) = (unsafe {
        SSL_get_ex_data(ssl, nginx_sys::ngx_ssl_connection_index)
            .cast::<ngx_connection_t>()
            .as_mut()
    }) else {
        return 0;
    };

    let name = unsafe { SSL_get_servername(ssl, openssl_sys::TLSEXT_NAMETYPE_host_name as _) };
    if name.is_null() {
        return 0;
    }

    let mut name = ngx_str_t {
        data: name.cast_mut().cast(),
        len: unsafe { CStr::from_ptr(name).count_bytes() },
    };

    // Validate `name` and reallocate on the connection pool.
    if !Status(unsafe { ngx_http_validate_host(&mut name, c.pool, 1) }).is_ok() {
        ngx_log_error!(NGX_LOG_WARN, c.log, "acme/tls-alpn-01: invalid server name");
        return 0;
    }

    let id = match acme_parse_ssl_server_name(&mut name) {
        Ok(x) => x,
        Err(err) => {
            ngx_log_error!(
                NGX_LOG_WARN,
                c.log,
                "acme/tls-alpn-01: cannot parse identifer \"{name}\": {err}"
            );
            return 0;
        }
    };

    let Some(amsh) = amcf.data else {
        return 0;
    };

    let (auth, pkey) = if let Some(resp) = amsh.tls_alpn_01_state.read().get(id.value().as_bytes())
    {
        (
            openssl::sha::sha256(resp.key_authorization.as_ref()),
            PKey::private_key_from_pem(resp.pkey.as_ref()),
        )
    } else {
        ngx_log_debug!(c.log, "acme/tls-alpn-01: no challenge registered for {id}",);
        return 0;
    };

    // TODO: consider fallback to a key generation
    let pkey = match pkey {
        Ok(pkey) => pkey,
        Err(err) => {
            ngx_log_error!(
                NGX_LOG_WARN,
                c.log,
                "acme/tls-alpn-01: PEM_read_bio_PrivateKey() failed: {err}"
            );
            return 0;
        }
    };

    ngx_log_debug!(c.log, "acme/tls-alpn-01: challenge for {id}");

    let cert = match make_challenge_cert(&id, &auth, &pkey) {
        Ok(x) => x,
        Err(err) => {
            ngx_log_error!(
                NGX_LOG_WARN,
                c.log,
                "acme/tls-alpn-01: make_challenge_cert({id}) failed: {err}"
            );
            return 0;
        }
    };

    if unsafe { SSL_use_certificate(ssl, cert.as_ptr()) } != 1
        || unsafe { SSL_use_PrivateKey(ssl, pkey.as_ptr()) } != 1
    {
        return 0;
    }

    // Ask ngx_http_ssl_handshake to terminate the connection without logging an error.
    c.set_close(1);

    1
}

#[derive(thiserror::Error, Debug, PartialEq)]
enum ParseIdentifierError {
    #[error("invalid IPv4 reverse mapping")]
    InvalidV4Ptr,
    #[error("invalid IPv6 reverse mapping")]
    InvalidV6Ptr,
    #[error(transparent)]
    Utf8(#[from] core::str::Utf8Error),
}

/// Parses SNI as an ACME identifier according to RFC8555 (DNS) and RFC8738 (IP).
fn acme_parse_ssl_server_name(
    name: &mut ngx_str_t,
) -> Result<Identifier<&str>, ParseIdentifierError> {
    if let Some(v4) = name.strip_suffix(".in-addr.arpa") {
        // RFC1035 § 3.5 encoded IPv4 address.

        let addr = {
            let mut octets = [0u8; 4];
            let mut it = v4.to_str()?.split('.');

            for out in octets.iter_mut().rev() {
                let x = it.next().ok_or(ParseIdentifierError::InvalidV4Ptr)?;
                *out = x.parse().map_err(|_| ParseIdentifierError::InvalidV4Ptr)?
            }

            if it.next().is_some() {
                return Err(ParseIdentifierError::InvalidV4Ptr);
            }

            Ipv4Addr::from(octets)
        };

        // Canonicalize via Ipv4Addr formatter.
        // Overwrite `name` in place, as it already has enough space.
        let mut cur = std::io::Cursor::new(name.as_bytes_mut());
        let _ = std::io::Write::write_fmt(&mut cur, format_args!("{addr}"));
        name.len = cur.position() as usize;

        Ok(Identifier::Ip(name.to_str()?))
    } else if let Some(v6) = name.strip_suffix(".ip6.arpa") {
        // RFC3596 § 2.5 encoded IPv6 address: 32 hexadecimal digits separated by dots.

        let addr = {
            let mut addr: u128 = 0;
            let mut it = v6.as_bytes().split(|x| *x == b'.');

            // Unlike the IPv4 branch above, here we deal with 4-bit values.
            // These can be more efficiently represented as 4-bit windows on u128.

            for shift in (0..128).step_by(4) {
                let x = it.next().ok_or(ParseIdentifierError::InvalidV6Ptr)?;

                if x.len() != 1 {
                    return Err(ParseIdentifierError::InvalidV6Ptr);
                }

                let x = match x[0] {
                    b'0'..=b'9' => x[0] - b'0',
                    b'a'..=b'f' => x[0] + 10 - b'a',
                    _ => return Err(ParseIdentifierError::InvalidV6Ptr),
                };

                // Max value is 0x0f << 124, does not overflow
                addr += (x as u128) << shift;
            }

            if it.next().is_some() {
                return Err(ParseIdentifierError::InvalidV6Ptr);
            }

            Ipv6Addr::from(addr)
        };

        // Canonicalize via Ipv6Addr formatter.
        // Overwrite `name` in place, as it already has enough space.
        let mut cur = std::io::Cursor::new(name.as_bytes_mut());
        let _ = std::io::Write::write_fmt(&mut cur, format_args!("{addr}"));
        name.len = cur.position() as usize;

        Ok(Identifier::Ip(name.to_str()?))
    } else {
        Ok(Identifier::Dns(name.to_str()?))
    }
}

extern "C" fn acme_ssl_alpn_select_cb(
    _ssl: *mut SSL,
    output: *mut *const u8,
    outlen: *mut u8,
    input: *const u8,
    inlen: core::ffi::c_uint,
    _data: *mut c_void,
) -> c_int {
    const SERVER_PROTOCOLS: &[u8] = b"\x0aacme-tls/1";

    let rc = unsafe {
        openssl_sys::SSL_select_next_proto(
            output as _,
            outlen,
            SERVER_PROTOCOLS.as_ptr(),
            SERVER_PROTOCOLS.len() as _,
            input,
            inlen,
        )
    };

    match rc {
        openssl_sys::OPENSSL_NPN_NEGOTIATED => SSL_TLSEXT_ERR_OK,
        _ => SSL_TLSEXT_ERR_ALERT_FATAL as _,
    }
}

pub fn make_challenge_cert(
    identifier: &Identifier<&str>,
    key_authorization: &[u8; SHA256_DIGEST_LENGTH],
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
        _ => return Err(ErrorStack::get()),
    };
    let subject_alt_name = subject_alt_name.build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_alt_name)?;

    /* RFC8737 Section 6.1, id-pe-acmeIdentifier */
    let oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.5.5.7.1.31")?;

    let mut digest = [0u8; SHA256_DIGEST_LENGTH + 2];
    digest[0] = openssl_sys::V_ASN1_OCTET_STRING as _;
    digest[1] = SHA256_DIGEST_LENGTH as _;
    digest[2..].copy_from_slice(key_authorization);
    let digest = openssl::asn1::Asn1OctetString::new_from_bytes(digest.as_slice())?;

    let acme_identifier = x509::X509Extension::new_from_der(&oid, true, &digest)?;
    cert_builder.append_extension(acme_identifier)?;

    cert_builder.sign(pkey, MessageDigest::sha256())?;
    Ok(cert_builder.build())
}

#[cfg(test)]
mod tests {
    use ngx::collections::Vec;

    use super::*;

    #[test]
    fn test_identifier_parser() {
        use super::ParseIdentifierError as Error;

        let pairs: &[(&str, Result<Identifier<&str>, _>)] = &[
            ("example.com", Ok(Identifier::Dns("example.com"))),
            ("1.0.0.127.in-addr.arpa", Ok(Identifier::Ip("127.0.0.1"))),
            ("1.0.0.0.127.in-addr.arpa", Err(Error::InvalidV4Ptr)),
            ("1.0..0.127.in-addr.arpa", Err(Error::InvalidV4Ptr)),
            ("256.0.0.127.in-addr.arpa", Err(Error::InvalidV4Ptr)),
            ("0.0.127.in-addr.arpa", Err(Error::InvalidV4Ptr)),
            (
                "1.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                Ok(Identifier::Ip("fe80::fed:cba1")),
            ),
            (
                "1.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                Err(Error::InvalidV6Ptr),
            ),
            (
                "1.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0..0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                Err(Error::InvalidV6Ptr),
            ),
            (
                "1.a.b.c.d.e.f.g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                Err(Error::InvalidV6Ptr),
            ),
            (
                "1.a.b.c.d.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
                Err(Error::InvalidV6Ptr),
            ),
        ];

        for (sni, expected) in pairs {
            let mut buf: Vec<u8> = Vec::from(sni.as_bytes());
            let mut name = ngx_str_t {
                data: buf.as_mut_ptr(),
                len: buf.len(),
            };

            let rc = acme_parse_ssl_server_name(&mut name);
            assert_eq!(&rc, expected);
        }
    }
}
