//! Various SSL configuration utilities.
use core::ffi::{c_void, CStr};
use core::{mem, ptr};

use nginx_sys::{
    ngx_conf_t, ngx_ssl_create, ngx_ssl_error, ngx_ssl_t, ngx_ssl_trusted_certificate, ngx_str_t,
    ngx_uint_t, NGX_LOG_EMERG,
};
use ngx::allocator::AllocError;
use ngx::core::Status;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use openssl_sys::SSL_CTX_set_default_verify_paths;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateFetchError {
    #[error(transparent)]
    Alloc(#[from] AllocError),
    #[error("{0:?}")]
    Fetch(&'static CStr),
    #[error("{0:?} {1}")]
    Ssl(&'static CStr, openssl::error::ErrorStack),
}

#[cfg(ngx_ssl_cache)]
pub fn conf_read_certificate(
    cf: &mut ngx_conf_t,
    name: &str,
) -> Result<openssl::stack::Stack<X509>, CertificateFetchError> {
    conf_ssl_cache_fetch(cf, nginx_sys::NGX_SSL_CACHE_CERT as _, name)
}

#[cfg(not(ngx_ssl_cache))]
pub fn conf_read_certificate(
    _cf: &mut ngx_conf_t,
    name: &str,
) -> Result<std::vec::Vec<X509>, CertificateFetchError> {
    let Ok(buf) = std::fs::read_to_string(name) else {
        return Err(CertificateFetchError::Fetch(c"cannot load certificate"));
    };

    match X509::stack_from_pem(buf.as_bytes()) {
        Ok(x) => Ok(x),
        Err(err) => Err(CertificateFetchError::Ssl(c"cannot load key", err)),
    }
}

#[cfg(ngx_ssl_cache)]
pub fn conf_read_private_key(
    cf: &mut ngx_conf_t,
    name: &str,
) -> Result<PKey<Private>, CertificateFetchError> {
    conf_ssl_cache_fetch(cf, nginx_sys::NGX_SSL_CACHE_PKEY as _, name.as_bytes())
}

#[cfg(not(ngx_ssl_cache))]
pub fn conf_read_private_key(
    _cf: &mut ngx_conf_t,
    name: &str,
) -> Result<PKey<Private>, CertificateFetchError> {
    let Ok(buf) = std::fs::read_to_string(name) else {
        return Err(CertificateFetchError::Fetch(c"cannot load key"));
    };

    match PKey::private_key_from_pem(buf.as_bytes()) {
        Ok(x) => Ok(x),
        Err(err) => Err(CertificateFetchError::Ssl(c"cannot load key", err)),
    }
}

#[cfg(ngx_ssl_cache)]
fn conf_ssl_cache_fetch<T: openssl_foreign_types::ForeignType>(
    cf: &mut ngx_conf_t,
    ct: ngx_uint_t,
    name: impl AsRef<[u8]>,
) -> Result<T, CertificateFetchError> {
    let mut name = unsafe { copy_bytes_with_nul(cf.pool, name.as_ref())? };
    let mut err: *mut core::ffi::c_char = ptr::null_mut();

    let p = unsafe { nginx_sys::ngx_ssl_cache_fetch(cf, ct, &mut err, &mut name, ptr::null_mut()) };

    if !p.is_null() {
        return Ok(unsafe { T::from_ptr(p.cast()) });
    }

    let err = if err.is_null() {
        c"unknown error"
    } else {
        unsafe { CStr::from_ptr(err) }
    };

    let sslerr = openssl::error::ErrorStack::get();
    if sslerr.errors().is_empty() {
        Err(CertificateFetchError::Fetch(err))
    } else {
        Err(CertificateFetchError::Ssl(err, sslerr))
    }
}

#[cfg(ngx_ssl_cache)]
unsafe fn copy_bytes_with_nul(
    pool: *mut nginx_sys::ngx_pool_t,
    src: &[u8],
) -> Result<ngx_str_t, AllocError> {
    let mut tmp = ngx_str_t::empty();
    tmp.len = src.len() + 1;
    tmp.data = nginx_sys::ngx_pnalloc(pool, tmp.len).cast();
    if tmp.data.is_null() {
        return Err(AllocError);
    }

    ptr::copy_nonoverlapping(src.as_ptr(), tmp.data, src.len());
    *tmp.data.add(tmp.len - 1) = b'\0';

    Ok(tmp)
}

#[derive(Debug)]
pub struct NgxSsl(ngx_ssl_t);

impl AsRef<ngx_ssl_t> for NgxSsl {
    fn as_ref(&self) -> &ngx_ssl_t {
        &self.0
    }
}

impl AsMut<ngx_ssl_t> for NgxSsl {
    fn as_mut(&mut self) -> &mut ngx_ssl_t {
        &mut self.0
    }
}

impl NgxSsl {
    pub fn init(&mut self, data: *mut c_void) -> Result<(), Status> {
        let protocols: ngx_uint_t = (nginx_sys::NGX_SSL_TLSv1_2 | nginx_sys::NGX_SSL_TLSv1_3) as _;

        let rc = unsafe { ngx_ssl_create(&mut self.0, protocols, data) };
        if rc != Status::NGX_OK.0 {
            return Err(Status(rc));
        }

        Ok(())
    }

    pub fn set_verify(&mut self, cf: &mut ngx_conf_t, cert: &mut ngx_str_t) -> Result<(), Status> {
        unsafe {
            let rc = ngx_ssl_trusted_certificate(cf, self.as_mut(), cert, 10);
            if rc != Status::NGX_OK.0 {
                return Err(Status(rc));
            }

            // Use system trust store if no certificates configured.
            if cert.is_empty() && SSL_CTX_set_default_verify_paths(self.0.ctx.cast()) != 1 {
                ngx_ssl_error(
                    NGX_LOG_EMERG as _,
                    cf.log,
                    0,
                    c"SSL_CTX_set_default_verify_paths() failed"
                        .as_ptr()
                        .cast_mut(),
                );
            }
        }

        Ok(())
    }
}

impl Default for NgxSsl {
    fn default() -> Self {
        Self(unsafe { mem::zeroed() })
    }
}

impl Drop for NgxSsl {
    fn drop(&mut self) {
        if !self.0.ctx.is_null() {
            unsafe { nginx_sys::ngx_ssl_cleanup_ctx(ptr::addr_of_mut!(self.0).cast()) }
        }
    }
}
