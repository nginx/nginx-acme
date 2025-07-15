use core::ptr::{self, NonNull};
use core::str;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use http::Uri;
use nginx_sys::{ngx_conf_t, ngx_flag_t, ngx_msec_t, ngx_path_t, ngx_resolver_t, ngx_str_t};
use ngx::allocator::{AllocError, Box};
use ngx::collections::{RbTreeMap, Vec};
use ngx::core::{Pool, Status};
use ngx::http::{HttpModuleLocationConf, NgxHttpCoreModule};
use ngx::ngx_log_debug;
use openssl::pkey::{PKey, Private};
use thiserror::Error;

use super::order::CertificateOrder;
use super::pkey::PrivateKey;
use super::ssl::NgxSsl;
use super::AcmeMainConfig;

const ACCOUNT_KEY_FILE: &str = "account.key";
const NGX_ACME_DEFAULT_RESOLVER_TIMEOUT: ngx_msec_t = 30000;
const NGX_CONF_UNSET_FLAG: ngx_flag_t = nginx_sys::NGX_CONF_UNSET as _;
const NGX_CONF_UNSET_MSEC: ngx_msec_t = nginx_sys::NGX_CONF_UNSET as _;

/// Certificate issuer object configuration.
#[derive(Debug)]
pub struct Issuer {
    pub name: ngx_str_t,
    pub uri: Uri,
    pub account_key: PrivateKey,
    pub contacts: Vec<ngx_str_t, Pool>,
    pub resolver: Option<NonNull<ngx_resolver_t>>,
    pub resolver_timeout: ngx_msec_t,
    pub ssl_trusted_certificate: ngx_str_t,
    pub ssl_verify: ngx_flag_t,
    pub state_path: *mut ngx_path_t,
    // Generated fields
    // ngx_ssl_t stores a pointer to itself in SSL_CTX ex_data.
    pub ssl: Box<NgxSsl, Pool>,
    pub orders: RbTreeMap<CertificateOrder<ngx_str_t, Pool>, (), Pool>,
    pub pkey: Option<PKey<Private>>,
}

#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("cannot load account key: {0}")]
    AccountKey(super::ssl::CertificateFetchError),
    #[error("cannot generate account key: {0}")]
    AccountKeyGen(#[from] super::pkey::PKeyGenError),
    #[error("resolver is not configured")]
    Resolver,
    #[error("memory allocation failed")]
    Alloc(#[from] AllocError),
    #[error("ngx_ssl_create() failed")]
    Ssl,
    #[error("trusted ceritificate configuration failed")]
    SslVerify,
    #[error("invalid UTF-8 sequence")]
    Utf8(#[from] str::Utf8Error),
    #[error("\"uri\" is missing")]
    Uri,
}

impl Issuer {
    pub fn new_in(name: ngx_str_t, alloc: Pool) -> Result<Self, IssuerError> {
        let mut ssl: Box<NgxSsl, Pool> = Box::try_new_in(Default::default(), alloc.clone())?;
        ssl.init(ptr::null_mut()).map_err(|_| IssuerError::Ssl)?;

        Ok(Self {
            name,
            uri: Default::default(),
            account_key: PrivateKey::Unset,
            contacts: Vec::new_in(alloc.clone()),
            resolver: None,
            resolver_timeout: NGX_CONF_UNSET_MSEC,
            ssl_trusted_certificate: ngx_str_t::empty(),
            ssl_verify: NGX_CONF_UNSET_FLAG,
            state_path: ptr::null_mut(),
            ssl,
            pkey: None,
            orders: RbTreeMap::try_new_in(alloc)?,
        })
    }

    /// Finalizes configuration after parsing the issuer block.
    pub fn init(&mut self, cf: &mut ngx_conf_t) -> Result<(), IssuerError> {
        if self.uri.host().is_none() {
            return Err(IssuerError::Uri);
        }

        if matches!(self.account_key, PrivateKey::Unset) {
            self.account_key = PrivateKey::default();
        }

        self.pkey = Some(self.try_init_account_key(cf)?);

        if self.ssl_verify == NGX_CONF_UNSET_FLAG {
            self.ssl_verify = 1;
        }

        if self.ssl_verify != 0
            && self
                .ssl
                .set_verify(cf, &mut self.ssl_trusted_certificate)
                .is_err()
        {
            return Err(IssuerError::SslVerify);
        }

        Ok(())
    }

    /// Finalizes configuration after parsing the whole http block.
    pub fn postconfiguration(&mut self, cf: &mut ngx_conf_t) -> Result<(), IssuerError> {
        // Verify that the resolver is set.
        if self.resolver.is_none() || self.resolver_timeout == NGX_CONF_UNSET_MSEC {
            let clcf = NgxHttpCoreModule::location_conf(cf).expect("http core loc conf");

            if self.resolver.is_none() {
                self.resolver = NonNull::new(clcf.resolver);
            }

            if matches!(
                self.resolver
                    .map(|r| unsafe { r.as_ref() }.connections.nelts),
                Some(0) | None
            ) {
                return Err(IssuerError::Resolver);
            }

            if self.resolver_timeout == NGX_CONF_UNSET_MSEC {
                self.resolver_timeout = if clcf.resolver_timeout != NGX_CONF_UNSET_MSEC {
                    clcf.resolver_timeout
                } else {
                    NGX_ACME_DEFAULT_RESOLVER_TIMEOUT
                }
            }
        }

        Ok(())
    }

    /// Registers a new certificate order.
    pub fn add_certificate_order(
        &mut self,
        cf: &mut ngx_conf_t,
        order: &CertificateOrder<ngx_str_t, Pool>,
    ) -> Result<(), Status> {
        if self.orders.get(order).is_none() {
            ngx_log_debug!(
                cf.log,
                "acme: order \"{}\" created in issuer \"{}\"",
                order.cache_key(),
                self.name
            );

            if self.orders.try_insert(order.clone(), ()).is_err() {
                return Err(Status::NGX_ERROR);
            }
        } else {
            ngx_log_debug!(
                cf.log,
                "acme: order \"{}\" already exists in issuer \"{}\"",
                order.cache_key(),
                self.name
            );
        }

        Ok(())
    }

    /// Recovers an existing account key from the sources listed below or creates a new one:
    ///  - full path specified with `account_key=file`
    ///  - previous configuration cycle
    ///  - state directory
    fn try_init_account_key(&mut self, cf: &mut ngx_conf_t) -> Result<PKey<Private>, IssuerError> {
        if let PrivateKey::File(ref path) = self.account_key {
            let path: &str = (*path).try_into()?;
            return super::ssl::conf_read_private_key(cf, path).map_err(IssuerError::AccountKey);
        }

        if let Some(oamcf) = AcmeMainConfig::old_config(cf) {
            if let Some(oissuer) = oamcf.issuer(&self.name) {
                if oissuer.account_key == self.account_key {
                    if let Some(pkey) = oissuer.pkey.clone() {
                        return Ok(pkey);
                    }
                }
            }
        }

        let state_dir = unsafe { StateDir::from_ptr(self.state_path) };

        if let Some(state_dir) = state_dir {
            let path = state_dir.full_path(ACCOUNT_KEY_FILE);
            let path = path.to_string_lossy();

            if let Ok(pkey) = super::ssl::conf_read_private_key(cf, &path) {
                return Ok(pkey);
            }
        }

        let pkey = self.account_key.generate()?;

        if let Some(state_dir) = state_dir {
            let path = state_dir.full_path(ACCOUNT_KEY_FILE);
            // The only time we need to write to the state_dir during configuration.
            //
            // `ngx_create_paths` at the end of `ngx_init_cycle` will ensure that the directory
            // exists and has correct ownership and permissions. This method is called a bit earlier
            // though, so we have to ensure that the dir exists and is not readable to the world.
            if let Some(parent) = path.parent().filter(|x| !x.exists()) {
                if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(parent) {
                    if err.kind() != std::io::ErrorKind::AlreadyExists {
                        // Ignore the error and stop attempting to save the file.
                        return Ok(pkey);
                    }
                }
            }

            if let Ok(buf) = pkey.private_key_to_pem_pkcs8() {
                // Ignore write errors.
                let _ = state_dir.write(&path, &buf);
            }
        }

        Ok(pkey)
    }
}

/// The StateDir helper encapsulates operations with a persistent state in the state directory.
#[repr(transparent)]
struct StateDir(ngx_path_t);

impl StateDir {
    /// Creates a StateDir reference from a pointer to `ngx_path_t`.
    ///
    /// # Safety
    ///
    /// `path` should be a well-aligned pointer to an `ngx_path_t` or nul.
    pub unsafe fn from_ptr<'a>(path: *const ngx_path_t) -> Option<&'a Self> {
        // SAFETY: the conversion between `ngx_path_t` and `Self` is safe because of
        // `repr(transparent)`.
        path.cast::<Self>().as_ref()
    }

    pub fn full_path(&self, path: impl AsRef<[u8]>) -> PathBuf {
        // TODO: reimplement without heap allocations
        let pb: PathBuf = OsStr::from_bytes(self.0.name.as_bytes()).into();
        pb.join(OsStr::from_bytes(path.as_ref()))
    }

    pub fn write(&self, path: &std::path::Path, data: &[u8]) -> Result<(), std::io::Error> {
        std::fs::write(path, data)
    }
}
