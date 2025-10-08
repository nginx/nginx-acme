// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt::{self, Write};
use core::hash::{self, Hash, Hasher};
use core::net::IpAddr;
use core::str::Utf8Error;

use nginx_sys::{ngx_conf_t, ngx_http_server_name_t, ngx_str_t};
use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{NgxString, Pool, Status};
use ngx::ngx_log_error;
use siphasher::sip::SipHasher;
use thiserror::Error;

use crate::conf::identifier::Identifier;
use crate::conf::pkey::PrivateKey;

#[derive(Clone, Debug)]
pub struct CertificateOrder<S, A>
where
    A: Allocator,
{
    pub identifiers: Vec<Identifier<S>, A>,
    pub key: PrivateKey,
}

impl<S, A> CertificateOrder<S, A>
where
    A: Allocator,
{
    pub fn new_in(alloc: A) -> Self
    where
        S: Default,
    {
        Self {
            identifiers: Vec::new_in(alloc),
            key: Default::default(),
        }
    }

    /// Generates a stable unique identifier for this order.
    pub fn cache_key(&self) -> PrintableOrderId<'_, S, A>
    where
        S: fmt::Display + hash::Hash,
    {
        PrintableOrderId(self)
    }

    /// Attempts to find the first DNS identifier, with fallback to a first identifier of any kind.
    pub fn first_name(&self) -> Option<&S> {
        let dns = self
            .identifiers
            .iter()
            .find(|x| matches!(x, Identifier::Dns(_)));

        dns.or_else(|| self.identifiers.first())
            .map(Identifier::value)
    }

    pub fn to_str_order<NewA>(&self, alloc: NewA) -> CertificateOrder<&str, NewA>
    where
        NewA: Allocator + Clone,
        S: AsRef<[u8]>,
    {
        let mut identifiers = Vec::<Identifier<&str>, NewA>::new_in(alloc);
        identifiers.extend(self.identifiers.iter().map(|x| x.as_str().unwrap()));

        CertificateOrder {
            identifiers,
            key: self.key.clone(),
        }
    }
}

impl<S: Hash, A> Hash for CertificateOrder<S, A>
where
    A: Allocator,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.identifiers.hash(state);
        self.key.hash(state);
    }
}

impl<S: PartialEq, A> PartialEq for CertificateOrder<S, A>
where
    A: Allocator,
{
    fn eq(&self, other: &Self) -> bool {
        self.identifiers == other.identifiers && self.key == other.key
    }
}

impl<S: Eq, A> Eq for CertificateOrder<S, A> where A: Allocator {}

impl<S: PartialOrd, A> PartialOrd for CertificateOrder<S, A>
where
    A: Allocator,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match self.identifiers.partial_cmp(&other.identifiers) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        self.key.partial_cmp(&other.key)
    }
}

impl<S: Ord, A> Ord for CertificateOrder<S, A>
where
    A: Allocator,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.identifiers.cmp(&other.identifiers) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.key.cmp(&other.key)
    }
}

impl<S, OA> TryCloneIn for CertificateOrder<S, OA>
where
    S: AsRef<[u8]>,
    OA: Allocator,
{
    type Target<A: Allocator + Clone> = CertificateOrder<NgxString<A>, A>;

    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError> {
        let key = self.key.clone();

        let mut identifiers: Vec<Identifier<NgxString<A>>, A> = Vec::new_in(alloc.clone());
        identifiers
            .try_reserve_exact(self.identifiers.len())
            .map_err(|_| AllocError)?;

        for id in &self.identifiers[..] {
            identifiers.push(id.try_clone_in(alloc.clone())?);
        }

        Ok(Self::Target { identifiers, key })
    }
}

#[derive(Debug, Error)]
pub enum IdentifierError {
    #[error("memory allocation failed")]
    Alloc(#[from] AllocError),
    #[error("empty server name")]
    Empty,
    #[error("invalid server name")]
    Invalid,
    #[error("invalid UTF-8 string")]
    Utf8(#[from] Utf8Error),
    #[error("unsupported wildcard server name")]
    Wildcard,
}

impl CertificateOrder<ngx_str_t, Pool> {
    #[inline]
    fn push(&mut self, id: Identifier<ngx_str_t>) -> Result<(), AllocError> {
        self.identifiers.try_reserve(1).map_err(|_| AllocError)?;
        self.identifiers.push(id);
        Ok(())
    }

    pub fn add_server_names(
        &mut self,
        cf: &mut ngx_conf_t,
        server_names: &[ngx_http_server_name_t],
    ) -> Result<(), IdentifierError> {
        for server_name in server_names {
            if !server_name.regex.is_null() {
                ngx_log_error!(
                    nginx_sys::NGX_LOG_WARN,
                    cf.log,
                    "\"acme_certificate\": unsupported regular expression in server_name: {}",
                    server_name.name
                );
                continue;
            }

            // A valid server_name entry that we want to ignore.
            // We'll fail properly later if that's the only entry.
            if server_name.name.is_empty() {
                continue;
            }

            self.try_add_identifier(&server_name.name)?;
        }

        Ok(())
    }

    pub fn try_add_identifier(&mut self, value: &ngx_str_t) -> Result<(), IdentifierError> {
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }

        if core::str::from_utf8(value.as_ref())?
            .parse::<IpAddr>()
            .is_ok()
        {
            return self.push(Identifier::Ip(*value)).map_err(Into::into);
        }

        if value.as_bytes().contains(&b'*') {
            return Err(IdentifierError::Wildcard);
        }

        let host = validate_host(self.identifiers.allocator(), *value).map_err(|st| {
            if st == Status::NGX_ERROR {
                IdentifierError::Alloc(AllocError)
            } else {
                IdentifierError::Invalid
            }
        })?;

        /*
         * The only special syntax we want to support is a leading dot, which matches the domain
         * with "www." and without it.
         * See <https://nginx.org/en/docs/http/server_names.html>
         */

        if let Some(host) = host.strip_prefix(b".") {
            let mut www = NgxString::new_in(self.identifiers.allocator());
            www.try_reserve_exact(host.len + 4)
                .map_err(|_| AllocError)?;
            // write to a buffer of sufficient size will succeed
            let _ = write!(&mut www, "www.{host}");

            let parts = www.into_raw_parts();
            let www = ngx_str_t {
                data: parts.0,
                len: parts.1,
            };

            self.push(Identifier::Dns(www))?;
            self.push(Identifier::Dns(host))?;
        } else {
            self.push(Identifier::Dns(host))?;
        }

        Ok(())
    }
}

/// Unique identifier for the CertificateOrder.
///
/// This identifier should be suitable for logs, file names or cache keys.
pub struct PrintableOrderId<'a, S, A>(&'a CertificateOrder<S, A>)
where
    A: ngx::allocator::Allocator;

impl<S, A> fmt::Display for PrintableOrderId<'_, S, A>
where
    A: ngx::allocator::Allocator,
    S: fmt::Display + hash::Hash,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(name) = self.0.first_name() else {
            return Ok(());
        };

        let mut hasher = SipHasher::default();
        self.0.hash(&mut hasher);

        write!(f, "{name}-{hash:x}", hash = hasher.finish())
    }
}

fn validate_host(pool: &Pool, mut host: ngx_str_t) -> Result<ngx_str_t, Status> {
    let mut pool = pool.clone();
    let rc = Status(unsafe { nginx_sys::ngx_http_validate_host(&mut host, pool.as_mut(), 1) });
    if rc != Status::NGX_OK {
        return Err(rc);
    }
    Ok(host)
}
