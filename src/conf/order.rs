// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;
use core::hash::{self, Hash, Hasher};
use core::str::Utf8Error;

use nginx_sys::{ngx_conf_t, ngx_http_server_name_t};
use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{NgxString, Pool};
use ngx::ngx_log_error;
use siphasher::sip::SipHasher;
use thiserror::Error;

use crate::conf::ext::NgxConfExt;
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
    #[error("invalid server name: {0}")]
    Invalid(#[from] NameError),
    #[error("invalid UTF-8 string")]
    Utf8(#[from] Utf8Error),
}

impl CertificateOrder<&'static str, Pool> {
    #[inline]
    fn push(&mut self, id: Identifier<&'static str>) -> Result<(), AllocError> {
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

            // SAFETY: the value is not empty, well aligned, and the conversion result is assigned
            // to an object in the same pool.
            let value = unsafe { super::conf_value_to_str(&server_name.name)? };

            self.try_add_identifier(cf, value)?;
        }

        Ok(())
    }

    pub fn try_add_identifier(
        &mut self,
        cf: &ngx_conf_t,
        value: &'static str,
    ) -> Result<(), IdentifierError> {
        if let Some(addr) = parse_ip_identifier(cf, value)? {
            return self.push(Identifier::Ip(addr)).map_err(Into::into);
        }

        let realloc = validate_dns_identifier(value)?;

        /*
         * The only special syntax we want to support is a leading dot, which matches the domain
         * with "www." and without it.
         * See <https://nginx.org/en/docs/http/server_names.html>
         */

        if let Some(host) = value.strip_prefix(".") {
            let mut www = Vec::new_in(self.identifiers.allocator().clone());
            www.try_reserve_exact(host.len() + 4)
                .map_err(|_| AllocError)?;
            www.extend_from_slice(b"www.");
            www.extend_from_slice(host.as_bytes());
            www.make_ascii_lowercase();
            // SAFETY: www is a pre-validated ASCII character slice.
            // The buffer is owned by ngx_pool_t and does not leak.
            let www = unsafe { core::str::from_utf8_unchecked(www.leak()) };

            self.push(Identifier::Dns(www))?;
            self.push(Identifier::Dns(&www[4..]))?;
        } else if realloc {
            let mut out = Vec::new_in(self.identifiers.allocator().clone());
            out.try_reserve_exact(value.len()).map_err(|_| AllocError)?;
            out.extend_from_slice(value.as_bytes());
            out.make_ascii_lowercase();
            // SAFETY: out is a pre-validated ASCII character slice.
            // The buffer is owned by ngx_pool_t and does not leak.
            let out = unsafe { core::str::from_utf8_unchecked(out.leak()) };

            self.push(Identifier::Dns(out))?;
        } else {
            self.push(Identifier::Dns(value))?;
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

/// Attempts to parse the value as an IP address, returning `Some(...)` on success.
///
/// The address will be converted to a canonical textual form and reallocated on the
/// configuration pool if necessary.
fn parse_ip_identifier(
    cf: &ngx_conf_t,
    value: &'static str,
) -> Result<Option<&'static str>, AllocError> {
    const INET6_ADDRSTRLEN: usize = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".len();

    let Ok(addr) = value.parse::<core::net::IpAddr>() else {
        return Ok(None);
    };

    let mut buf = [0u8; INET6_ADDRSTRLEN];
    let mut cur = std::io::Cursor::new(&mut buf[..]);
    // Formatting IP address to a sufficiently large buffer should always succeed
    let _ = std::io::Write::write_fmt(&mut cur, format_args!("{addr}"));
    let len = cur.position() as usize;
    let buf = &buf[..len];

    if buf == value.as_bytes() {
        return Ok(Some(value));
    }

    let mut out = Vec::new_in(cf.pool());
    out.try_reserve_exact(buf.len()).map_err(|_| AllocError)?;
    out.extend_from_slice(buf);
    // SAFETY: formatted IpAddr is always a valid ASCII string.
    // The buffer is owned by the ngx_pool_t and does not leak.
    let out = unsafe { core::str::from_utf8_unchecked(out.leak()) };

    Ok(Some(out))
}

#[derive(Debug, Error, PartialEq)]
pub enum NameError {
    #[error("invalid character {0:x} at position {1}")]
    Invalid(u8, usize),
    #[error("unexpected character '{0}' at position {1}")]
    Unexpected(char, usize),
    #[error("does not end with a label")]
    NotALabel,
}

/// Validates that the `name` can be used as a DNS identifier.
///
/// RFC8555 § 7.1.4 states that the "dns" identifier is a fully qualified domain name,
/// encoded according to the rules in RFC5280 § 7.
/// In practice, existing ACME servers and clients are rather relaxed about this requirement,
/// trusting the user to specify valid values and the underlying protocol implementations (DNS or
/// HTTP) to reject invalid ones.
///
/// Given that, the validation logic is loosely based on the `ngx_http_validate_host` as of 1.29.4,
/// asserting that the name
///
///  - is a printable ASCII string, as required both by ACME and by NGINX[^1]
///  - is a valid Host value accepted by NGINX
///  - can have a leading dot or a single leading wildcard label
///  - ends with a non-empty label
///
/// Returns true if the name needs to be reallocated and converted to lower case.
///
/// [^1]: https://nginx.org/en/docs/http/server_names.html
fn validate_dns_identifier(name: &str) -> Result<bool, NameError> {
    #[derive(PartialEq, Eq)]
    enum State {
        Start,
        Label,
        Dot,
        Wildcard,
    }

    let mut alloc = false;
    let mut state = State::Start;

    for (i, ch) in name.bytes().enumerate() {
        state = match ch {
            // non-printable - handle separately for better error formatting
            0x00..=0x20 | 0x7f.. => return Err(NameError::Invalid(ch, i)),

            b'*' if state == State::Start => State::Wildcard,
            b'.' if state != State::Dot => State::Dot,
            // A wildcard domain name consists of a single asterisk character followed by a single
            // full stop character ("*.") followed by a domain name (RFC8555 § 7.1.3)
            _ if state == State::Wildcard => return Err(NameError::Unexpected(ch as _, i)),

            // unreserved
            b'A'..=b'Z' => {
                alloc = true;
                State::Label
            }
            b'0'..=b'9' | b'a'..=b'z' | b'-' | b'_' | b'~' => State::Label,

            // pct-encoded
            b'%' => State::Label,

            // sub-delims
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'+' | b',' | b';' | b'=' => State::Label,

            _ => return Err(NameError::Unexpected(ch as _, i)),
        };
    }

    // We intentionally reject the trailing dot, as it should not appear in the TLS layer.

    if state != State::Label {
        return Err(NameError::NotALabel);
    }

    Ok(alloc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dns_identifier() {
        for (name, expect) in [
            ("example", Ok(false)),
            ("_example", Ok(false)),
            ("exam_ple", Ok(false)),
            ("Example", Ok(true)),
            ("Example.", Err(NameError::NotALabel)),
            ("E\x10ample", Err(NameError::Invalid(0x10, 1))),
            ("00.example.test", Ok(false)),
            ("www1.example.Test", Ok(true)),
            ("www.example..test", Err(NameError::Unexpected('.', 12))),
            ("www.example.test.", Err(NameError::NotALabel)),
            ("пример.испытание", Err(NameError::Invalid(0xd0, 0))),
            ("xn--e1afmkfd.xn--80akhbyknj4f", Ok(false)),
            // wildcards
            ("*", Err(NameError::NotALabel)),
            ("*.example.test", Ok(false)),
            ("*.xn--e1afmkfd.xn--80akhbyknj4f", Ok(false)),
            ("*ww.example.test", Err(NameError::Unexpected('w', 1))),
            ("ww*.example.test", Err(NameError::Unexpected('*', 2))),
            ("www.example.*", Err(NameError::Unexpected('*', 12))),
            // incorrect syntax
            ("", Err(NameError::NotALabel)),
            ("*.", Err(NameError::NotALabel)),
        ] {
            assert_eq!(
                super::validate_dns_identifier(name),
                expect,
                "incorrect validation result for \"{name}\"",
            );
        }
    }
}
