// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::fmt;
use core::time::Duration;
use std::string::ToString;

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use ngx::allocator::{AllocError, Allocator, Box, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{Pool, SlabPool};
use ngx::sync::RwLock;
use zeroize::Zeroize;

use crate::time::{jitter, Interval, Timestamp};
use crate::util::new_boxed_str;

const RENEWAL_RETRY_MAX: u64 = 24 * 60 * 60;
const RENEWAL_INFO_RETRY_MAX: u64 = 6 * 60 * 60;
const SSL_VARIABLE_PREFIX: &[u8] = b"data:";

pub type SharedCertificateContext = RwLock<CertificateContextInner<SlabPool>>;

#[derive(Debug, Default)]
pub enum CertificateContext {
    #[default]
    Empty,
    // Previously issued certificate, restored from the state directory.
    Local(CertificateContextInner<Pool>),
    // Ready to use certificate in shared memory.
    Shared(&'static SharedCertificateContext),
}

impl CertificateContext {
    pub fn as_ref(&self) -> Option<&'static SharedCertificateContext> {
        if let CertificateContext::Shared(data) = self {
            Some(data)
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertificateState {
    RequestScheduled { next: Timestamp, fails: usize },
    RenewalScheduled { next: Timestamp, fails: usize },
    RenewalInfoScheduled { next: Timestamp, fails: usize },
    Invalid,
}

impl Default for CertificateState {
    fn default() -> Self {
        CertificateState::RequestScheduled { next: Timestamp::MIN, fails: 0 }
    }
}

impl CertificateState {
    /// Checks if the certificate was issued and can be used.
    pub fn ready(&self) -> bool {
        matches!(self, Self::RenewalScheduled { .. } | Self::RenewalInfoScheduled { .. })
    }

    /// Checks if the certificate is due for renewal or not set.
    pub fn can_update_certificate(&self) -> bool {
        match self {
            CertificateState::RequestScheduled { next, .. }
            | CertificateState::RenewalScheduled { next, .. } => &Timestamp::now() >= next,
            _ => false,
        }
    }

    /// Checks if the renewal info is due for update.
    pub fn can_update_renewal_info(&self) -> bool {
        match self {
            CertificateState::RenewalInfoScheduled { next, .. } => &Timestamp::now() >= next,
            _ => false,
        }
    }

    /// Checks if the certificate updates are deactivated due to a configuration error.
    pub fn is_invalid(&self) -> bool {
        matches!(self, CertificateState::Invalid)
    }

    pub fn next_update(&self) -> Option<Timestamp> {
        match self {
            CertificateState::RequestScheduled { next, .. }
            | CertificateState::RenewalScheduled { next, .. }
            | CertificateState::RenewalInfoScheduled { next, .. } => Some(*next),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetRenewalInfoError {
    #[error(transparent)]
    Alloc(#[from] AllocError),
    #[error("invalid renewal window")]
    Invalid,
}

#[derive(Debug)]
pub struct CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    pub state: CertificateState,
    pub error: Option<Box<str, A>>,
    pub chain: Vec<u8, A>,
    pub pkey: Vec<u8, A>,
    pub identifier: Option<CertificateIdentifier<A>>,
    pub valid: Interval,
    pub renewal_window: Interval,
}

impl<OA> TryCloneIn for CertificateContextInner<OA>
where
    OA: Allocator + Clone,
{
    type Target<A: Allocator + Clone> = CertificateContextInner<A>;

    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError> {
        /*
         * This method is used to copy the certificate state into a new shared zone on reload.
         *
         * Failure to obtain a certificate may be resolved by a configuration change;
         * thus, we forget the last error state and schedule the next attempt immediately.
         */
        let (state, error) = if self.state.ready() {
            let new_error =
                self.error.as_ref().map(|x| new_boxed_str(x, alloc.clone())).transpose()?;
            (self.state, new_error)
        } else {
            (CertificateState::default(), None)
        };

        let identifier =
            self.identifier.as_ref().map(|x| x.try_clone_in(alloc.clone())).transpose()?;

        let mut chain = Vec::new_in(alloc.clone());
        chain.try_reserve_exact(self.chain.len()).map_err(|_| AllocError)?;
        chain.extend(self.chain.iter());

        let mut pkey = Vec::new_in(alloc);
        pkey.try_reserve_exact(self.pkey.len()).map_err(|_| AllocError)?;
        pkey.extend(self.pkey.iter());

        Ok(Self::Target {
            state,
            error,
            chain,
            pkey,
            identifier,
            valid: self.valid,
            renewal_window: self.renewal_window,
        })
    }
}

impl<A> CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    pub fn new_in(alloc: A) -> Self {
        Self {
            state: CertificateState::default(),
            error: None,
            chain: Vec::new_in(alloc.clone()),
            pkey: Vec::new_in(alloc),
            identifier: None,
            valid: Default::default(),
            renewal_window: Default::default(),
        }
    }

    pub fn allocator(&self) -> &A {
        self.chain.allocator()
    }

    pub fn set(
        &mut self,
        chain: &[u8],
        pkey: &[u8],
        valid: Interval,
    ) -> Result<Timestamp, AllocError> {
        // reallocate the storage only if the current capacity is insufficient

        fn needs_realloc<A: Allocator>(buf: &Vec<u8, A>, new_size: usize) -> bool {
            buf.capacity() < SSL_VARIABLE_PREFIX.len() + new_size
        }

        if needs_realloc(&self.chain, chain.len()) || needs_realloc(&self.pkey, pkey.len()) {
            let alloc = self.allocator();

            let mut new_chain: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_chain
                .try_reserve_exact(SSL_VARIABLE_PREFIX.len() + chain.len())
                .map_err(|_| AllocError)?;

            let mut new_pkey: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_pkey
                .try_reserve_exact(SSL_VARIABLE_PREFIX.len() + pkey.len())
                .map_err(|_| AllocError)?;

            // Zeroize is not implemented for allocator-api2 types.
            self.chain.as_mut_slice().zeroize();
            self.pkey.as_mut_slice().zeroize();

            self.chain = new_chain;
            self.pkey = new_pkey;
        }

        // update the stored data in-place

        self.chain.clear();
        self.chain.extend(SSL_VARIABLE_PREFIX);
        self.chain.extend(chain);

        self.pkey.clear();
        self.pkey.extend(SSL_VARIABLE_PREFIX);
        self.pkey.extend(pkey);

        self.error = None;
        // The identifier that we had for the previous keypair is no longer valid.
        self.identifier = None;
        self.renewal_window = renewal_window_from_validity(&valid, 2);
        self.valid = valid;

        Ok(self.schedule_renewal())
    }

    pub fn set_renewal_info<OA>(
        &mut self,
        identifier: &CertificateIdentifier<OA>,
        window: Interval,
        expires: Timestamp,
    ) -> Result<Timestamp, (Timestamp, SetRenewalInfoError)>
    where
        OA: Allocator,
    {
        if window.end > self.valid.end {
            let err = SetRenewalInfoError::Invalid;
            return Err((self.set_error(&err), err));
        }

        if self.identifier.is_none() {
            let identifier = identifier
                .try_clone_in(self.allocator().clone())
                .map_err(|x| (self.set_error(&x), x.into()))?;
            self.identifier = Some(identifier);
        }

        self.error = None;
        self.renewal_window = window;

        let renew_at = window.random_point();
        if renew_at < expires {
            self.state = CertificateState::RenewalScheduled { next: renew_at, fails: 0 };
            Ok(renew_at)
        } else {
            self.state = CertificateState::RenewalInfoScheduled { next: expires, fails: 0 };
            Ok(expires)
        }
    }

    pub fn schedule_renewal(&mut self) -> Timestamp {
        let next = self.renewal_window.random_point();
        self.state = CertificateState::RenewalScheduled { next, fails: 0 };
        next
    }

    pub fn schedule_renewal_info_update(&mut self) {
        let next = Timestamp::MIN;
        self.state = CertificateState::RenewalInfoScheduled { next, fails: 0 }
    }

    pub fn set_error(&mut self, err: &dyn StdError) -> Timestamp {
        fn next_attempt(fails: usize, max: u64) -> Timestamp {
            let interval = Duration::from_secs(match fails {
                0 => 60,
                1 => 600,
                2 => 6000,
                _ => max,
            });
            Timestamp::now() + jitter(interval, 2)
        }

        let next = match self.state {
            CertificateState::RequestScheduled { fails, .. } => {
                let next = next_attempt(fails, RENEWAL_RETRY_MAX);
                self.state = CertificateState::RequestScheduled { next, fails: fails + 1 };
                next
            }

            CertificateState::RenewalScheduled { fails, .. } => {
                let next = next_attempt(fails, RENEWAL_RETRY_MAX);
                self.state = CertificateState::RenewalScheduled { next, fails: fails + 1 };
                next
            }

            CertificateState::RenewalInfoScheduled { fails, .. } => {
                let next = next_attempt(fails, RENEWAL_INFO_RETRY_MAX);

                if next >= self.renewal_window.end {
                    self.schedule_renewal()
                } else {
                    self.state = CertificateState::RenewalInfoScheduled { next, fails: fails + 1 };
                    next
                }
            }

            _ => return Timestamp::MAX,
        };

        let msg = err.to_string();
        // it is fine to have an empty reason if we failed to reserve space for the message
        self.error = new_boxed_str(&msg, self.allocator().clone()).ok();

        next
    }

    pub fn set_invalid(&mut self, err: &dyn StdError) {
        let msg = err.to_string();
        // it is fine to have an empty reason if we failed to reserve space for the message
        self.error = new_boxed_str(&msg, self.allocator().clone()).ok();
        self.state = CertificateState::Invalid;
    }

    pub fn chain(&self) -> Option<&[u8]> {
        if self.state.ready() {
            return Some(&self.chain);
        }

        None
    }

    pub fn pkey(&self) -> Option<&[u8]> {
        if self.state.ready() {
            return Some(&self.pkey);
        }

        None
    }

    /// Returns ACME Renewal Info certificate identifier.
    pub fn certificate_identifier<A1>(
        &self,
        alloc: A1,
    ) -> Result<CertificateIdentifier<A1>, CertificateIdentifierError>
    where
        A1: Allocator + Clone,
    {
        if let Some(ref x) = self.identifier {
            Ok(x.try_clone_in(alloc)?)
        } else if let Some(chain) = self.chain() {
            let x509 = openssl::x509::X509::from_pem(&chain[SSL_VARIABLE_PREFIX.len()..])?;
            CertificateIdentifier::from_x509(&x509, alloc)
        } else {
            Err(CertificateIdentifierError::Invalid)
        }
    }
}

impl<A> Drop for CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    fn drop(&mut self) {
        // Zeroize is not implemented for allocator-api2 types.
        self.chain.as_mut_slice().zeroize();
        self.pkey.as_mut_slice().zeroize();
    }
}

/// Calculates preferred renewal window based on the certificate notBefore and notAfter dates.
fn renewal_window_from_validity(valid: &Interval, pct: u32) -> Interval {
    // Schedule the next update at third of the remaining lifetime for certificates with
    // a validity period over 10 days and halfway through the lifetime otherwise,
    // as recommended in the Let's Encrypt integration guide.
    let lifetime = valid.duration();

    let renew_at = if lifetime > Duration::from_secs(10 * 24 * 60 * 60) {
        lifetime * 2 / 3
    } else {
        lifetime / 2
    };

    let var = lifetime * pct / 100;
    Interval::new(valid.start + (renew_at - var), valid.start + (renew_at + var))
}

/*
 * ACME Renewal Info certificate identifier, RFC9773 Section 4.1
 */

#[derive(Debug, Eq)]
pub struct CertificateIdentifier<A>(Box<str, A>)
where
    A: Allocator;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub enum CertificateIdentifierError {
    Alloc(#[from] AllocError),
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("invalid certificate")]
    Invalid,
}

impl<A> AsRef<str> for CertificateIdentifier<A>
where
    A: Allocator,
{
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<A> fmt::Display for CertificateIdentifier<A>
where
    A: Allocator,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl<AL, AR> PartialEq<CertificateIdentifier<AR>> for CertificateIdentifier<AL>
where
    AL: Allocator,
    AR: Allocator,
{
    fn eq(&self, other: &CertificateIdentifier<AR>) -> bool {
        *self.0 == *other.0
    }
}

impl<OA> TryCloneIn for CertificateIdentifier<OA>
where
    OA: Allocator,
{
    type Target<A: Allocator + Clone> = CertificateIdentifier<A>;

    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError> {
        new_boxed_str(self.as_ref(), alloc).map(CertificateIdentifier)
    }
}

impl<A> CertificateIdentifier<A>
where
    A: Allocator,
{
    pub fn from_x509(
        x509: &openssl::x509::X509Ref,
        alloc: A,
    ) -> Result<Self, CertificateIdentifierError> {
        let aki = x509.authority_key_id().ok_or(CertificateIdentifierError::Invalid)?;

        /*
         * The only (safe) way to access Serial Number bytes via rust-openssl is a conversion
         * through BIGNUM. However, this operation is lossy: Serial Number SHOULD be a positive
         * integer, and will be padded with 00 to remove ambiguity when the leading bit is set
         * (e.g. 00:87:...). BN_bn2bin writes an absolute value without the leading 0.
         * To work around this, we have to serialize with the padding and check if it should be
         * preserved.
         */

        let bn = x509.serial_number().to_bn()?;
        let mut buf = ngx::collections::Vec::new();
        buf.try_reserve_exact(bn.num_bytes() as usize + 1).map_err(|_| AllocError)?;
        buf.resize(buf.capacity(), 0);
        let serial = crate::jws::bn2binpad(&bn, &mut buf)?;
        let serial =
            if serial.get(1).is_some_and(|x| x & 0x80 == 0) { &serial[1..] } else { serial };

        let encoded_len = 1
            + base64::encoded_len(aki.as_slice().len(), false).expect("sane AKI length")
            + base64::encoded_len(serial.len(), false).expect("sane serial length");

        let out = Box::try_new_zeroed_slice_in(encoded_len, alloc)?;
        let mut out: Box<[u8], A> = unsafe { out.assume_init() };

        let mut pos = URL_SAFE_NO_PAD
            .encode_slice(aki.as_slice(), &mut out[..])
            .map_err(|_| CertificateIdentifierError::Invalid)?;

        out[pos] = b'.';
        pos += 1;

        URL_SAFE_NO_PAD
            .encode_slice(serial, &mut out[pos..])
            .map_err(|_| CertificateIdentifierError::Invalid)?;

        // SAFETY: base64 output is always a valid ASCII
        let out = unsafe {
            let (raw, alloc) = Box::into_raw_with_allocator(out);
            Box::from_raw_in(raw as *mut str, alloc)
        };

        Ok(Self(out))
    }
}
