// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::time::Duration;
use std::string::ToString;

use ngx::allocator::{AllocError, Allocator, Box, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{Pool, SlabPool};
use ngx::sync::RwLock;
use zeroize::Zeroize;

use crate::time::{jitter, Interval, Timestamp};
use crate::util::new_boxed_str;

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
        matches!(self, Self::RenewalScheduled { .. })
    }

    /// Checks if the certificate is due for renewal or not set.
    pub fn can_update_certificate(&self) -> bool {
        match self {
            CertificateState::RequestScheduled { next, .. }
            | CertificateState::RenewalScheduled { next, .. } => &Timestamp::now() >= next,
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
            | CertificateState::RenewalScheduled { next, .. } => Some(*next),
            _ => None,
        }
    }
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
    pub valid: Interval,
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

        let mut chain = Vec::new_in(alloc.clone());
        chain.try_reserve_exact(self.chain.len()).map_err(|_| AllocError)?;
        chain.extend(self.chain.iter());

        let mut pkey = Vec::new_in(alloc);
        pkey.try_reserve_exact(self.pkey.len()).map_err(|_| AllocError)?;
        pkey.extend(self.pkey.iter());

        Ok(Self::Target { state, error, chain, pkey, valid: self.valid.clone() })
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
            pkey: Vec::new_in(alloc.clone()),
            valid: Default::default(),
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
        const PREFIX: &[u8] = b"data:";

        // reallocate the storage only if the current capacity is insufficient

        fn needs_realloc<A: Allocator>(buf: &Vec<u8, A>, new_size: usize) -> bool {
            buf.capacity() < PREFIX.len() + new_size
        }

        if needs_realloc(&self.chain, chain.len()) || needs_realloc(&self.pkey, pkey.len()) {
            let alloc = self.allocator();

            let mut new_chain: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_chain.try_reserve_exact(PREFIX.len() + chain.len()).map_err(|_| AllocError)?;

            let mut new_pkey: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_pkey.try_reserve_exact(PREFIX.len() + pkey.len()).map_err(|_| AllocError)?;

            // Zeroize is not implemented for allocator-api2 types.
            self.chain.as_mut_slice().zeroize();
            self.pkey.as_mut_slice().zeroize();

            self.chain = new_chain;
            self.pkey = new_pkey;
        }

        // update the stored data in-place

        self.chain.clear();
        self.chain.extend(PREFIX);
        self.chain.extend(chain);

        self.pkey.clear();
        self.pkey.extend(PREFIX);
        self.pkey.extend(pkey);

        self.valid = valid;
        self.error = None;

        // Schedule the next update at around 2/3 of the cert lifetime,
        // as recommended in Let's Encrypt integration guide
        let next = self.valid.start + jitter(self.valid.duration() * 2 / 3, 2);
        self.state = CertificateState::RenewalScheduled { next, fails: 0 };

        Ok(next)
    }

    pub fn set_error(&mut self, err: &dyn StdError) -> Timestamp {
        fn next_attempt(fails: usize) -> Timestamp {
            let interval = Duration::from_secs(match fails {
                0 => 60,
                1 => 600,
                2 => 6000,
                _ => 24 * 60 * 60,
            });
            Timestamp::now() + jitter(interval, 2)
        }

        let next = match self.state {
            CertificateState::RequestScheduled { fails, .. } => {
                let next = next_attempt(fails);
                self.state = CertificateState::RequestScheduled { next, fails: fails + 1 };
                next
            }

            CertificateState::RenewalScheduled { fails, .. } => {
                let next = next_attempt(fails);
                self.state = CertificateState::RenewalScheduled { next, fails: fails + 1 };
                next
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
