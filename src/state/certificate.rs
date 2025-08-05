use core::error::Error as StdError;
use core::time::Duration;
use std::string::ToString;

use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{NgxString, Pool, SlabPool};
use ngx::sync::RwLock;
use zeroize::Zeroize;

use crate::time::{jitter, Time, TimeRange};

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

#[derive(Debug, Default, PartialEq, Eq)]
pub enum CertificateState<A>
where
    A: Allocator + Clone,
{
    #[default]
    Pending,
    InitialRequestFailed {
        fails: usize,
        reason: NgxString<A>,
    },
    Ready,
    RenewalFailed {
        fails: usize,
        reason: NgxString<A>,
    },
    Invalid {
        reason: NgxString<A>,
    },
}

#[derive(Debug)]
pub struct CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    pub state: CertificateState<A>,
    pub chain: Vec<u8, A>,
    pub pkey: Vec<u8, A>,
    pub valid: TimeRange,
    pub next: Time,
}

impl<OA> TryCloneIn for CertificateContextInner<OA>
where
    OA: Allocator + Clone,
{
    type Target<A: Allocator + Clone> = CertificateContextInner<A>;

    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError> {
        let state = if self.is_ready() {
            CertificateState::Ready
        } else {
            CertificateState::Pending
        };

        let mut chain = Vec::new_in(alloc.clone());
        chain
            .try_reserve_exact(self.chain.len())
            .map_err(|_| AllocError)?;
        chain.extend(self.chain.iter());

        let mut pkey = Vec::new_in(alloc);
        pkey.try_reserve_exact(self.pkey.len())
            .map_err(|_| AllocError)?;
        pkey.extend(self.pkey.iter());

        Ok(Self::Target {
            state,
            chain,
            pkey,
            valid: self.valid.clone(),
            next: self.next,
        })
    }
}

impl<A> CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    pub fn new_in(alloc: A) -> Self {
        Self {
            state: CertificateState::Pending,
            chain: Vec::new_in(alloc.clone()),
            pkey: Vec::new_in(alloc.clone()),
            valid: Default::default(),
            next: Default::default(),
        }
    }

    pub fn set(&mut self, chain: &[u8], pkey: &[u8], valid: TimeRange) -> Result<Time, AllocError> {
        const PREFIX: &[u8] = b"data:";

        // reallocate the storage only if the current capacity is insufficient

        fn needs_realloc<A: Allocator>(buf: &Vec<u8, A>, new_size: usize) -> bool {
            buf.capacity() < PREFIX.len() + new_size
        }

        if needs_realloc(&self.chain, chain.len()) || needs_realloc(&self.pkey, pkey.len()) {
            let alloc = self.chain.allocator();

            let mut new_chain: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_chain
                .try_reserve_exact(PREFIX.len() + chain.len())
                .map_err(|_| AllocError)?;

            let mut new_pkey: Vec<u8, A> = Vec::new_in(alloc.clone());
            new_pkey
                .try_reserve_exact(PREFIX.len() + pkey.len())
                .map_err(|_| AllocError)?;

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

        // Schedule the next update at around 2/3 of the cert lifetime,
        // as recommended in Let's Encrypt integration guide
        self.next = valid.start + jitter(valid.duration() * 2 / 3, 2);
        self.valid = valid;

        self.state = CertificateState::Ready;

        Ok(self.next)
    }

    pub fn set_error(&mut self, err: &dyn StdError) -> Time {
        let mut reason = NgxString::new_in(self.chain.allocator().clone());

        let fails = match self.state {
            CertificateState::InitialRequestFailed { fails, .. } => fails + 1,
            CertificateState::RenewalFailed { fails, .. } => fails + 1,
            CertificateState::Invalid { .. } => return Time::MAX,
            _ => 1,
        };

        let msg = err.to_string();
        // it is fine to have an empty reason if we failed to reserve space for the message
        if reason.try_reserve_exact(msg.len()).is_ok() {
            let _ = reason.append_within_capacity(msg.as_bytes());
        }

        self.state = match self.state {
            CertificateState::Pending | CertificateState::InitialRequestFailed { .. } => {
                CertificateState::InitialRequestFailed { fails, reason }
            }

            CertificateState::Ready | CertificateState::RenewalFailed { .. } => {
                CertificateState::RenewalFailed { fails, reason }
            }

            _ => unreachable!(),
        };

        let interval = Duration::from_secs(match fails {
            1 => 60,
            2 => 600,
            3 => 6000,
            _ => 24 * 60 * 60,
        });

        self.next = Time::now() + jitter(interval, 2);
        self.next
    }

    pub fn set_invalid(&mut self, err: &dyn StdError) {
        let mut reason = NgxString::new_in(self.chain.allocator().clone());

        let msg = err.to_string();
        // it is fine to have an empty reason if we failed to reserve space for the message
        if reason.try_reserve_exact(msg.len()).is_ok() {
            let _ = reason.append_within_capacity(msg.as_bytes());
        }

        self.state = CertificateState::Invalid { reason };
    }

    pub fn chain(&self) -> Option<&[u8]> {
        if self.is_ready() {
            return Some(&self.chain);
        }

        None
    }

    pub fn pkey(&self) -> Option<&[u8]> {
        if self.is_ready() {
            return Some(&self.pkey);
        }

        None
    }

    pub fn is_ready(&self) -> bool {
        matches!(
            self.state,
            CertificateState::Ready | CertificateState::RenewalFailed { .. }
        )
    }

    pub fn is_renewable(&self) -> bool {
        !matches!(self.state, CertificateState::Invalid { .. }) && Time::now() >= self.next
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
