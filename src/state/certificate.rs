use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::collections::Vec;
use ngx::core::{Pool, SlabPool};
use ngx::sync::RwLock;

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
pub enum CertificateState {
    #[default]
    Pending,
    Ready,
}

#[derive(Debug)]
pub struct CertificateContextInner<A>
where
    A: Allocator + Clone,
{
    pub state: CertificateState,
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
            state: CertificateState::Ready,
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

    pub fn chain(&self) -> Option<&[u8]> {
        if matches!(self.state, CertificateState::Ready) {
            return Some(&self.chain);
        }

        None
    }

    pub fn pkey(&self) -> Option<&[u8]> {
        if matches!(self.state, CertificateState::Ready) {
            return Some(&self.pkey);
        }

        None
    }
}
