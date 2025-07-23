use core::ptr;

use ngx::allocator::AllocError;
use ngx::collections::Queue;
use ngx::core::SlabPool;
use ngx::sync::RwLock;

use crate::conf::issuer::Issuer;

use super::certificate::{CertificateContext, CertificateContextInner, SharedCertificateContext};

#[derive(Debug)]
pub struct IssuerContext {
    // Using Queue here to ensure address stability.
    #[allow(unused)]
    pub certificates: Queue<SharedCertificateContext, SlabPool>,
}

impl IssuerContext {
    pub fn try_new_in(issuer: &mut Issuer, alloc: SlabPool) -> Result<Self, AllocError> {
        let mut certificates = Queue::try_new_in(alloc.clone())?;

        for (_, value) in issuer.orders.iter_mut() {
            let ctx = CertificateContextInner::new_in(alloc.clone());
            let ctx = certificates.push_back(RwLock::new(ctx))?;
            *value = CertificateContext::Shared(unsafe { &*ptr::from_ref(ctx) });
        }

        Ok(IssuerContext { certificates })
    }
}
