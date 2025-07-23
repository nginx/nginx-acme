//! Shared runtime state of the module.
use core::ffi::c_void;
use core::ptr;

use nginx_sys::{ngx_int_t, ngx_shm_zone_t, NGX_LOG_EMERG};
use ngx::allocator::{AllocError, Allocator, Box, TryCloneIn};
use ngx::collections::Queue;
use ngx::core::{SlabPool, Status};
use ngx::log::ngx_cycle_log;
use ngx::sync::RwLock;
use ngx::{ngx_log_debug, ngx_log_error};

use crate::conf::shared_zone::SharedZone;
use crate::conf::AcmeMainConfig;

pub use self::certificate::CertificateContext;
pub use self::issuer::IssuerContext;

pub mod certificate;
pub mod issuer;

#[derive(Debug)]
pub struct AcmeSharedData<A = SlabPool>
where
    A: Allocator + Clone,
{
    pub issuers: Queue<RwLock<IssuerContext>, A>,
}

impl<A> AcmeSharedData<A>
where
    A: Allocator + Clone,
{
    pub fn try_new_in(alloc: A) -> Result<Self, AllocError> {
        Ok(Self {
            issuers: Queue::try_new_in(alloc)?,
        })
    }
}

pub extern "C" fn ngx_acme_shared_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    data: *mut c_void,
) -> ngx_int_t {
    // SAFETY: shm_zone is always valid in this callback
    let shm_zone = unsafe { &mut *shm_zone };
    let log = ngx_cycle_log().as_ptr();

    ngx_log_debug!(
        log,
        "acme: init shared zone \"{}:{}\"",
        shm_zone.shm.name,
        shm_zone.shm.size,
    );

    let oamcf = unsafe { data.cast::<AcmeMainConfig>().as_ref() };
    let amcf = unsafe { shm_zone.data.cast::<AcmeMainConfig>().as_mut().unwrap() };
    let zone = SharedZone::Ready(shm_zone.into());

    let mut alloc = zone.allocator().expect("shared zone allocator");

    // Our shared zone is `noreuse`, meaning that we get an empty zone every time unless we are
    // running on Windows.

    let Ok(mut data) =
        AcmeSharedData::try_new_in(alloc.clone()).and_then(|x| Box::try_new_in(x, alloc.clone()))
    else {
        ngx_log_error!(NGX_LOG_EMERG, log, "cannot allocate acme shared data");
        return Status::NGX_ERROR.into();
    };

    for issuer in &mut amcf.issuers[..] {
        // Create new shared data.
        let Ok(ctx) = IssuerContext::try_new_in(issuer, alloc.clone()) else {
            ngx_log_error!(
                NGX_LOG_EMERG,
                log,
                "cannot allocate acme issuer \"{}\"",
                issuer.name,
            );
            return Status::NGX_ERROR.into();
        };

        // Copy data from the previous cycle.
        if let Some(oissuer) = oamcf.and_then(|x| x.issuer(&issuer.name)) {
            ngx_log_debug!(log, "acme: copy old data for issuer \"{}\"", issuer.name);

            for (order, ctx) in issuer.orders.iter_mut() {
                // Should not fail as we just allocated all the certificate contexts.
                let CertificateContext::Shared(ctx) = ctx else {
                    continue;
                };

                let Some(CertificateContext::Shared(octx)) = oissuer.orders.get(order) else {
                    continue;
                };

                // The old shared zone is going away as soon as we're done, so we have to copy the
                // data to the new slab pool.
                let Ok(cloned) = octx.read().try_clone_in(alloc.clone()) else {
                    return Status::NGX_ERROR.into();
                };

                *ctx.write() = cloned;
            }
        }

        if let Ok(ctx) = data.issuers.push_back(RwLock::new(ctx)) {
            // SAFETY: we ensured that the chosen data structure will not move the IssuerContext,
            // thus the pointer will remain valid beyond this scope.
            //
            // The assigned lifetime is a bit misleading though; shared zone will be unmapped
            // while the main config is still present, right before calling the cycle pool cleanup.
            // A proper ownership-tracking pointer could attempt to unref the data from the config
            // destructor _after_ the zone is unmapped and thus trip on an invalid address.
            //
            // Of all the ways to handle that, we are picking the most obviously unsafe to make
            // sure this detail is not missed while reading.
            issuer.data = Some(unsafe { &*ptr::from_ref(ctx) });
        } else {
            ngx_log_error!(
                NGX_LOG_EMERG,
                log,
                "cannot allocate acme issuer \"{}\"",
                issuer.name,
            );
            return Status::NGX_ERROR.into();
        }
    }

    // Will be freed when the zone is unmapped.
    let data = Box::leak(data);

    alloc.as_mut().data = ptr::from_mut(data).cast();

    amcf.data = Some(data);
    amcf.shm_zone = zone;

    Status::NGX_OK.into()
}
