// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::ptr;
use core::time::Duration;

use ngx::allocator::{AllocError, TryCloneIn};
use ngx::collections::Queue;
use ngx::core::SlabPool;
use ngx::sync::RwLock;

use super::certificate::{CertificateContext, CertificateContextInner, SharedCertificateContext};
use crate::conf::issuer::Issuer;
use crate::time::{jitter, Time};

#[derive(Debug, Eq, PartialEq)]
pub enum IssuerState {
    Idle,
    Error { fails: usize },
    Invalid,
}

#[derive(Debug)]
pub struct IssuerContext {
    pub state: IssuerState,
    // Using Queue here to ensure address stability.
    #[allow(unused)]
    pub certificates: Queue<SharedCertificateContext, SlabPool>,
}

impl IssuerContext {
    pub fn try_new_in(issuer: &mut Issuer, alloc: SlabPool) -> Result<Self, AllocError> {
        let mut certificates = Queue::try_new_in(alloc.clone())?;

        for (_, value) in issuer.orders.iter_mut() {
            let ctx = if let CertificateContext::Local(value) = value {
                value.try_clone_in(alloc.clone())?
            } else {
                CertificateContextInner::new_in(alloc.clone())
            };

            let ctx = certificates.push_back(RwLock::new(ctx))?;
            *value = CertificateContext::Shared(unsafe { &*ptr::from_ref(ctx) });
        }

        Ok(IssuerContext {
            state: IssuerState::Idle,
            certificates,
        })
    }

    pub fn set_error(&mut self, _err: &dyn StdError) -> Time {
        let fails = match self.state {
            IssuerState::Error { fails } => fails + 1,
            IssuerState::Invalid => return Time::MAX,
            _ => 1,
        };

        self.state = IssuerState::Error { fails };

        let interval = Duration::from_secs(match fails {
            1 => 60,
            2 => 600,
            3 => 6000,
            _ => 24 * 60 * 60,
        });

        Time::now() + jitter(interval, 2)
    }

    pub fn set_invalid(&mut self, _err: &dyn StdError) {
        self.state = IssuerState::Invalid;
    }
}
