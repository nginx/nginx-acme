// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use thiserror::Error;

use super::types::{Challenge, ChallengeKind};
use super::AuthorizationContext;
use crate::conf::identifier::Identifier;

pub mod http;
pub mod tls_alpn;

#[derive(Debug, Error)]
#[error("challenge registration failed: {0}")]
pub enum SolverError {
    Alloc(#[from] ngx::allocator::AllocError),
    Ssl(#[from] openssl::error::ErrorStack),
    TryReserve(#[from] ngx::collections::TryReserveError),
}

pub trait ChallengeSolver {
    fn supports(&self, c: &ChallengeKind) -> bool;

    fn register(
        &self,
        ctx: &AuthorizationContext,
        identifier: &Identifier<&str>,
        challenge: &Challenge,
    ) -> Result<(), SolverError>;

    fn unregister(
        &self,
        identifier: &Identifier<&str>,
        challenge: &Challenge,
    ) -> Result<(), SolverError>;
}
