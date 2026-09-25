// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! ACME dns-persist-01 challenge implementation.
//!
//! High level overview:
//!
//! Unlike the other challenge types, dns-persist-01 does not require the client to publish
//! anything at validation time.  The domain owner provisions a persistent TXT record at
//! `_validation-persist.<identifier>` once, naming the CA and the ACME account allowed to request
//! certificates for the identifier.  The CA looks that record up on every validation attempt.
//!
//! That leaves nothing for the solver to set up or tear down: we only have to acknowledge that the
//! challenge type is supported, so that it is not filtered out of the authorization object, and
//! let the generic code POST the response to the challenge URL.
//!
//! The one thing we can usefully do here is to log the record the CA expects to see.  Both values
//! needed to construct it are provided by the server in the challenge object, and an incorrect or
//! missing record is the only way this challenge can fail.

use super::{ChallengeSolver, SolverError};
use crate::acme;
use crate::acme::resource::{Challenge, ChallengeKind};
use crate::conf::identifier::Identifier;

/// Label of the persistent validation record.
const VALIDATION_LABEL: &str = "_validation-persist";

#[derive(Debug, Default)]
pub struct DnsPersist01Solver;

impl DnsPersist01Solver {
    pub fn new() -> Self {
        Self
    }
}

impl ChallengeSolver for DnsPersist01Solver {
    fn supports(&self, c: &ChallengeKind) -> bool {
        matches!(c, ChallengeKind::DnsPersist01)
    }

    fn register(
        &self,
        ctx: &acme::AuthorizationContext,
        identifier: &Identifier<&str>,
        wildcard: bool,
        challenge: &Challenge,
    ) -> Result<(), SolverError> {
        // The record is provisioned externally; there's nothing to publish here.
        // Log what the server asked for, as that is the only actionable output we can produce if
        // the validation fails.
        let Some(account_uri) = challenge.account_uri.as_ref() else {
            return Ok(());
        };

        // A wildcard authorization is only granted by a record with the "wildcard" policy, but it
        // is still looked up at the base name.
        let policy = if wildcard { "; policy=wildcard" } else { "" };

        for issuer_domain_name in &challenge.issuer_domain_names {
            info!(
                ctx.log,
                "acme/dns-persist-01: {identifier} expects a TXT record at \
                 \"{VALIDATION_LABEL}.{}\" with the value \"{issuer_domain_name}; \
                 accounturi={account_uri}{policy}\"",
                identifier.value(),
            );
        }

        Ok(())
    }

    fn unregister(
        &self,
        _identifier: &Identifier<&str>,
        _challenge: &Challenge,
    ) -> Result<(), SolverError> {
        Ok(())
    }
}
