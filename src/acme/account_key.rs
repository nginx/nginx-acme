// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use std::string::String;

use ngx::collections::Vec;
use openssl::pkey::{Id, PKeyRef, Private};
use serde::{Serialize, Serializer};
use thiserror::Error;

use crate::jws::{JsonWebKey, NewKeyError, ShaWithEcdsaKey, ShaWithRsaKey};

#[derive(Debug)]
pub struct AccountKey {
    inner: AccountKeyInner,
    thumbprint: String,
}

#[derive(Debug, Error)]
pub enum AccountKeyError {
    #[error(transparent)]
    Jwk(#[from] crate::jws::NewKeyError),
    #[error(transparent)]
    Thumbprint(#[from] crate::jws::Error),
}

#[derive(Debug)]
enum AccountKeyInner {
    ShaWithEcdsa(ShaWithEcdsaKey),
    ShaWithRsa(ShaWithRsaKey),
}

impl AccountKey {
    pub fn thumbprint(&self) -> &[u8] {
        self.thumbprint.as_bytes()
    }
}

impl JsonWebKey for AccountKey {
    fn alg(&self) -> &str {
        match self.inner {
            AccountKeyInner::ShaWithEcdsa(ref key) => key.alg(),
            AccountKeyInner::ShaWithRsa(ref key) => key.alg(),
        }
    }

    fn compute_mac(&self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, crate::jws::Error> {
        match self.inner {
            AccountKeyInner::ShaWithEcdsa(ref key) => key.compute_mac(header, payload),
            AccountKeyInner::ShaWithRsa(ref key) => key.compute_mac(header, payload),
        }
    }

    fn thumbprint(&self) -> Result<String, crate::jws::Error> {
        Ok(self.thumbprint.clone())
    }
}

impl Serialize for AccountKey {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.inner {
            AccountKeyInner::ShaWithEcdsa(ref key) => key.serialize(serializer),
            AccountKeyInner::ShaWithRsa(ref key) => key.serialize(serializer),
        }
    }
}

impl TryFrom<&PKeyRef<Private>> for AccountKey {
    type Error = AccountKeyError;

    fn try_from(value: &PKeyRef<Private>) -> Result<Self, Self::Error> {
        let inner = match value.id() {
            Id::EC => value.try_into().map(AccountKeyInner::ShaWithEcdsa),
            Id::RSA => value.try_into().map(AccountKeyInner::ShaWithRsa),
            id => Err(NewKeyError::Algorithm(id)),
        }?;

        let thumbprint = match inner {
            AccountKeyInner::ShaWithEcdsa(ref key) => key.thumbprint(),
            AccountKeyInner::ShaWithRsa(ref key) => key.thumbprint(),
        }?;

        Ok(Self { inner, thumbprint })
    }
}
