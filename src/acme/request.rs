// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use std::string::String;

use serde::Serialize;

use crate::conf::identifier::Identifier;

/// RFC8555 Section 7.3 Account Management
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account<'a> {
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub contact: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<crate::jws::SignedMessage>,
}

/// RFC8555 Section 7.4 Applying for Certificate Issuance
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order<'a> {
    pub identifiers: &'a [Identifier<&'a str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'a str>,
}
