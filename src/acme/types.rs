// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

#![allow(dead_code)]
use core::error::Error as StdError;
use core::fmt;
use std::string::{String, ToString};

use http::Uri;
use ngx::collections::Vec;
use serde::{Deserialize, Serialize};

use crate::conf::identifier::Identifier;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DirectoryMetadata {
    pub terms_of_service: Option<String>,
    #[serde(with = "http_serde::option::uri")]
    pub website: Option<Uri>,
    pub caa_identities: Vec<String>,
    pub external_account_required: Option<bool>,
}

/// RFC8555 Section 7.1.1 Directory
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    #[serde(with = "http_serde::uri")]
    pub new_nonce: Uri,
    #[serde(with = "http_serde::uri")]
    pub new_account: Uri,
    #[serde(with = "http_serde::uri")]
    pub new_order: Uri,
    #[serde(default, with = "http_serde::option::uri")]
    pub new_authz: Option<Uri>,
    #[serde(with = "http_serde::uri")]
    pub revoke_cert: Uri,
    #[serde(with = "http_serde::uri")]
    pub key_change: Uri,
    #[serde(default)]
    pub meta: DirectoryMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

/// RFC8555 Section 7.1.2 Account Object
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
}

/// RFC8555 Section 7.3 Account Management
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRequest<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
    // external_account_binding: Option<JWS>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// RFC8555 Section 7.1.3 Order Object
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order<'a> {
    pub status: OrderStatus,
    #[serde(default)]
    pub expires: Option<&'a str>,
    pub identifiers: Vec<Identifier<&'a str>>,
    #[serde(default)]
    pub not_before: Option<&'a str>,
    #[serde(default)]
    pub not_after: Option<&'a str>,
    #[serde(default)]
    pub error: Option<Problem>,
    #[serde(deserialize_with = "deserialize_vec_of_uri")]
    pub authorizations: Vec<Uri>,
    #[serde(with = "http_serde::uri")]
    pub finalize: Uri,
    #[serde(default, with = "http_serde::option::uri")]
    pub certificate: Option<Uri>,
}

/// RFC8555 Section 7.4 Applying for Certificate Issuance
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderRequest<'a> {
    pub identifiers: &'a [Identifier<&'a str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

/// RFC8555 Section 7.1.4 Authorization Object
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub identifier: Identifier<String>,
    pub status: AuthorizationStatus,
    #[serde(default)]
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    #[serde(default)]
    pub wildcard: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum ChallengeKind {
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(untagged)]
    Other(String),
}

impl From<&str> for ChallengeKind {
    fn from(s: &str) -> Self {
        match s {
            "http-01" => ChallengeKind::Http01,
            "dns-01" => ChallengeKind::Dns01,
            "tls-alpn-01" => ChallengeKind::TlsAlpn01,
            _ => ChallengeKind::Other(s.to_string()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// RFC8555 Section 8 Challenge Object
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    #[serde(rename = "type")]
    pub kind: ChallengeKind,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
    pub status: ChallengeStatus,
    #[serde(default)]
    pub validated: Option<String>,
    #[serde(default)]
    pub error: Option<Problem>,
    #[serde(default)] // Some challenge types may not have a token.
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(from = "&str")]
pub enum ErrorKind {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCsr,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    Caa,
    Compound,
    Connection,
    Dns,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Tls,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
    Other(String),
}

const ERROR_NAMESPACE: &str = "urn:ietf:params:acme:error:";
const ERROR_KIND: &[(&str, ErrorKind)] = &[
    ("accountDoesNotExist", ErrorKind::AccountDoesNotExist),
    ("alreadyRevoked", ErrorKind::AlreadyRevoked),
    ("badCSR", ErrorKind::BadCsr),
    ("badNonce", ErrorKind::BadNonce),
    ("badPublicKey", ErrorKind::BadPublicKey),
    ("badRevocationReason", ErrorKind::BadRevocationReason),
    ("badSignatureAlgorithm", ErrorKind::BadSignatureAlgorithm),
    ("caa", ErrorKind::Caa),
    ("compound", ErrorKind::Compound),
    ("connection", ErrorKind::Connection),
    ("dns", ErrorKind::Dns),
    (
        "externalAccountRequired",
        ErrorKind::ExternalAccountRequired,
    ),
    ("incorrectResponse", ErrorKind::IncorrectResponse),
    ("invalidContact", ErrorKind::InvalidContact),
    ("malformed", ErrorKind::Malformed),
    ("orderNotReady", ErrorKind::OrderNotReady),
    ("rateLimited", ErrorKind::RateLimited),
    ("rejectedIdentifier", ErrorKind::RejectedIdentifier),
    ("serverInternal", ErrorKind::ServerInternal),
    ("tls", ErrorKind::Tls),
    ("unauthorized", ErrorKind::Unauthorized),
    ("unsupportedContact", ErrorKind::UnsupportedContact),
    ("unsupportedIdentifier", ErrorKind::UnsupportedIdentifier),
    ("userActionRequired", ErrorKind::UserActionRequired),
];

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (tag, kind) in ERROR_KIND {
            if kind == self {
                f.write_str(ERROR_NAMESPACE)?;
                return f.write_str(tag);
            }
        }
        if let ErrorKind::Other(str) = self {
            return f.write_str(str);
        }
        unreachable!()
    }
}

impl From<&str> for ErrorKind {
    fn from(value: &str) -> Self {
        value
            .strip_prefix(ERROR_NAMESPACE)
            .and_then(|x| ERROR_KIND.iter().find(|(tag, _)| *tag == x))
            .map(|(_, kind)| kind.clone())
            .unwrap_or_else(|| ErrorKind::Other(value.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subproblem {
    #[serde(rename = "type")]
    pub kind: ErrorKind,
    pub detail: String,
    #[serde(default)]
    pub identifier: Option<Identifier<String>>,
}

/// RFC7807 Problem Document
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: ErrorKind,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;
        f.write_str(": ")?;
        f.write_str(&self.detail)?;

        if self.kind == ErrorKind::UserActionRequired {
            if let Some(instance) = self.instance.as_ref() {
                write!(f, "({instance})")?;
            }
        }

        Ok(())
    }
}

impl StdError for Problem {}

#[derive(Debug, Eq, PartialEq)]
pub enum ProblemCategory {
    /// The account did not pass server validation.
    Account,
    /// The request message was malformed.
    /// This may point to a problem with the order or account.
    Malformed,
    /// The order did not pass server validation.
    Order,
    Other,
}

impl Problem {
    pub fn category(&self) -> ProblemCategory {
        match self.kind {
            ErrorKind::AccountDoesNotExist
            | ErrorKind::BadPublicKey
            | ErrorKind::BadSignatureAlgorithm
            | ErrorKind::ExternalAccountRequired
            | ErrorKind::InvalidContact
            | ErrorKind::UnsupportedContact
            | ErrorKind::UserActionRequired => ProblemCategory::Account,

            ErrorKind::BadCsr
            | ErrorKind::Caa
            | ErrorKind::RejectedIdentifier
            | ErrorKind::UnsupportedIdentifier => ProblemCategory::Order,

            ErrorKind::Malformed => ProblemCategory::Malformed,

            _ => ProblemCategory::Other,
        }
    }
}

fn deserialize_vec_of_uri<'de, D>(deserializer: D) -> Result<Vec<Uri>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UriSeqVisitor;

    impl<'de> serde::de::Visitor<'de> for UriSeqVisitor {
        type Value = Vec<Uri>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of URLs")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            use serde::de;

            let mut val = Vec::new();

            while let Some(value) = seq.next_element::<&str>()? {
                let uri = value
                    .parse()
                    .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(value), &self))?;
                val.push(uri)
            }

            Ok(val)
        }
    }

    deserializer.deserialize_seq(UriSeqVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order() {
        let _order: Order = serde_json::from_str(
            r#"{
                "status": "valid",
                "expires": "2016-01-20T14:09:07.99Z",

                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],

                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",

                "authorizations": [
                    "https://example.com/acme/authz/PAniVnsZcis",
                    "https://example.com/acme/authz/r4HqLzrSrpI"
                ],

                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",

                "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn authorization() {
        let auth: Authorization = serde_json::from_str(
            r#"
            {
                "status": "pending",
                "identifier": {
                    "type": "dns",
                    "value": "www.example.org"
                },
                "challenges": [
                    {
                        "type": "http-01",
                        "url": "https://example.com/acme/chall/prV_B7yEyA4",
                        "status": "pending",
                        "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
                    },
                    {
                        "type": "dns-01",
                        "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
                        "status": "pending",
                        "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
                    },
                    {
                        "type": "tls-alpn-01",
                        "url": "https://example.com/acme/chall/TJds3qqnMAf",
                        "status": "pending",
                        "token": "nRsTyUVQh1YAwovxwzAEVgtFLRV47f7HAcRfl6pED5Y="
                    }
                ],

                "wildcard": false
            }"#,
        )
        .unwrap();

        assert_eq!(auth.challenges.len(), 3);
        assert_eq!(auth.challenges[0].kind, ChallengeKind::Http01);
        assert_eq!(auth.challenges[1].kind, ChallengeKind::Dns01);
        assert_eq!(auth.challenges[2].kind, ChallengeKind::TlsAlpn01);
    }

    #[test]
    fn error_kind() {
        let err: Problem = serde_json::from_str(
            r#"
            {
                "type": "urn:ietf:params:acme:error:badNonce",
                "detail": "The client sent an unacceptable anti-replay nonce"
            }"#,
        )
        .unwrap();

        assert_eq!(err.kind, ErrorKind::BadNonce);

        let err: Problem = serde_json::from_str(
            r#"
            {
                "type": "urn:ietf:params:acme:error:caa",
                "detail": "CAA records forbid the CA from issuing a certificate"
            }"#,
        )
        .unwrap();

        assert_eq!(err.kind, ErrorKind::Caa);

        let err: Problem = serde_json::from_str(
            r#"
            {
                "type": "unknown-error",
                "detail": "Some unknown error"
            }"#,
        )
        .unwrap();

        assert_eq!(err.kind, ErrorKind::Other("unknown-error".to_string()));

        let err: Problem = serde_json::from_str(
            r#"
            {
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "Some of the identifiers requested were rejected",
                "subproblems": [
                    {
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "Invalid underscore in DNS name \"_example.org\"",
                        "identifier": {
                            "type": "dns",
                            "value": "_example.org"
                        }
                    },
                    {
                        "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                        "detail": "This CA will not issue for \"example.net\"",
                        "identifier": {
                            "type": "dns",
                            "value": "example.net"
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(err.kind, ErrorKind::Malformed);
        assert_eq!(err.subproblems.len(), 2);
        assert_eq!(
            err.subproblems[0].identifier,
            Some(Identifier::Dns("_example.org".to_string()))
        )
    }
}
