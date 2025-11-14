// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::time::Duration;

use ngx::allocator::{unsize_box, Box};
use thiserror::Error;

use super::solvers::SolverError;
use super::types::{AccountStatus, Problem, ProblemCategory};
use crate::net::http::HttpClientError;

#[derive(Debug, Error)]
pub enum NewAccountError {
    #[error("directory update failed ({0})")]
    Directory(RequestError),

    #[error("external account key required")]
    ExternalAccount,

    #[error(transparent)]
    Protocol(#[from] Problem),

    #[error("account request failed ({0})")]
    Request(RequestError),

    #[error("unexpected account status {0:?}")]
    Status(AccountStatus),

    #[error("no account URL in response")]
    Url,
}

impl From<RequestError> for NewAccountError {
    fn from(value: RequestError) -> Self {
        match value {
            RequestError::Protocol(problem) => Self::Protocol(problem),
            _ => Self::Request(value),
        }
    }
}

impl NewAccountError {
    pub fn is_invalid(&self) -> bool {
        match self {
            Self::ExternalAccount => true,
            Self::Protocol(err) => matches!(
                err.category(),
                ProblemCategory::Account | ProblemCategory::Malformed
            ),
            Self::Status(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum NewCertificateError {
    #[error("unexpected authorization status {0:?}")]
    AuthorizationStatus(super::types::AuthorizationStatus),

    #[error("unexpected challenge status {0:?}")]
    ChallengeStatus(super::types::ChallengeStatus),

    #[error("csr generation failed ({0})")]
    Csr(openssl::error::ErrorStack),

    #[error("PEM_read_bio_X509() failed: {0}")]
    InvalidCertificate(openssl::error::ErrorStack),

    #[error("no certificate in the completed order")]
    MissingCertificate,

    #[error("no supported challenges")]
    NoSupportedChallenges,

    #[error("unexpected order status {0:?}")]
    OrderStatus(super::types::OrderStatus),

    #[error("invalid or missing order URL")]
    OrderUrl,

    #[error(transparent)]
    PrivateKey(#[from] crate::conf::pkey::PKeyGenError),

    #[error(transparent)]
    Protocol(#[from] Problem),

    #[error(transparent)]
    Request(RequestError),

    #[error(transparent)]
    Solver(#[from] SolverError),
}

impl From<RequestError> for NewCertificateError {
    fn from(value: RequestError) -> Self {
        match value {
            RequestError::Protocol(problem) => Self::Protocol(problem),
            _ => Self::Request(value),
        }
    }
}

impl NewCertificateError {
    pub fn is_invalid(&self) -> bool {
        match self {
            Self::Protocol(err) => matches!(
                err.category(),
                ProblemCategory::Order | ProblemCategory::Malformed
            ),
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum RedirectError {
    #[error("invalid redirect URI")]
    InvalidRedirectUri,

    #[error("missing redirect URI")]
    MissingRedirectUri,

    #[error("too many redirects")]
    TooManyRedirects,
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    Client(Box<dyn StdError + Send + Sync>),

    #[error("cannot deserialize problem document ({0})")]
    ErrorFormat(#[from] serde_json::Error),

    #[error("cannot build request ({0})")]
    Http(#[from] http::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("cannot obtain replay nonce")]
    Nonce,

    #[error(transparent)]
    Protocol(#[from] Problem),

    #[error("rate limit exceeded, next attempt in {0:?}")]
    RateLimited(Duration),

    #[error("redirect failed: {0}")]
    Redirect(#[from] RedirectError),

    #[error("cannot serialize request ({0})")]
    RequestFormat(serde_json::Error),

    #[error("cannot deserialize response ({0})")]
    ResponseFormat(serde_json::Error),

    #[error("cannot sign request body ({0})")]
    Sign(#[from] crate::jws::Error),
}

impl From<HttpClientError> for RequestError {
    fn from(value: HttpClientError) -> Self {
        match value {
            HttpClientError::Io(err) => Self::Io(err),
            _ => Self::Client(unsize_box!(Box::new(value))),
        }
    }
}
