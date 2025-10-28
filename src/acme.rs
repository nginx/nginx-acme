// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::cell::RefCell;
use core::ptr::NonNull;
use core::time::Duration;
use std::collections::VecDeque;
use std::string::{String, ToString};

use bytes::Bytes;
use error::{NewAccountError, NewCertificateError, RedirectError, RequestError};
use http::Uri;
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use ngx::allocator::{Allocator, Box};
use ngx::async_::sleep;
use ngx::collections::Vec;
use ngx::ngx_log_debug;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::{self, extension as x509_ext, X509Req, X509};
use types::{AccountStatus, ProblemCategory};

use self::account_key::{AccountKey, AccountKeyError};
use self::types::{AuthorizationStatus, ChallengeKind, ChallengeStatus, OrderStatus};
use crate::conf::identifier::Identifier;
use crate::conf::issuer::{CertificateChainMatcher, Issuer, Profile};
use crate::conf::order::CertificateOrder;
use crate::net::http::HttpClient;
use crate::time::Time;

pub mod account_key;
pub mod error;
pub mod headers;
pub mod solvers;
pub mod types;

const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Upper limit for locally generated increasing backoff interval.
const MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(8);

/// Upper limit for server-generated retry intervals (Retry-After).
const MAX_SERVER_RETRY_INTERVAL: Duration = Duration::from_secs(60);

static REPLAY_NONCE: http::HeaderName = http::HeaderName::from_static("replay-nonce");

// Maximum number of redirects to follow for a single request.
const MAX_REDIRECTS: usize = 10;

pub enum NewAccountOutput<'a> {
    Created(&'a str),
    Found(&'a str),
}

pub struct NewCertificateOutput {
    pub bytes: Bytes,
    pub x509: std::vec::Vec<X509>,
    pub pkey: PKey<Private>,
}

pub struct AuthorizationContext<'a> {
    /// Account key thumbprint.
    pub thumbprint: &'a [u8],
    /// A private key generated for the new certificate request.
    ///
    /// This is used in tls-alpn-01 challenge to avoid generating a new key on each verification
    /// attempt.
    pub pkey: &'a PKeyRef<Private>,
}

pub struct AcmeClient<'a, Http>
where
    Http: HttpClient,
{
    issuer: &'a Issuer,
    http: Http,
    log: NonNull<nginx_sys::ngx_log_t>,
    key: AccountKey,
    account: Option<String>,
    profile: Option<&'a str>,
    nonce: NoncePool,
    directory: types::Directory,
    solvers: Vec<Box<dyn solvers::ChallengeSolver + Send + 'a>>,
    authorization_timeout: Duration,
    finalize_timeout: Duration,
    network_error_retries: usize,
}

#[derive(Default)]
pub struct NoncePool(RefCell<VecDeque<String>>);

impl NoncePool {
    pub fn get(&self) -> Option<String> {
        self.0.borrow_mut().pop_front()
    }

    pub fn add(&self, nonce: String) {
        self.0.borrow_mut().push_back(nonce);
    }

    pub fn add_from_response<T>(&self, res: &http::Response<T>) {
        if let Some(nonce) = try_get_header(res.headers(), &REPLAY_NONCE) {
            self.add(nonce.to_string());
        }
    }
}

#[inline]
fn try_get_header<K: http::header::AsHeaderName>(
    headers: &http::HeaderMap,
    key: K,
) -> Option<&str> {
    headers.get(key).and_then(|x| x.to_str().ok())
}

fn resolve_uri(base: &Uri, relative: &str) -> Option<Uri> {
    let base_abs = UriAbsoluteString::try_from(base.to_string()).ok()?;
    let location_ref = UriReferenceStr::new(relative).ok()?;
    let resolved = location_ref.resolve_against(&base_abs).to_string();
    Uri::try_from(resolved).ok()
}

impl<'a, Http> AcmeClient<'a, Http>
where
    Http: HttpClient,
    RequestError: From<<Http as HttpClient>::Error>,
{
    pub fn new(
        http: Http,
        issuer: &'a Issuer,
        log: NonNull<nginx_sys::ngx_log_t>,
    ) -> Result<Self, AccountKeyError> {
        let key = AccountKey::try_from(
            issuer
                .pkey
                .as_ref()
                .expect("checked during configuration load")
                .as_ref(),
        )?;

        Ok(Self {
            issuer,
            http,
            log,
            key,
            account: None,
            profile: None,
            nonce: Default::default(),
            directory: Default::default(),
            solvers: Vec::new(),
            authorization_timeout: Duration::from_secs(60),
            finalize_timeout: Duration::from_secs(60),
            network_error_retries: 3,
        })
    }

    pub fn add_solver(&mut self, s: impl solvers::ChallengeSolver + Send + 'a) {
        self.solvers.push(ngx::allocator::unsize_box!(Box::new(s)))
    }

    pub fn find_solver_for(
        &self,
        kind: &ChallengeKind,
    ) -> Option<&Box<dyn solvers::ChallengeSolver + Send + 'a>> {
        self.solvers.iter().find(|x| x.supports(kind))
    }

    pub fn is_supported_challenge(&self, kind: &ChallengeKind) -> bool {
        self.solvers.iter().any(|s| s.supports(kind))
    }

    async fn get_directory(&self) -> Result<types::Directory, RequestError> {
        let res = self.get(&self.issuer.uri).await?;
        let directory = deserialize_body(res.body())?;

        Ok(directory)
    }

    async fn get_nonce(&self) -> Result<String, RequestError> {
        let res = self.get(&self.directory.new_nonce).await?;
        try_get_header(res.headers(), &REPLAY_NONCE)
            .ok_or(RequestError::Nonce)
            .map(String::from)
    }

    pub async fn get(&self, url: &Uri) -> Result<http::Response<Bytes>, RequestError> {
        let mut u = url.clone();

        for _ in 0..MAX_REDIRECTS {
            let req = http::Request::builder()
                .uri(&u)
                .method(http::Method::GET)
                .header(http::header::CONTENT_LENGTH, 0)
                .body(String::new())?;
            let res = self.http.request(req).await?;

            if res.status().is_redirection() {
                let location = try_get_header(res.headers(), http::header::LOCATION)
                    .ok_or(RedirectError::MissingRedirectUri)?;
                u = resolve_uri(&u, location).ok_or(RedirectError::InvalidRedirectUri)?;
                continue;
            }

            return Ok(res);
        }

        Err(RedirectError::TooManyRedirects.into())
    }

    pub async fn post<P: AsRef<[u8]>>(
        &self,
        url: &Uri,
        payload: P,
    ) -> Result<http::Response<Bytes>, RequestError> {
        let mut nonce = if let Some(nonce) = self.nonce.get() {
            nonce
        } else {
            self.get_nonce().await?
        };

        let mut tries = core::iter::repeat(DEFAULT_RETRY_INTERVAL).take(self.network_error_retries);

        ngx_log_debug!(self.log.as_ptr(), "sending request to {url:?}");
        let res = loop {
            let body = crate::jws::sign_jws(
                &self.key,
                self.account.as_deref(),
                &url.to_string(),
                Some(&nonce),
                payload.as_ref(),
            )?
            .to_string();

            let req = http::Request::builder()
                .uri(url)
                .method(http::Method::POST)
                .header(http::header::CONTENT_LENGTH, body.len())
                .header(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/jose+json"),
                )
                .body(body)?;

            let res = match self.http.request(req).await {
                Ok(res) => res,
                Err(err) => {
                    // TODO: limit retries to connection errors
                    if let Some(tm) = tries.next() {
                        sleep(tm).await;
                        ngx_log_debug!(self.log.as_ptr(), "retrying failed request ({err})");
                        continue;
                    } else {
                        return Err(err.into());
                    }
                }
            };

            if res.status().is_success() {
                break res;
            }

            // 8555.6.5, when retrying in response to a "badNonce" error, the client MUST use
            // the nonce provided in the error response.
            nonce = try_get_header(res.headers(), &REPLAY_NONCE)
                .ok_or(RequestError::Nonce)?
                .to_string();

            let err: types::Problem = deserialize_body(res.body())?;

            let retriable = match err.kind {
                types::ErrorKind::RateLimited => {
                    // The server may ask us to retry in several hours or days.
                    if let Some(val) = res
                        .headers()
                        .get(http::header::RETRY_AFTER)
                        .and_then(headers::parse_retry_after)
                        .filter(|x| x > &MAX_SERVER_RETRY_INTERVAL)
                    {
                        return Err(RequestError::RateLimited(val));
                    }
                    true
                }
                types::ErrorKind::BadNonce => true,
                _ => false,
            };

            if retriable && wait_for_retry(&res, &mut tries).await {
                ngx_log_debug!(self.log.as_ptr(), "retrying failed request ({err})");
                continue;
            }

            self.nonce.add(nonce);
            return Err(err.into());
        };

        self.nonce.add_from_response(&res);

        Ok(res)
    }

    pub async fn new_account(&mut self) -> Result<NewAccountOutput<'_>, NewAccountError> {
        self.directory = self
            .get_directory()
            .await
            .map_err(NewAccountError::Directory)?;

        if self.directory.meta.external_account_required == Some(true)
            && self.issuer.eab_key.is_none()
        {
            return Err(NewAccountError::ExternalAccount);
        }

        let external_account_binding = self
            .issuer
            .eab_key
            .as_ref()
            .map(|x| -> Result<_, RequestError> {
                let key = crate::jws::ShaWithHmacKey::new(&x.key, 256);
                let payload = serde_json::to_vec(&self.key)?;
                let message = crate::jws::sign_jws(
                    &key,
                    Some(x.kid),
                    &self.directory.new_account.to_string(),
                    None,
                    &payload,
                )?;
                Ok(message)
            })
            .transpose()?;

        self.profile = match self.issuer.profile {
            Profile::Required(x) => Some(x),
            Profile::Preferred(x) if self.directory.meta.profiles.contains_key(x) => Some(x),
            Profile::Preferred(x) => {
                ngx::ngx_log_error!(
                    nginx_sys::NGX_LOG_NOTICE,
                    self.log.as_ptr(),
                    "acme profile \"{x}\" is not supported by the server"
                );
                None
            }
            _ => None,
        };

        let payload = types::AccountRequest {
            terms_of_service_agreed: self.issuer.accept_tos,
            contact: &self.issuer.contacts,
            external_account_binding,

            ..Default::default()
        };
        let payload = serde_json::to_string(&payload).map_err(RequestError::RequestFormat)?;

        let res = self.post(&self.directory.new_account, payload).await?;

        let account: types::Account = deserialize_body(res.body())?;
        if !matches!(account.status, AccountStatus::Valid) {
            return Err(NewAccountError::Status(account.status));
        }

        let key_id: &str =
            try_get_header(res.headers(), http::header::LOCATION).ok_or(NewAccountError::Url)?;

        self.account = Some(key_id.to_string());

        let key_id = self.account.as_ref().unwrap();
        match res.status() {
            http::StatusCode::CREATED => Ok(NewAccountOutput::Created(key_id)),
            _ => Ok(NewAccountOutput::Found(key_id)),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.account.is_some()
    }

    pub async fn new_certificate<A>(
        &self,
        req: &CertificateOrder<&str, A>,
    ) -> Result<NewCertificateOutput, NewCertificateError>
    where
        A: Allocator,
    {
        ngx_log_debug!(
            self.log.as_ptr(),
            "new certificate request: {:?}",
            req.identifiers
        );
        let identifiers: Vec<Identifier<&str>> =
            req.identifiers.iter().map(|x| x.as_ref()).collect();

        let payload = types::OrderRequest {
            identifiers: &identifiers,
            not_before: None,
            not_after: None,
            profile: self.profile,
        };

        let payload = serde_json::to_string(&payload).map_err(RequestError::RequestFormat)?;

        let res = self.post(&self.directory.new_order, payload).await?;

        let order_url = try_get_header(res.headers(), http::header::LOCATION)
            .and_then(|x| Uri::try_from(x).ok())
            .ok_or(NewCertificateError::OrderUrl)?;

        let order: types::Order = deserialize_body(res.body())?;

        let mut pending_authorizations: Vec<(http::Uri, types::Authorization)> = Vec::new();
        for auth_url in order.authorizations {
            let res = self.post(&auth_url, b"").await?;
            let mut authorization: types::Authorization = deserialize_body(res.body())?;

            match authorization.status {
                types::AuthorizationStatus::Pending => {
                    authorization
                        .challenges
                        .retain(|x| self.is_supported_challenge(&x.kind));

                    if authorization.challenges.is_empty() {
                        return Err(NewCertificateError::NoSupportedChallenges);
                    }

                    pending_authorizations.push((auth_url, authorization))
                }
                types::AuthorizationStatus::Valid => {
                    ngx_log_debug!(
                        self.log.as_ptr(),
                        "authorization {:?}: identifier {:?} already validated",
                        auth_url,
                        authorization.identifier
                    );
                }
                status => return Err(NewCertificateError::AuthorizationStatus(status)),
            }
        }

        let pkey = req.key.generate()?;

        let order = AuthorizationContext {
            thumbprint: self.key.thumbprint(),
            pkey: &pkey,
        };

        for (url, authorization) in pending_authorizations {
            self.do_authorization(&order, url, authorization).await?;
        }

        let mut res = self.post(&order_url, b"").await?;
        let mut order: types::Order = deserialize_body(res.body())?;

        if order.status != OrderStatus::Ready {
            if let Some(err) = order.error {
                return Err(err.into());
            }
            return Err(NewCertificateError::OrderStatus(order.status));
        }

        let csr = make_certificate_request(&order.identifiers, &pkey)
            .and_then(|x| x.to_der())
            .map_err(NewCertificateError::Csr)?;
        let payload = std::format!(r#"{{"csr":"{}"}}"#, crate::jws::base64url(csr));

        match self.post(&order.finalize, payload).await {
            Ok(x) => {
                drop(order);
                res = x;
                order = deserialize_body(res.body())?;
            }
            Err(RequestError::Protocol(problem))
                if matches!(
                    problem.category(),
                    ProblemCategory::Order | ProblemCategory::Malformed
                ) =>
            {
                return Err(problem.into())
            }
            _ => order.status = OrderStatus::Processing,
        };

        let mut tries = backoff(MAX_BACKOFF_INTERVAL, self.finalize_timeout);

        while order.status == OrderStatus::Processing && wait_for_retry(&res, &mut tries).await {
            drop(order);
            res = self.post(&order_url, b"").await?;
            order = deserialize_body(res.body())?;
        }

        let certificate = order
            .certificate
            .ok_or(NewCertificateError::MissingCertificate)?;

        let res = self.post(&certificate, b"").await?;

        if let Some(ref matcher) = self.issuer.chain {
            let (bytes, x509) = self
                .find_preferred_chain(&certificate, res, matcher)
                .await?;
            Ok(NewCertificateOutput { bytes, x509, pkey })
        } else {
            let bytes = res.into_body();
            let x509 =
                X509::stack_from_pem(&bytes).map_err(NewCertificateError::InvalidCertificate)?;
            if x509.is_empty() {
                return Err(NewCertificateError::MissingCertificate);
            }

            Ok(NewCertificateOutput { bytes, x509, pkey })
        }
    }

    async fn find_preferred_chain(
        &self,
        base: &Uri,
        cert: http::Response<Bytes>,
        matcher: &CertificateChainMatcher,
    ) -> Result<(Bytes, std::vec::Vec<X509>), NewCertificateError> {
        let default =
            X509::stack_from_pem(cert.body()).map_err(NewCertificateError::InvalidCertificate)?;

        if !matcher.test(&default) {
            if let Ok(base) = iri_string::types::UriAbsoluteString::try_from(base.to_string()) {
                let alternates = cert
                    .headers()
                    .get_all(http::header::LINK)
                    .into_iter()
                    .filter_map(headers::parse_link)
                    .flatten()
                    .filter(|x| x.is_rel("alternate"));

                for link in alternates {
                    let uri = link.target.resolve_against(&base).to_string();
                    let Ok(uri) = Uri::try_from(uri) else {
                        continue;
                    };

                    let res = self.post(&uri, b"").await?;
                    let bytes = res.into_body();

                    let stack = X509::stack_from_pem(&bytes)
                        .map_err(NewCertificateError::InvalidCertificate)?;
                    if matcher.test(&stack) {
                        return Ok((bytes, stack));
                    }
                }
            }
        }

        if default.is_empty() {
            return Err(NewCertificateError::MissingCertificate);
        }

        Ok((cert.into_body(), default))
    }

    async fn do_authorization(
        &self,
        order: &AuthorizationContext<'_>,
        url: http::Uri,
        authorization: types::Authorization,
    ) -> Result<(), NewCertificateError> {
        let identifier = authorization.identifier.as_ref();

        // Find and set up first supported challenge.
        let (challenge, solver) = authorization
            .challenges
            .iter()
            .find_map(|x| {
                let solver = self.find_solver_for(&x.kind)?;
                Some((x, solver))
            })
            .ok_or(NewCertificateError::NoSupportedChallenges)?;

        solver.register(order, &identifier, challenge)?;

        scopeguard::defer! {
            let _ = solver.unregister(&identifier, challenge);
        };

        let res = self.post(&challenge.url, b"{}").await?;
        let result: types::Challenge = deserialize_body(res.body())?;
        if !matches!(
            result.status,
            ChallengeStatus::Pending | ChallengeStatus::Processing | ChallengeStatus::Valid
        ) {
            return Err(NewCertificateError::ChallengeStatus(result.status));
        }

        let mut tries = backoff(MAX_BACKOFF_INTERVAL, self.authorization_timeout);
        wait_for_retry(&res, &mut tries).await;

        let result = loop {
            let res = self.post(&url, b"").await?;
            let result: types::Authorization = deserialize_body(res.body())?;

            if result.status != AuthorizationStatus::Pending
                || !wait_for_retry(&res, &mut tries).await
            {
                break result;
            }
        };

        ngx_log_debug!(
            self.log.as_ptr(),
            "authorization status for {:?}: {:?}",
            authorization.identifier,
            result.status
        );

        if result.status != AuthorizationStatus::Valid {
            if let Some(err) = result
                .challenges
                .iter()
                .find(|x| x.kind == challenge.kind)
                .and_then(|x| x.error.clone())
            {
                return Err(err.into());
            } else {
                return Err(NewCertificateError::AuthorizationStatus(result.status));
            }
        }

        Ok(())
    }
}

pub fn make_certificate_request(
    identifiers: &[Identifier<&str>],
    pkey: &PKeyRef<Private>,
) -> Result<X509Req, openssl::error::ErrorStack> {
    let mut req = X509Req::builder()?;

    let mut x509_name = x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", identifiers[0].value())?;
    let x509_name = x509_name.build();
    req.set_subject_name(&x509_name)?;

    let mut extensions = openssl::stack::Stack::new()?;

    let mut subject_alt_name = x509_ext::SubjectAlternativeName::new();
    for identifier in identifiers {
        match identifier {
            Identifier::Dns(name) => {
                subject_alt_name.dns(name);
            }
            Identifier::Ip(addr) => {
                subject_alt_name.ip(addr);
            }
            _ => (),
        };
    }
    let subject_alt_name = subject_alt_name.build(&req.x509v3_context(None))?;
    extensions.push(subject_alt_name)?;

    req.add_extensions(&extensions)?;

    req.set_pubkey(pkey)?;
    req.sign(pkey, openssl::hash::MessageDigest::sha256())?;
    Ok(req.build())
}

/// Waits until the next retry attempt is allowed.
async fn wait_for_retry<B>(
    res: &http::Response<B>,
    policy: &mut impl Iterator<Item = Duration>,
) -> bool {
    let Some(interval) = policy.next() else {
        return false;
    };

    let retry_after = res
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(headers::parse_retry_after)
        .unwrap_or(interval)
        .min(MAX_SERVER_RETRY_INTERVAL);

    sleep(retry_after).await;
    true
}

/// Generate increasing intervals saturated at `max` until `timeout` has passed.
fn backoff(max: Duration, timeout: Duration) -> impl Iterator<Item = Duration> {
    let first = (Duration::ZERO, Duration::from_secs(1));
    let stop = Time::now() + timeout;

    core::iter::successors(Some(first), move |prev: &(Duration, Duration)| {
        if Time::now() >= stop {
            return None;
        }
        Some((prev.1, prev.0.saturating_add(prev.1)))
    })
    .map(move |(_, x)| x.min(max))
}

/// Deserializes JSON response body as T and converts error type.
#[inline(always)]
fn deserialize_body<'a, T>(bytes: &'a Bytes) -> Result<T, RequestError>
where
    T: serde::Deserialize<'a>,
{
    serde_json::from_slice(bytes).map_err(RequestError::ResponseFormat)
}
