// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::cell::RefCell;
use core::ptr::NonNull;
use core::time::Duration;
use std::collections::VecDeque;
use std::string::{String, ToString};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::Uri;
use ngx::allocator::{Allocator, Box};
use ngx::async_::sleep;
use ngx::collections::Vec;
use ngx::ngx_log_debug;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::{self, extension as x509_ext, X509Req};

use self::account_key::AccountKey;
use self::types::{AuthorizationStatus, ChallengeKind, ChallengeStatus, OrderStatus};
use crate::conf::identifier::Identifier;
use crate::conf::issuer::Issuer;
use crate::conf::order::CertificateOrder;
use crate::net::http::HttpClient;
use crate::time::Time;

pub mod account_key;
pub mod solvers;
pub mod types;

const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_secs(1);
static REPLAY_NONCE: http::HeaderName = http::HeaderName::from_static("replay-nonce");

pub struct NewCertificateOutput {
    pub chain: Bytes,
    pub pkey: PKey<Private>,
}

pub struct AuthorizationContext<'a> {
    pub thumbprint: &'a [u8],
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
    nonce: NoncePool,
    directory: types::Directory,
    solvers: Vec<Box<dyn solvers::ChallengeSolver + Send + 'a>>,
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

impl<'a, Http> AcmeClient<'a, Http>
where
    Http: HttpClient,
{
    pub fn new(http: Http, issuer: &'a Issuer, log: NonNull<nginx_sys::ngx_log_t>) -> Result<Self> {
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
            nonce: Default::default(),
            directory: Default::default(),
            solvers: Vec::new(),
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

    async fn get_directory(&mut self) -> Result<types::Directory> {
        let res = self.get(&self.issuer.uri).await?;
        let directory = serde_json::from_slice(res.body())?;

        Ok(directory)
    }

    async fn get_nonce(&self) -> Result<String> {
        let res = self.get(&self.directory.new_nonce).await?;
        try_get_header(res.headers(), &REPLAY_NONCE)
            .ok_or(anyhow!("no nonce in response headers"))
            .map(String::from)
    }

    pub async fn get(&self, url: &Uri) -> Result<http::Response<Bytes>> {
        let req = http::Request::builder()
            .uri(url)
            .method(http::Method::GET)
            .header(http::header::CONTENT_LENGTH, 0)
            .body(String::new())?;
        Ok(self.http.request(req).await?)
    }

    pub async fn post<P: AsRef<[u8]>>(
        &self,
        url: &Uri,
        payload: P,
    ) -> Result<http::Response<Bytes>> {
        let mut fails = 0;

        let mut nonce = if let Some(nonce) = self.nonce.get() {
            nonce
        } else {
            self.get_nonce().await?
        };

        ngx_log_debug!(self.log.as_ptr(), "sending request to {url:?}");
        let res = loop {
            let body = crate::jws::sign_jws(
                &self.key,
                self.account.as_deref(),
                &url.to_string(),
                &nonce,
                payload.as_ref(),
            )?;
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
                Err(e) if fails >= 3 => return Err(e.into()),
                // TODO: limit retries to connection errors
                Err(_) => {
                    fails += 1;
                    sleep(DEFAULT_RETRY_INTERVAL).await;
                    ngx_log_debug!(self.log.as_ptr(), "retrying: {} of 3", fails + 1);
                    continue;
                }
            };

            if res.status().is_success() {
                break res;
            }

            // 8555.6.5, when retrying in response to a "badNonce" error, the client MUST use
            // the nonce provided in the error response.
            nonce = try_get_header(res.headers(), &REPLAY_NONCE)
                .ok_or(anyhow!("no nonce in response"))?
                .to_string();

            let err: types::Problem = serde_json::from_slice(res.body())?;

            let retriable = matches!(
                err.kind,
                types::ErrorKind::BadNonce | types::ErrorKind::RateLimited
            );

            if !retriable || fails >= 3 {
                self.nonce.add(nonce);
                return Err(err.into());
            }

            fails += 1;

            wait_for_retry(&res).await;
            ngx_log_debug!(self.log.as_ptr(), "retrying: {} of 3", fails + 1);
        };

        self.nonce.add_from_response(&res);

        Ok(res)
    }

    pub async fn new_account(&mut self) -> Result<types::Account> {
        self.directory = self.get_directory().await?;

        let payload = types::AccountRequest {
            terms_of_service_agreed: self.issuer.accept_tos,
            contact: &self.issuer.contacts,

            ..Default::default()
        };
        let payload = serde_json::to_string(&payload)?;

        let res = self.post(&self.directory.new_account, payload).await?;

        let key_id = res
            .headers()
            .get("location")
            .ok_or(anyhow!("account URL unavailable"))?
            .to_str()?
            .to_string();
        self.account = Some(key_id);
        self.nonce.add_from_response(&res);

        Ok(serde_json::from_slice(res.body())?)
    }

    pub fn is_ready(&self) -> bool {
        self.account.is_some()
    }

    pub async fn new_certificate<A>(
        &mut self,
        req: &CertificateOrder<&str, A>,
    ) -> Result<NewCertificateOutput>
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
        };

        let payload = serde_json::to_string(&payload)?;

        let res = self.post(&self.directory.new_order, payload).await?;

        let order_url = res
            .headers()
            .get("location")
            .and_then(|x| x.to_str().ok())
            .ok_or(anyhow!("no order URL"))?;

        let order_url = Uri::try_from(order_url)?;
        let order: types::Order = serde_json::from_slice(res.body())?;

        let mut authorizations: Vec<(http::Uri, types::Authorization)> = Vec::new();
        for auth_url in order.authorizations {
            let res = self.post(&auth_url, b"").await?;
            let mut authorization: types::Authorization = serde_json::from_slice(res.body())?;

            authorization
                .challenges
                .retain(|x| self.is_supported_challenge(&x.kind));

            if authorization.challenges.is_empty() {
                anyhow::bail!("no supported challenge for {:?}", authorization.identifier)
            }

            match authorization.status {
                types::AuthorizationStatus::Pending => {
                    authorizations.push((auth_url, authorization))
                }
                types::AuthorizationStatus::Valid => {
                    ngx_log_debug!(
                        self.log.as_ptr(),
                        "authorization {:?}: identifier {:?} already validated",
                        auth_url,
                        authorization.identifier
                    );
                }
                status => anyhow::bail!(
                    "unexpected authorization status for {:?}: {:?}",
                    authorization.identifier,
                    status
                ),
            }
        }

        let pkey = req.key.generate()?;

        let order = AuthorizationContext {
            thumbprint: self.key.thumbprint(),
        };

        for (url, authorization) in authorizations {
            self.do_authorization(&order, url, authorization).await?;
        }

        let mut res = self.post(&order_url, b"").await?;
        let mut order: types::Order = serde_json::from_slice(res.body())?;

        if order.status != OrderStatus::Ready {
            anyhow::bail!("not ready");
        }

        let csr = make_certificate_request(&order.identifiers, &pkey).and_then(|x| x.to_der())?;
        let payload = std::format!(r#"{{"csr":"{}"}}"#, crate::jws::base64url(csr));

        match self.post(&order.finalize, payload).await {
            Ok(x) => {
                drop(order);
                res = x;
                order = serde_json::from_slice(res.body())?;
            }
            Err(err) => {
                if !err.to_string().contains("orderNotReady") {
                    return Err(err);
                }
                order.status = OrderStatus::Processing
            }
        };

        let mut tries = 10;

        while order.status == OrderStatus::Processing && tries > 0 {
            tries -= 1;
            wait_for_retry(&res).await;

            drop(order);
            res = self.post(&order_url, b"").await?;
            order = serde_json::from_slice(res.body())?;
        }

        let certificate = order.certificate.ok_or(anyhow!("certificate not ready"))?;

        let chain = self.post(&certificate, b"").await?.into_body();

        Ok(NewCertificateOutput { chain, pkey })
    }

    async fn do_authorization(
        &self,
        order: &AuthorizationContext<'_>,
        url: http::Uri,
        authorization: types::Authorization,
    ) -> Result<()> {
        let mut result = Err(anyhow!("no challenges"));
        let identifier = authorization.identifier.as_ref();

        for challenge in authorization.challenges {
            result = self.do_challenge(order, &identifier, &challenge).await;

            if result.is_ok() {
                break;
            }
        }

        result?;

        let mut tries = 10;

        let result = loop {
            let res = self.post(&url, b"").await?;
            let result: types::Authorization = serde_json::from_slice(res.body())?;

            if result.status != AuthorizationStatus::Pending || tries == 0 {
                break result;
            }

            tries -= 1;
            wait_for_retry(&res).await;
        };

        ngx_log_debug!(
            self.log.as_ptr(),
            "authorization status for {:?}: {:?}",
            authorization.identifier,
            result.status
        );

        if result.status != AuthorizationStatus::Valid {
            return Err(anyhow!("authorization failed"));
        }

        Ok(())
    }

    async fn do_challenge(
        &self,
        ctx: &AuthorizationContext<'_>,
        identifier: &Identifier<&str>,
        challenge: &types::Challenge,
    ) -> Result<()> {
        let res = self.post(&challenge.url, b"").await?;
        let result: types::Challenge = serde_json::from_slice(res.body())?;

        // Previous challenge result is still valid.
        // Should not happen as we already skip valid authorizations.
        if result.status == ChallengeStatus::Valid {
            return Ok(());
        }

        let solver = self
            .find_solver_for(&challenge.kind)
            .ok_or(anyhow!("no solver for {:?}", challenge.kind))?;

        solver.register(ctx, identifier, challenge)?;

        scopeguard::defer! {
            let _ = solver.unregister(identifier, challenge);
        };

        // "{}" in request payload initiates the challenge, "" checks the status.
        let mut payload: &[u8] = b"{}";
        let mut tries = 10;

        let result = loop {
            let res = self.post(&challenge.url, payload).await?;
            let result: types::Challenge = serde_json::from_slice(res.body())?;

            if !matches!(
                result.status,
                ChallengeStatus::Pending | ChallengeStatus::Processing,
            ) || tries == 0
            {
                break result;
            }

            tries -= 1;
            payload = b"";
            wait_for_retry(&res).await;
        };

        if result.status != ChallengeStatus::Valid {
            return Err(result
                .error
                .map(Into::into)
                .unwrap_or(anyhow!("unknown error")));
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
async fn wait_for_retry<B>(res: &http::Response<B>) {
    let retry_after = res
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(parse_retry_after)
        .unwrap_or(DEFAULT_RETRY_INTERVAL);
    sleep(retry_after).await
}

fn parse_retry_after(val: &http::HeaderValue) -> Option<Duration> {
    let val = val.to_str().ok()?;

    // Retry-After: <http-date>
    if let Ok(time) = Time::parse(val) {
        return Some(time - Time::now());
    }

    // Retry-After: <delay-seconds>
    val.parse().map(Duration::from_secs).ok()
}
