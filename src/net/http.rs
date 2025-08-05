// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::future;
use core::ptr::NonNull;
use std::io;

use bytes::Bytes;
use http::uri::Scheme;
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use nginx_sys::{ngx_log_t, ngx_resolver_t, NGX_LOG_WARN};
use ngx::allocator::Box;
use ngx::async_::spawn;
use ngx::ngx_log_error;
use thiserror::Error;

use super::peer_conn::PeerConnection;
use super::resolver::Resolver;
use crate::conf::ssl::NgxSsl;

// The largest response we can reasonably expect is a certificate chain, which should not exceed
// a few kilobytes.
const NGX_ACME_MAX_BODY_SIZE: usize = 64 * 1024;

const NGINX_VER: &str = match nginx_sys::NGINX_VER.to_str() {
    Ok(x) => x.trim_ascii(),
    _ => unreachable!(),
};

const NGX_ACME_USER_AGENT: &str = constcat::concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " ",
    NGINX_VER,
);

#[allow(async_fn_in_trait)]
pub trait HttpClient {
    type Error: StdError + Send + Sync + 'static;

    async fn request<B>(&self, req: Request<B>) -> Result<Response<Bytes>, Self::Error>
    where
        B: Body + Send + 'static,
        <B as Body>::Data: Send,
        <B as Body>::Error: StdError + Send + Sync;
}

pub struct NgxHttpClient<'a> {
    log: NonNull<ngx_log_t>,
    resolver: Resolver,
    ssl: &'a NgxSsl,
    ssl_verify: bool,
}

#[derive(Debug, Error)]
pub enum HttpClientError {
    #[error("response body read error: {0}")]
    Body(std::boxed::Box<dyn StdError + Send + Sync>),
    #[error("request error: {0}")]
    Http(#[from] hyper::Error),
    #[error("name resolution error: {0}")]
    Resolver(super::resolver::Error),
    #[error("connection error: {0}")]
    Io(io::Error),
    #[error("invalid uri: {0}")]
    Uri(&'static str),
}

impl From<io::Error> for HttpClientError {
    fn from(err: io::Error) -> Self {
        match err.downcast::<super::resolver::Error>() {
            Ok(x) => Self::Resolver(x),
            Err(x) => Self::Io(x),
        }
    }
}

impl<'a> NgxHttpClient<'a> {
    pub fn new(
        log: NonNull<ngx_log_t>,
        resolver: NonNull<ngx_resolver_t>,
        resolver_timeout: usize,
        ssl: &'a NgxSsl,
        ssl_verify: bool,
    ) -> Self {
        Self {
            log,
            resolver: Resolver::from_resolver(resolver, resolver_timeout),
            ssl,
            ssl_verify,
        }
    }
}

impl HttpClient for NgxHttpClient<'_> {
    type Error = HttpClientError;

    async fn request<B>(&self, mut req: Request<B>) -> Result<Response<Bytes>, Self::Error>
    where
        B: Body + Send + 'static,
        <B as Body>::Data: Send,
        <B as Body>::Error: StdError + Send + Sync,
    {
        let uri = req.uri().clone();

        let authority = uri
            .authority()
            .ok_or(HttpClientError::Uri("missing authority"))?;

        let path_and_query = uri
            .path_and_query()
            .ok_or(HttpClientError::Uri("missing path"))?;

        *req.uri_mut() = path_and_query.clone().into();

        {
            let headers = req.headers_mut();
            headers.insert(
                http::header::HOST,
                http::HeaderValue::from_str(authority.as_str())
                    .map_err(|_| HttpClientError::Uri("bad authority"))?,
            );
            headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_static(NGX_ACME_USER_AGENT),
            );
            headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("close"),
            );
        }

        let ssl = if uri.scheme() == Some(&Scheme::HTTPS) {
            Some(self.ssl.as_ref())
        } else {
            None
        };

        let mut peer = Box::pin(PeerConnection::new(self.log)?);

        peer.as_mut()
            .connect_to(authority.as_str(), &self.resolver, ssl)
            .await?;

        if self.ssl_verify {
            if let Err(err) = peer.verify_peer() {
                let _ = future::poll_fn(|cx| peer.as_mut().poll_shutdown(cx)).await;
                return Err(err.into());
            }
        }

        if let Some(c) = peer.connection_mut() {
            c.requests += 1;
        }

        let (mut sender, conn) = hyper::client::conn::http1::handshake(peer).await?;

        let log = self.log;
        spawn(async move {
            if let Err(err) = conn.await {
                ngx_log_error!(NGX_LOG_WARN, log.as_ptr(), "connection error: {err}");
            }
        })
        .detach();

        let resp = sender.send_request(req).await?;
        let (parts, body) = resp.into_parts();

        let body = http_body_util::Limited::new(body, NGX_ACME_MAX_BODY_SIZE)
            .collect()
            .await
            .map_err(HttpClientError::Body)?
            .to_bytes();

        Ok(Response::from_parts(parts, body))
    }
}
