// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::error::Error as StdError;
use core::ffi::CStr;
use core::future;
use core::pin::Pin;
use core::ptr::NonNull;
use std::io;

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use nginx_sys::{ngx_log_t, ngx_resolver_t, NGX_LOG_WARN};
use ngx::allocator::Box;
use ngx::async_::resolver::Resolver;
use ngx::async_::spawn;
use ngx::ngx_log_error;
use thiserror::Error;

use super::peer_conn::PeerConnection;
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
}

#[derive(Debug, Error)]
pub enum HttpClientError {
    #[error(transparent)]
    Alloc(#[from] ngx::allocator::AllocError),
    #[error("response body read error: {0}")]
    Body(std::boxed::Box<dyn StdError + Send + Sync>),
    #[error("request error: {0}")]
    Http(#[from] hyper::Error),
    #[error("name resolution error: {0}")]
    Resolver(#[from] ngx::async_::resolver::Error),
    #[error("connection error: {0}")]
    Io(io::Error),
    #[error("invalid uri: {0}")]
    Uri(&'static str),
}

impl From<io::Error> for HttpClientError {
    fn from(err: io::Error) -> Self {
        match err.downcast::<ngx::async_::resolver::Error>() {
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
    ) -> Self {
        Self {
            log,
            resolver: Resolver::from_resolver(resolver, resolver_timeout),
            ssl,
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
        const DEFAULT_PATH: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/");

        let path_and_query = req
            .uri()
            .path_and_query()
            // filter empty ("") values that are represented as "/"
            .filter(|x| x.as_str() != "/")
            .cloned()
            .unwrap_or(DEFAULT_PATH);

        let uri = core::mem::replace(req.uri_mut(), path_and_query.into());

        let authority = uri
            .authority()
            .ok_or(HttpClientError::Uri("missing authority"))?;

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

        let mut peer = self.connect(&uri).await?;

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

impl NgxHttpClient<'_> {
    async fn connect(&self, uri: &http::Uri) -> Result<Pin<Box<PeerConnection>>, HttpClientError> {
        let mut pool = crate::util::OwnedPool::with_default_size(self.log)?;

        let authority = uri.authority().expect("checked before calling connect");
        let is_ssl = uri.scheme() == Some(&http::uri::Scheme::HTTPS);

        let url = {
            let mut url: nginx_sys::ngx_url_t = unsafe { core::mem::zeroed() };
            url.url = unsafe { crate::util::copy_bytes_with_nul(&pool, authority.as_str())? };
            url.default_port = if is_ssl { 443 } else { 80 };
            url.set_no_resolve(1);

            if ngx::core::Status(unsafe { nginx_sys::ngx_parse_url(pool.as_mut(), &mut url) })
                != ngx::core::Status::NGX_OK
            {
                if !url.err.is_null() {
                    // All error messages from ngx_parse_url() are static NULL-terminated strings.
                    let err: &'static str = unsafe { CStr::from_ptr(url.err) }
                        .to_str()
                        .unwrap_or("ngx_parse_url() failed");
                    return Err(HttpClientError::Uri(err));
                }
                return Err(HttpClientError::Uri("ngx_parse_url() failed"));
            }

            url
        };

        let resolved = url.naddrs == 0;
        let mut addr_vec;

        let addrs = if resolved {
            addr_vec = self.resolver.resolve_name(&url.host, pool.as_mut()).await?;
            for addr in addr_vec.iter_mut() {
                unsafe { nginx_sys::ngx_inet_set_port(addr.sockaddr, url.port) };
            }
            &mut addr_vec
        } else {
            unsafe { core::slice::from_raw_parts_mut(url.addrs, url.naddrs) }
        };

        let Some(addr) = addrs.get_mut(0) else {
            return Err(HttpClientError::Uri("no addresses"));
        };

        // Init addr.name for logging
        if addr.name.is_empty() {
            addr.name = url.url;
        }

        let mut peer = Box::pin(PeerConnection::new(self.log)?);
        peer.as_mut().connect(addr).await?;

        if is_ssl {
            let ssl_name = if resolved {
                let ssl_name = unsafe {
                    crate::util::copy_bytes_with_nul(&pool, url.host.as_bytes())
                        .map(|x| CStr::from_ptr(x.data.cast()))
                }?;
                Some(ssl_name)
            } else {
                None
            };

            future::poll_fn(|cx| {
                peer.as_mut()
                    .poll_ssl_handshake(self.ssl.as_ref(), ssl_name, cx)
            })
            .await?;
        }

        Ok(peer)
    }
}
