// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_long, CStr};
use core::future;
use core::mem;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::task::{self, Poll};
use std::io;

use nginx_sys::{
    ngx_addr_t, ngx_connection_t, ngx_destroy_pool, ngx_event_connect_peer, ngx_event_get_peer,
    ngx_inet_set_port, ngx_int_t, ngx_log_t, ngx_msec_t, ngx_peer_connection_t, ngx_pool_t,
    ngx_ssl_shutdown, ngx_ssl_t, ngx_str_t, ngx_url_t, NGX_DEFAULT_POOL_SIZE, NGX_LOG_ERR,
    NGX_LOG_WARN,
};
use ngx::collections::Vec;
use ngx::core::Status;
use ngx::{ngx_log_debug, ngx_log_error};
use openssl_sys::{SSL_get_verify_result, X509_verify_cert_error_string, X509_V_OK};

use super::connection::{Connection, ConnectionLogError};
use super::resolver::Resolver;
use crate::util::OwnedPool;

const ACME_DEFAULT_READ_TIMEOUT: ngx_msec_t = 60000;

/// Async wrapper over an [ngx_peer_connection_t].
pub struct PeerConnection {
    pub pool: OwnedPool,
    pub pc: ngx_peer_connection_t,
    pub rev: Option<task::Waker>,
    pub wev: Option<task::Waker>,
    server_name: Option<NonNull<ngx_str_t>>,
}

impl hyper::rt::Read for PeerConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Some(c) = self.connection_mut() else {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };

        if c.read().timedout() != 0 {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }

        let n = c.recv(unsafe { buf.as_mut() });

        if n == nginx_sys::NGX_ERROR as isize {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }

        let rev = c.read();

        if Status(unsafe { nginx_sys::ngx_handle_read_event(rev, 0) }) != Status::NGX_OK {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }

        if rev.active() != 0 {
            unsafe { nginx_sys::ngx_add_timer(rev, ACME_DEFAULT_READ_TIMEOUT) };
        } else if rev.timer_set() != 0 {
            unsafe { nginx_sys::ngx_del_timer(rev) };
        }

        if n == nginx_sys::NGX_AGAIN as isize {
            self.rev = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if n > 0 {
            unsafe { buf.advance(n as _) };
        }

        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for PeerConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let Some(c) = self.connection_mut() else {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };

        let n = c.send(buf);

        if n == nginx_sys::NGX_AGAIN as ngx_int_t {
            self.wev = Some(cx.waker().clone());
            Poll::Pending
        } else if n > 0 {
            Poll::Ready(Ok(n as usize))
        } else {
            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.poll_shutdown(cx)
    }
}

impl PeerConnection {
    pub fn new(log: NonNull<ngx_log_t>) -> Result<Self, io::Error> {
        let mut pool = OwnedPool::new(NGX_DEFAULT_POOL_SIZE as _, log)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;

        // We need a copy of the log object to avoid modifying log.connection on a cycle log.
        let new_log = ngx::allocator::allocate(unsafe { log.read() }, &*pool)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        (*pool).as_mut().log = new_log.as_ptr();

        let mut this = Self {
            pool,
            pc: unsafe { mem::zeroed() },
            rev: None,
            wev: None,
            server_name: None,
        };

        let pc = &mut this.pc;
        pc.get = Some(ngx_event_get_peer);
        pc.log = new_log.as_ptr();
        pc.set_log_error(ConnectionLogError::Info as _);

        Ok(this)
    }

    pub async fn connect_to(
        mut self: Pin<&mut Self>,
        authority: &str,
        res: &Resolver,
        ssl: Option<&ngx_ssl_t>,
    ) -> Result<(), io::Error> {
        let mut url: ngx_url_t = unsafe { mem::zeroed() };
        url.url = unsafe {
            let mut s = ngx_str_t::empty();
            s.len = authority.len();
            s.data = self.pool.alloc_unaligned(s.len + 1).cast();
            if s.data.is_null() {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            nginx_sys::ngx_cpystrn(s.data, authority.as_ptr().cast_mut(), s.len + 1);
            s
        };
        url.default_port = if ssl.is_some() { 443 } else { 80 };
        url.set_no_resolve(1);

        let addr_vec: Vec<ngx_addr_t>;

        if Status(unsafe { nginx_sys::ngx_parse_url(self.pool.as_mut(), &mut url) })
            != Status::NGX_OK
        {
            if url.err.is_null() {
                ngx_log_error!(NGX_LOG_ERR, self.pc.log, "bad uri: {authority}");
            } else {
                let err = unsafe { CStr::from_ptr(url.err) };
                ngx_log_error!(NGX_LOG_ERR, self.pc.log, "bad uri: {authority} ({err:?})",);
            }
            return Err(io::ErrorKind::InvalidInput.into());
        } else if url.naddrs > 0 {
            let addr = unsafe { &*url.addrs };
            self.pc.sockaddr = addr.sockaddr;
            self.pc.socklen = addr.socklen;
        } else {
            addr_vec = res
                .resolve(&url.host, self.pool.as_mut())
                .await
                .map_err(io::Error::other)?;

            self.pc.sockaddr = addr_vec[0].sockaddr;
            self.pc.socklen = addr_vec[0].socklen;

            unsafe { ngx_inet_set_port(self.pc.sockaddr, url.port) };
        }

        if url.url.len > url.host.len {
            // We already copied the authority as nul-terminated, but what we actually need is a
            // nul-terminated host string. Replace ':' with nul.
            url.url.as_bytes_mut()[url.host.len] = b'\0';
        }

        self.pc.name = ngx::allocator::allocate(url.host, &*self.pool)
            .map_err(|_| io::ErrorKind::OutOfMemory)?
            .as_ptr();

        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await?;

        if let Some(ssl) = ssl {
            if url.naddrs == 0 {
                self.server_name = NonNull::new(self.pc.name);
            }

            future::poll_fn(|cx| self.as_mut().poll_ssl_handshake(ssl, cx)).await?;
        }

        Ok(())
    }

    pub fn verify_peer(&mut self) -> Result<(), io::Error> {
        let c = self.connection_mut().ok_or(io::ErrorKind::NotConnected)?;

        let rc = unsafe { SSL_get_verify_result((*c.ssl).connection.cast()) };
        if rc != (X509_V_OK as c_long) {
            let err = unsafe { CStr::from_ptr(X509_verify_cert_error_string(rc)) };
            return Err(io::Error::other(std::format!(
                "upstream SSL certificate verify error: ({rc}:{err:?})"
            )));
        }

        if self.server_name.is_some_and(|mut n| {
            Status(unsafe { nginx_sys::ngx_ssl_check_host(self.pc.connection, n.as_mut()) })
                != Status::NGX_OK
        }) {
            return Err(io::Error::other(std::format!(
                "upstream SSL certificate does not match \"{}\"",
                unsafe { &*self.pc.name }
            )));
        }

        Ok(())
    }

    fn connect_peer(&mut self) -> Status {
        let rc = Status(unsafe { ngx_event_connect_peer(&mut self.pc) });

        if rc == Status::NGX_ERROR || rc == Status::NGX_BUSY || rc == Status::NGX_DECLINED {
            return rc;
        }

        let c = unsafe { &mut *self.pc.connection };
        c.data = ptr::from_mut(self).cast();

        if c.pool.is_null() {
            c.pool = ptr::from_mut(self.pool.as_mut());
        }

        unsafe {
            (*c.log).connection = c.number;
            (*c.read).handler = Some(ngx_peer_conn_read_handler);
            (*c.write).handler = Some(ngx_peer_conn_write_handler);
        }

        rc
    }

    pub fn poll_connect(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let Some(c) = self.connection_mut() {
            if c.read().timedout() != 0 || c.write().timedout() != 0 {
                c.close();
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }

            if let Err(err) = c.test_connect() {
                return Poll::Ready(Err(io::Error::from_raw_os_error(err)));
            }

            c.read().handler = Some(ngx_peer_conn_read_handler);
            c.write().handler = Some(ngx_peer_conn_write_handler);

            return Poll::Ready(Ok(()));
        }

        match self.connect_peer() {
            Status::NGX_OK => {
                let c = self.connection_mut().unwrap();
                ngx_log_debug!(c.log, "connected");
                Poll::Ready(Ok(()))
            }
            Status::NGX_AGAIN => {
                let c = self.connection_mut().unwrap();
                ngx_log_debug!(c.log, "connect returned NGX_AGAIN");

                c.read().handler = Some(ngx_peer_conn_read_handler);
                c.write().handler = Some(ngx_peer_conn_write_handler);

                unsafe { nginx_sys::ngx_add_timer(c.read(), ACME_DEFAULT_READ_TIMEOUT) };

                self.rev = Some(cx.waker().clone());
                self.wev = Some(cx.waker().clone());

                Poll::Pending
            }
            x => {
                ngx_log_debug!(self.pc.log, "connect returned {x:?}");
                Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()))
            }
        }
    }

    pub fn poll_ssl_handshake(
        mut self: Pin<&mut Self>,
        ssl: &ngx_ssl_t,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Some(c) = (unsafe {
            self.pc
                .connection
                .as_mut()
                .map(|x| Connection::from_ptr_mut(x))
        }) else {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };

        if c.ssl.is_null() {
            let flags = (nginx_sys::NGX_SSL_CLIENT | nginx_sys::NGX_SSL_BUFFER) as usize;
            // ngx_ssl_create_connection will increment a reference count on ssl.ctx: *mut SSL_CTX.
            // The pointer comes from foreign code and is considered mutable.
            let sslp = ptr::from_ref(ssl).cast_mut();
            if Status(unsafe { nginx_sys::ngx_ssl_create_connection(sslp, c.as_mut(), flags) })
                != Status::NGX_OK
            {
                return Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()));
            }

            if self.server_name.is_some_and(|server_name| unsafe {
                openssl_sys::SSL_set_tlsext_host_name(
                    (*c.ssl).connection.cast(),
                    server_name.as_ref().data.cast(),
                ) == 0
            }) {
                let err = openssl::error::ErrorStack::get();
                return Poll::Ready(Err(io::Error::other(err)));
            }

            unsafe { nginx_sys::ngx_reusable_connection(c.as_mut(), 0) };
        }

        match Status(unsafe { nginx_sys::ngx_ssl_handshake(c.as_mut()) } as _) {
            Status::NGX_OK => {
                ngx_log_debug!(c.log, "ssl_handshake succeeded");
                c.read().handler = Some(ngx_peer_conn_read_handler);
                c.write().handler = Some(ngx_peer_conn_write_handler);
                Poll::Ready(Ok(()))
            }
            Status::NGX_AGAIN => {
                ngx_log_debug!(c.log, "ssl_handshake returned NGX_AGAIN");
                unsafe { (*c.ssl).handler = Some(ngx_peer_conn_ssl_handler) };
                self.rev = Some(cx.waker().clone());
                Poll::Pending
            }
            x => {
                ngx_log_debug!(c.log, "ssl_handshake returned {x:?}");
                Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()))
            }
        }
    }

    pub fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Some(c) = self.connection_mut() else {
            return Poll::Ready(Ok(()));
        };

        if !c.ssl.is_null() {
            let rc = Status(unsafe { ngx_ssl_shutdown(c.as_mut()) });
            ngx_log_debug!(c.log, "ssl shutdown returned {rc:?}");
            if rc == Status::NGX_AGAIN {
                unsafe { (*c.ssl).handler = Some(ngx_peer_conn_ssl_shutdown_handler) };
                self.rev = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }

        let pool = c.pool;
        c.close();
        self.pc.connection = ptr::null_mut();

        if !ptr::eq::<ngx_pool_t>(self.pool.as_ref(), pool) {
            unsafe { ngx_destroy_pool(pool) };
        }

        Poll::Ready(Ok(()))
    }

    pub fn connection_mut(&mut self) -> Option<&mut Connection> {
        if self.pc.connection.is_null() {
            None
        } else {
            Some(unsafe { Connection::from_ptr_mut(self.pc.connection) })
        }
    }

    fn close(&mut self) {
        let Some(c) = self.connection_mut() else {
            return;
        };

        if !c.ssl.is_null() {
            ngx_log_debug!(c.log, "SSL connection was not shut down");
            unsafe {
                (*c.ssl).set_no_wait_shutdown(1);
                let _ = ngx_ssl_shutdown(c.as_mut());
            };
        }

        let pool = c.pool;
        c.close();
        self.pc.connection = ptr::null_mut();

        if !ptr::eq::<ngx_pool_t>(self.pool.as_ref(), pool) {
            unsafe { ngx_destroy_pool(pool) };
        }
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        self.close();
    }
}

unsafe extern "C" fn ngx_peer_conn_ssl_handler(c: *mut ngx_connection_t) {
    let this: *mut PeerConnection = (*c).data.cast();
    // This callback is invoked when both event handlers are set to ngx_event_openssl functions.
    // Using any of the wakers would result in polling the correct future.
    if let Some(waker) = (*this).rev.take() {
        waker.wake();
    }
}

unsafe extern "C" fn ngx_peer_conn_ssl_shutdown_handler(c: *mut ngx_connection_t) {
    let this: *mut PeerConnection = (*c).data.cast();
    // c.ssl is gone and it's no longer safe to use the ssl module event handlers
    (*(*c).read).handler = Some(ngx_peer_conn_read_handler);
    (*(*c).write).handler = Some(ngx_peer_conn_write_handler);

    if let Some(waker) = (*this).rev.take() {
        waker.wake();
    }
}

unsafe extern "C" fn ngx_peer_conn_read_handler(ev: *mut nginx_sys::ngx_event_t) {
    let c: *mut ngx_connection_t = (*ev).data.cast();
    let this: *mut PeerConnection = (*c).data.cast();

    if let Some(waker) = (*this).rev.take() {
        waker.wake();
    }
}

unsafe extern "C" fn ngx_peer_conn_write_handler(ev: *mut nginx_sys::ngx_event_t) {
    let c: *mut ngx_connection_t = (*ev).data.cast();
    let this: *mut PeerConnection = (*c).data.cast();

    if let Some(waker) = (*this).wev.take() {
        waker.wake();

    // Handle write events posted from the ngx_event_openssl code.
    } else if Status(nginx_sys::ngx_handle_write_event(ev, 0)) != Status::NGX_OK {
        ngx_log_error!(
            NGX_LOG_WARN,
            (*c).log,
            "acme: ngx_handle_write_event() failed"
        );
    }
}
