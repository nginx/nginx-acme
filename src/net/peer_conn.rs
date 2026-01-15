// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_int, CStr};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::task::{self, Poll};
use core::{fmt, future, mem};
use std::io;

use nginx_sys::{
    ngx_addr_t, ngx_connection_t, ngx_destroy_pool, ngx_event_connect_peer, ngx_event_get_peer,
    ngx_inet_set_port, ngx_int_t, ngx_log_t, ngx_msec_t, ngx_peer_connection_t, ngx_pool_t,
    ngx_ssl_shutdown, ngx_ssl_t, ngx_url_t, NGX_DEFAULT_POOL_SIZE, NGX_LOG_ERR, NGX_LOG_WARN,
};
use ngx::async_::resolver::Resolver;
use ngx::collections::Vec;
use ngx::core::{Pool, Status};
use ngx::{ngx_log_debug, ngx_log_error};
use openssl_sys::{
    SSL_get_verify_mode, SSL_get_verify_result, X509_VERIFY_PARAM_set1_host,
    X509_VERIFY_PARAM_set1_ip,
};

use super::connection::{Connection, ConnectionLogError};
use crate::util::{copy_bytes_with_nul, OwnedPool};

const ACME_DEFAULT_READ_TIMEOUT: ngx_msec_t = 60000;

#[derive(Debug)]
pub struct SslVerifyError(c_int);

impl core::error::Error for SslVerifyError {}

impl fmt::Display for SslVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = unsafe {
            // SAFETY: If an unrecognized error code is passed, the function may return a pointer
            // to an internal static buffer. It's safe to access it from a single-threaded nginx
            // module and that should never happen anyways.
            let s = openssl_sys::X509_verify_cert_error_string(self.0 as _);
            // SAFETY: all returned error messages are valid pointers to nul-terminated ASCII strings.
            CStr::from_ptr(s).to_str().unwrap_or("<unknown>")
        };

        f.write_fmt(core::format_args!(
            "upstream SSL certificate verify error: ({}:{})",
            self.0,
            desc
        ))
    }
}

/// Async wrapper over an [ngx_peer_connection_t].
pub struct PeerConnection {
    pub pool: OwnedPool,
    pub pc: ngx_peer_connection_t,
    pub rev: Option<task::Waker>,
    pub wev: Option<task::Waker>,
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
        let new_log = {
            let mut new_log = unsafe { log.read() };
            new_log.action = ptr::null_mut();
            new_log.data = ptr::null_mut(); // no final address
            new_log.handler = Some(Self::log_handler);
            ngx::allocator::allocate(new_log, &*pool).map_err(|_| io::ErrorKind::OutOfMemory)?
        };

        (*pool).as_mut().log = new_log.as_ptr();

        let mut this = Self {
            pool,
            pc: unsafe { mem::zeroed() },
            rev: None,
            wev: None,
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
        url.url = unsafe { copy_bytes_with_nul(&self.pool, authority) }
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        url.default_port = if ssl.is_some() { 443 } else { 80 };
        url.set_no_resolve(1);

        let addr_vec: Vec<ngx_addr_t, Pool>;

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
                .resolve_name(&url.host, self.pool.as_mut())
                .await
                .map_err(io::Error::other)?;

            self.pc.sockaddr = addr_vec[0].sockaddr;
            self.pc.socklen = addr_vec[0].socklen;

            unsafe { ngx_inet_set_port(self.pc.sockaddr, url.port) };
        }

        self.pc.name = ngx::allocator::allocate(url.url, &*self.pool)
            .map_err(|_| io::ErrorKind::OutOfMemory)?
            .as_ptr();

        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await?;

        if let Some(ssl) = ssl {
            let ssl_name = if url.naddrs == 0 {
                let n = unsafe { copy_bytes_with_nul(&self.pool, url.host) }
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
                Some(unsafe { CStr::from_ptr(n.data.cast()) })
            } else {
                None
            };

            future::poll_fn(|cx| self.as_mut().poll_ssl_handshake(ssl, ssl_name, cx)).await?;
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
            let rv = if c.read().timedout() != 0 || c.write().timedout() != 0 {
                c.close();
                Err(io::ErrorKind::TimedOut.into())
            } else if let Err(err) = c.test_connect() {
                Err(io::Error::from_raw_os_error(err))
            } else {
                c.read().handler = Some(ngx_peer_conn_read_handler);
                c.write().handler = Some(ngx_peer_conn_write_handler);
                Ok(())
            };

            self.unset_log_action();
            return Poll::Ready(rv);
        }

        self.set_log_action(c"connecting");

        match self.connect_peer() {
            Status::NGX_OK => {
                let c = self.connection_mut().unwrap();
                ngx_log_debug!(c.log, "connected");
                self.unset_log_action();
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
        ssl_name: Option<&CStr>, // *domain name* of the peer
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let c = unsafe { self.pc.connection.as_mut() }
            .expect("SSL handshake started on established connection");
        let c = unsafe { Connection::from_ptr_mut(c) };

        if c.ssl.is_null() {
            self.set_log_action(c"SSL handshaking");
            self.ssl_create_connection(ssl, ssl_name)?;
            unsafe { nginx_sys::ngx_reusable_connection(c.as_mut(), 0) };
        }

        match Status(unsafe { nginx_sys::ngx_ssl_handshake(c.as_mut()) } as _) {
            Status::NGX_OK => {
                let ssl = unsafe { (*c.ssl).connection.cast() };

                // ngx_ssl_verify_callback always allows the handshake to finish,
                // so we have to additionally check the verify result.

                if unsafe { SSL_get_verify_mode(ssl) } != openssl_sys::SSL_VERIFY_NONE {
                    let rc = unsafe { SSL_get_verify_result(ssl) } as c_int;
                    if rc != openssl_sys::X509_V_OK {
                        self.close();
                        return Err(io::Error::other(SslVerifyError(rc))).into();
                    }
                }

                ngx_log_debug!(c.log, "ssl_handshake succeeded");
                c.read().handler = Some(ngx_peer_conn_read_handler);
                c.write().handler = Some(ngx_peer_conn_write_handler);
                self.unset_log_action();
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

    fn ssl_create_connection(
        &mut self,
        ssl: &ngx_ssl_t,
        ssl_name: Option<&CStr>,
    ) -> Result<(), io::Error> {
        const FLAGS: usize = (nginx_sys::NGX_SSL_CLIENT | nginx_sys::NGX_SSL_BUFFER) as _;

        let c = unsafe { self.pc.connection.as_mut() }
            .expect("SSL handshake started on established connection");

        // ngx_ssl_create_connection will increment a reference count on ssl.ctx: *mut SSL_CTX.
        // The pointer comes from foreign code and is considered mutable.
        let sslp = ptr::from_ref(ssl).cast_mut();
        if Status(unsafe { nginx_sys::ngx_ssl_create_connection(sslp, c, FLAGS) }) != Status::NGX_OK
        {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }

        let ssl_conn = unsafe { (*c.ssl).connection.cast() };

        if let Some(name) = ssl_name {
            if unsafe { openssl_sys::SSL_set_tlsext_host_name(ssl_conn, name.as_ptr().cast_mut()) }
                != 1
            {
                return Err(openssl::error::ErrorStack::get().into());
            }
        }

        if unsafe { SSL_get_verify_mode(ssl_conn) } != openssl_sys::SSL_VERIFY_NONE {
            let vp = unsafe { openssl_sys::SSL_get0_param(ssl_conn) };
            let mut addr_buf = [0u8; 16];

            if let Some(name) = ssl_name {
                if unsafe { X509_VERIFY_PARAM_set1_host(vp, name.as_ptr(), name.count_bytes()) }
                    != 1
                {
                    return Err(openssl::error::ErrorStack::get().into());
                }
            } else if let Some(ip) = unsafe {
                self.pc
                    .sockaddr
                    .cast::<libc::sockaddr>()
                    .as_ref()
                    .and_then(|x| sockaddr_to_in_addr_buf(x, &mut addr_buf))
            } {
                if unsafe { X509_VERIFY_PARAM_set1_ip(vp, ip.as_ptr(), ip.len()) } != 1 {
                    return Err(openssl::error::ErrorStack::get().into());
                }
            }
        }

        Ok(())
    }

    pub fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.set_log_action(c"closing connection");

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

    fn set_log_action(self: &Pin<&mut Self>, action: &'static CStr) {
        if let Some(log) = unsafe { self.pc.log.as_mut() } {
            log.data = ptr::from_ref(&self.pc).cast_mut().cast();
            log.action = action.as_ptr().cast_mut().cast();
        }
    }

    fn unset_log_action(&self) {
        if let Some(log) = unsafe { self.pc.log.as_mut() } {
            log.action = ptr::null_mut();
        }
    }

    unsafe extern "C" fn log_handler(
        log: *mut ngx_log_t,
        mut buf: *mut u8,
        mut len: usize,
    ) -> *mut u8 {
        unsafe {
            // SAFETY: log is never empty when calling log->handler
            let log = &mut *log;
            // SAFETY: log is an unique object owned by self, and log.data is either NULL or
            // initialized with a stable pointer to self.pc.
            let Some(pc) = log.data.cast::<ngx_peer_connection_t>().as_ref() else {
                return buf;
            };

            if !log.action.is_null() {
                let p = nginx_sys::ngx_snprintf(buf, len, c" while %s".as_ptr(), log.action);
                len -= p.offset_from(buf) as usize;
                buf = p;
            }

            if !pc.name.is_null() {
                let p = nginx_sys::ngx_snprintf(buf, len, c", server: %V".as_ptr(), pc.name);
                len -= p.offset_from(buf) as usize;
                buf = p;
            }

            if pc.socklen != 0 {
                let p = nginx_sys::ngx_snprintf(buf, len, c", addr: ".as_ptr());
                len -= p.offset_from(buf) as usize;

                let n = nginx_sys::ngx_sock_ntop(pc.sockaddr, pc.socklen, p, len, 1);
                buf = p.byte_add(n);
            }

            buf
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

// Gets a binary representation of an IP address from a well-formed [libc::sockaddr].
//
// The representation should match one required for [X509_VERIFY_PARAM_set1_ip].
fn sockaddr_to_in_addr_buf<'a>(sa: &libc::sockaddr, out: &'a mut [u8; 16]) -> Option<&'a [u8]> {
    match sa.sa_family as c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe { NonNull::from(sa).cast().as_ref() };
            // s_addr is stored in network byte order
            out[..4].copy_from_slice(&sin.sin_addr.s_addr.to_ne_bytes());
            Some(&out[..4])
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 = unsafe { NonNull::from(sa).cast().as_ref() };
            out.copy_from_slice(&sin6.sin6_addr.s6_addr);
            Some(out)
        }
        _ => None,
    }
}
