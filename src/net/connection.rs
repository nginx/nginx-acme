// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_int, CStr};
use core::mem::{self, MaybeUninit};
use core::{ops, ptr};

use nginx_sys::{
    ngx_close_connection, ngx_connection_t, ngx_err_t, ngx_event_t, ngx_int_t, ngx_socket_errno,
};

#[allow(dead_code)]
#[repr(u32)] // ngx_connection_log_error_e == c_uint == u32 on all supported platforms
pub enum ConnectionLogError {
    Alert = nginx_sys::ngx_connection_log_error_e_NGX_ERROR_ALERT,
    Err = nginx_sys::ngx_connection_log_error_e_NGX_ERROR_ERR,
    Info = nginx_sys::ngx_connection_log_error_e_NGX_ERROR_INFO,
    IgnoreConnectionReset = nginx_sys::ngx_connection_log_error_e_NGX_ERROR_IGNORE_ECONNRESET,
    IgnoreInvalidArgument = nginx_sys::ngx_connection_log_error_e_NGX_ERROR_IGNORE_EINVAL,
}

/// Wrapper struct for an [`ngx_connection_t`].
///
/// [`ngx_connection_t`]: http://nginx.org/en/docs/dev/development_guide.html#connection
#[repr(transparent)]
pub struct Connection(ngx_connection_t);

impl AsRef<ngx_connection_t> for Connection {
    #[inline]
    fn as_ref(&self) -> &ngx_connection_t {
        &self.0
    }
}

impl AsMut<ngx_connection_t> for Connection {
    #[inline]
    fn as_mut(&mut self) -> &mut ngx_connection_t {
        &mut self.0
    }
}

impl ops::Deref for Connection {
    type Target = ngx_connection_t;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl ops::DerefMut for Connection {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl Connection {
    /// Creates a new connection wrapper.
    pub unsafe fn from_ptr_mut<'a>(c: *mut ngx_connection_t) -> &'a mut Self {
        unsafe { &mut *c.cast::<Self>() }
    }

    /// Returns a read event reference
    pub fn read(&mut self) -> &mut ngx_event_t {
        debug_assert!(!self.0.read.is_null());
        unsafe { &mut *self.0.read }
    }

    /// Returns a write event reference
    pub fn write(&mut self) -> &mut ngx_event_t {
        debug_assert!(!self.0.write.is_null());
        unsafe { &mut *self.0.write }
    }

    /// Check `connect` result
    pub fn test_connect(&mut self) -> Result<(), ngx_err_t> {
        #[cfg(ngx_feature = "have_kqueue")]
        if unsafe { nginx_sys::ngx_event_flags } & (nginx_sys::NGX_USE_KQUEUE_EVENT as usize) != 0 {
            if self.write().pending_eof() != 0 || self.read().pending_eof() != 0 {
                let err = if self.write().pending_eof() != 0 {
                    self.write().kq_errno
                } else {
                    self.read().kq_errno
                };

                self.error(err, c"kevent() reported that connect() failed");
                return Err(err);
            } else {
                return Ok(());
            }
        }

        let mut err: c_int = 0;
        let mut len: libc::socklen_t = mem::size_of_val(&err) as _;

        // BSDs and Linux return 0 and set a pending error in err
        // Solaris returns -1 and sets errno
        if unsafe {
            libc::getsockopt(
                self.0.fd,
                libc::SOL_SOCKET as _,
                libc::SO_ERROR as _,
                ptr::addr_of_mut!(err).cast(),
                &mut len,
            ) == -1
        } {
            err = ngx_socket_errno() as _;
        }

        if err != 0 {
            self.error(err, c"connect() failed");
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Handle connection errors.
    pub fn error(&mut self, err: ngx_err_t, msg: &CStr) -> ngx_int_t {
        unsafe { nginx_sys::ngx_connection_error(self.as_mut(), err, msg.as_ptr().cast_mut()) }
    }

    /// Receive data from the connection.
    pub fn recv(&mut self, buf: &mut [MaybeUninit<u8>]) -> isize {
        // SAFETY: send and recv are always set on a valid connection.
        unsafe {
            self.as_ref().recv.unwrap_unchecked()(self.as_mut(), buf.as_mut_ptr().cast(), buf.len())
        }
    }

    /// Send data to the connection.
    pub fn send(&mut self, buf: &[u8]) -> isize {
        // SAFETY: send and recv are always set on a valid connection.
        unsafe {
            self.as_ref().send.unwrap_unchecked()(self.as_mut(), buf.as_ptr().cast_mut(), buf.len())
        }
    }

    /// Close the connection.
    pub fn close(&mut self) {
        unsafe { ngx_close_connection(self.as_mut()) }
    }
}
