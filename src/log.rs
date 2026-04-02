// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use nginx_sys::ngx_log_t;

pub trait AsLogPtr {
    fn as_log_ptr(&self) -> *mut ngx_log_t;
}

impl<T: AsLogPtr> AsLogPtr for &T {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        T::as_log_ptr(self)
    }
}

impl<T: AsLogPtr> AsLogPtr for &mut T {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        T::as_log_ptr(self)
    }
}

impl AsLogPtr for *mut ngx_log_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        *self
    }
}

impl AsLogPtr for core::ptr::NonNull<ngx_log_t> {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.as_ptr()
    }
}

impl AsLogPtr for nginx_sys::ngx_conf_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.log
    }
}

impl AsLogPtr for nginx_sys::ngx_connection_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.log
    }
}

#[inline(always)]
pub fn as_log_ptr(x: impl AsLogPtr) -> *mut ngx_log_t {
    x.as_log_ptr()
}

macro_rules! emerg {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx_log_error!(nginx_sys::NGX_LOG_EMERG, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

macro_rules! error {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx_log_error!(nginx_sys::NGX_LOG_ERR, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

macro_rules! warn {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx_log_error!(nginx_sys::NGX_LOG_WARN, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

macro_rules! notice {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx_log_error!(nginx_sys::NGX_LOG_NOTICE, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

macro_rules! info {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx_log_error!(nginx_sys::NGX_LOG_INFO, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

macro_rules! debug {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_debug!($crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

// FIXME: remove with the next release of ngx-rust
macro_rules! ngx_log_error {
    ( $level:expr, $log:expr, $($arg:tt)+ ) => {
        let log = $log;
        let level = $level as ngx::ffi::ngx_uint_t;
        if level <= unsafe { (*log).log_level } {
            let mut buf =
                [const { ::core::mem::MaybeUninit::<u8>::uninit() }; ngx::log::LOG_BUFFER_SIZE];
            let message = ngx::log::write_fmt(&mut buf, format_args!($($arg)+));
            unsafe { ngx::log::log_error(level, log, 0, message) };
        }
    }
}

// FIXME: remove with the next release of ngx-rust
macro_rules! ngx_conf_log_error {
    ( $level:expr, $cf:expr, $($arg:tt)+ ) => {
        let cf: *mut nginx_sys::ngx_conf_t = $cf;
        let level = $level as nginx_sys::ngx_uint_t;
        if level <= unsafe { (*(*cf).log).log_level } {
            let mut buf =
                [const { ::core::mem::MaybeUninit::<u8>::uninit() }; ngx::log::LOG_BUFFER_SIZE];
            let message = ngx::log::write_fmt(&mut buf, format_args!($($arg)+));
            unsafe {
                nginx_sys::ngx_conf_log_error(
                    level,
                    cf,
                    0,
                    c"%*s".as_ptr(),
                    message.len(),
                    message.as_ptr()
                );
            }
        }
    }
}

#[cfg(feature = "trace")]
macro_rules! trace {
    ($($arg:tt)+) => (debug!($($arg)+))
}

#[cfg(not(feature = "trace"))]
macro_rules! trace {
    ($($arg:tt)+) => {};
}
