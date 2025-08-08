// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Extension traits for nginx-sys types.
use core::ffi::c_char;
use core::{error::Error as StdError, ptr};

use nginx_sys::{ngx_conf_t, ngx_str_t};
use ngx::core::NGX_CONF_ERROR;
use ngx::ngx_conf_log_error;

pub trait NgxConfExt {
    fn args(&self) -> &[ngx_str_t];
    fn error(&self, dir: impl AsRef<[u8]>, err: &dyn StdError) -> *mut c_char;
    fn pool(&self) -> ngx::core::Pool;
}

impl NgxConfExt for ngx_conf_t {
    fn args(&self) -> &[ngx_str_t] {
        // SAFETY: we know that cf.args is an array of ngx_str_t
        unsafe { self.args.as_ref().map(|x| x.as_slice()).unwrap_or_default() }
    }

    fn error(&self, dir: impl AsRef<[u8]>, err: &dyn StdError) -> *mut c_char {
        // ngx_conf_log_error does not modify the `cf` itself, and the log is mutable due to being a
        // pointer.
        let cfp = ptr::from_ref(self).cast_mut();
        let dir = ngx::core::NgxStr::from_bytes(dir.as_ref());
        ngx_conf_log_error!(nginx_sys::NGX_LOG_EMERG, cfp, "{}: {}", dir, err);
        NGX_CONF_ERROR
    }

    fn pool(&self) -> ngx::core::Pool {
        // SAFETY: `cf` always has a valid pool
        unsafe { ngx::core::Pool::from_ngx_pool(self.pool) }
    }
}
