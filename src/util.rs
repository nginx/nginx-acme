// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::io::{self, Read};

use nginx_sys::{ngx_conf_full_name, ngx_conf_t, ngx_log_t, ngx_pool_t, ngx_str_t, ngx_uint_t};
use ngx::allocator::AllocError;
use ngx::core::{Pool, Status};

use crate::conf::ext::NgxConfExt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NgxProcess {
    Single,
    Master,
    Signaller,
    Worker(ngx_uint_t),
    Helper,
}

pub fn ngx_process() -> NgxProcess {
    let process = unsafe { nginx_sys::ngx_process } as u32;
    match process {
        nginx_sys::NGX_PROCESS_SINGLE => NgxProcess::Single,
        nginx_sys::NGX_PROCESS_MASTER => NgxProcess::Master,
        nginx_sys::NGX_PROCESS_SIGNALLER => NgxProcess::Signaller,
        nginx_sys::NGX_PROCESS_WORKER => NgxProcess::Worker(unsafe { nginx_sys::ngx_worker }),
        #[cfg(not(windows))]
        nginx_sys::NGX_PROCESS_HELPER => NgxProcess::Helper,
        _ => unreachable!("unknown process type {}", process),
    }
}

pub fn read_to_ngx_str(cf: &ngx_conf_t, path: &ngx_str_t) -> Result<ngx_str_t, io::Error> {
    let mut path = *path;
    if !Status(unsafe { ngx_conf_full_name(cf.cycle, &mut path, 1) }).is_ok() {
        return Err(io::ErrorKind::OutOfMemory.into());
    };

    let path = path.to_str().map_err(io::Error::other)?;
    let mut file = std::fs::File::open(path)?;

    let buf = match file.metadata().map(|x| x.len() as usize) {
        Ok(len) => {
            let mut buf = ngx_str_t {
                data: cf.pool().alloc_unaligned(len).cast(),
                len,
            };
            if buf.data.is_null() {
                return Err(io::ErrorKind::OutOfMemory.into());
            }

            file.read_exact(buf.as_bytes_mut())?;
            buf
        }
        _ => {
            let mut buf = std::vec::Vec::new();
            file.read_to_end(&mut buf)?;

            unsafe { ngx_str_t::from_bytes(cf.pool, &buf) }.ok_or(io::ErrorKind::OutOfMemory)?
        }
    };

    Ok(buf)
}

pub fn ngx_str_trim(val: &mut ngx_str_t) {
    let b = val.as_bytes();
    let start = b.iter().take_while(|x| x.is_ascii_whitespace()).count();
    let end = b
        .iter()
        .rev()
        .take_while(|x| x.is_ascii_whitespace())
        .count();

    val.len -= start + end;
    val.data = unsafe { val.data.add(start) };
}

pub struct OwnedPool(Pool);
impl OwnedPool {
    pub fn new(size: usize, log: NonNull<ngx_log_t>) -> Result<Self, AllocError> {
        let pool = unsafe { nginx_sys::ngx_create_pool(size, log.as_ptr()) };
        if pool.is_null() {
            return Err(AllocError);
        }
        Ok(Self(unsafe { Pool::from_ngx_pool(pool) }))
    }
}

impl AsRef<ngx_pool_t> for OwnedPool {
    fn as_ref(&self) -> &ngx_pool_t {
        self.0.as_ref()
    }
}

impl AsMut<ngx_pool_t> for OwnedPool {
    fn as_mut(&mut self) -> &mut ngx_pool_t {
        self.0.as_mut()
    }
}

impl AsRef<Pool> for OwnedPool {
    fn as_ref(&self) -> &Pool {
        &self.0
    }
}

impl AsMut<Pool> for OwnedPool {
    fn as_mut(&mut self) -> &mut Pool {
        &mut self.0
    }
}

impl Deref for OwnedPool {
    type Target = Pool;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for OwnedPool {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl Drop for OwnedPool {
    fn drop(&mut self) {
        unsafe { nginx_sys::ngx_destroy_pool(self.0.as_mut()) };
    }
}
