// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ptr;

use nginx_sys::{
    ngx_array_push, ngx_buf_t, ngx_chain_t, ngx_conf_t, ngx_http_discard_request_body,
    ngx_http_finalize_request, ngx_http_handler_pt, ngx_http_output_filter,
    ngx_http_phases_NGX_HTTP_POST_READ_PHASE, ngx_http_request_t,
};
use ngx::allocator::TryCloneIn;
use ngx::collections::RbTreeMap;
use ngx::core::{NgxStr, NgxString, SlabPool, Status};
use ngx::http::HttpModuleMainConf;
use ngx::sync::RwLock;
use ngx::{http_request_handler, ngx_log_debug_http};

use super::{ChallengeSolver, SolverError};
use crate::acme;
use crate::conf::identifier::Identifier;
use crate::conf::AcmeMainConfig;

/// Registers http-01 challenge handler.
pub fn postconfiguration(cf: &mut ngx_conf_t, _amcf: &mut AcmeMainConfig) -> Result<(), Status> {
    let cmcf = ngx::http::NgxHttpCoreModule::main_conf_mut(cf).expect("http core main conf");

    // The handler needs to be set as early as possible, to ensure that it is not affected by the
    // server configuration.
    let h: *mut ngx_http_handler_pt = unsafe {
        ngx_array_push(&mut cmcf.phases[ngx_http_phases_NGX_HTTP_POST_READ_PHASE as usize].handlers)
    }
    .cast();

    if h.is_null() {
        return Err(Status::NGX_ERROR);
    }

    unsafe { *h = Some(handler) };

    Ok(())
}

pub type Http01SolverState<A> = RbTreeMap<NgxString<A>, NgxString<A>, A>;

#[derive(Debug)]
pub struct Http01Solver<'a>(&'a RwLock<Http01SolverState<SlabPool>>);

impl<'a> Http01Solver<'a> {
    pub fn new(inner: &'a RwLock<Http01SolverState<SlabPool>>) -> Self {
        Self(inner)
    }
}

impl ChallengeSolver for Http01Solver<'_> {
    fn supports(&self, c: &acme::types::ChallengeKind) -> bool {
        matches!(c, crate::acme::types::ChallengeKind::Http01)
    }

    fn register(
        &self,
        ctx: &acme::AuthorizationContext,
        _identifier: &Identifier<&str>,
        challenge: &acme::types::Challenge,
    ) -> Result<(), SolverError> {
        let alloc = self.0.read().allocator().clone();

        let mut key_authorization = NgxString::new_in(alloc.clone());
        key_authorization.try_reserve_exact(challenge.token.len() + ctx.thumbprint.len() + 1)?;
        // write to a preallocated buffer of a sufficient size should succeed
        let _ = key_authorization.append_within_capacity(challenge.token.as_bytes());
        let _ = key_authorization.append_within_capacity(b".");
        let _ = key_authorization.append_within_capacity(ctx.thumbprint);
        let token = NgxString::try_from_bytes_in(&challenge.token, alloc)?;
        self.0.write().try_insert(token, key_authorization)?;
        Ok(())
    }

    fn unregister(
        &self,
        _identifier: &Identifier<&str>,
        challenge: &acme::types::Challenge,
    ) -> Result<(), SolverError> {
        self.0.write().remove(challenge.token.as_bytes());
        Ok(())
    }
}

http_request_handler!(handler, |r: &mut ngx::http::Request| {
    if r.method() != ngx::http::Method::GET {
        return Status::NGX_DECLINED;
    }

    let amcf = crate::HttpAcmeModule::main_conf(r).expect("acme config");
    let Some(amsh) = amcf.data else {
        return Status::NGX_DECLINED;
    };

    let Some(token) = r
        .path()
        .as_bytes()
        .strip_prefix(b"/.well-known/acme-challenge/")
    else {
        return Status::NGX_DECLINED;
    };

    let token = NgxStr::from_bytes(token);

    let key_auth = if let Some(resp) = amsh.http_01_state.read().get(token) {
        resp.try_clone_in(r.pool())
    } else {
        ngx_log_debug_http!(r, "acme/http-01: no challenge registered for {token}");
        return Status::NGX_DECLINED;
    };

    let Ok(key_auth) = key_auth else {
        return Status::NGX_ERROR;
    };

    ngx_log_debug_http!(r, "acme/http-01: challenge for {token}");

    let rc = Status(unsafe { ngx_http_discard_request_body(r.as_mut()) });
    if rc != Status::NGX_OK {
        return rc;
    }

    r.set_status(ngx::http::HTTPStatus::OK);

    r.set_content_length_n(key_auth.len());
    if r.add_header_out("connection", "close").is_none()
        || r.add_header_out("content-type", "text/plain").is_none()
    {
        return Status::NGX_ERROR;
    }

    let rc = r.send_header();
    if rc == Status::NGX_ERROR || rc > Status::NGX_OK {
        return rc;
    }

    let buf: *mut ngx_buf_t = r.pool().calloc_type();
    if buf.is_null() {
        return Status::NGX_ERROR;
    }

    let (p, len, _, _) = key_auth.into_raw_parts();

    unsafe {
        (*buf).set_memory(1);
        (*buf).set_last_buf(if r.is_main() { 1 } else { 0 });
        (*buf).set_last_in_chain(1);
        (*buf).start = p;
        (*buf).end = p.add(len);
        (*buf).pos = (*buf).start;
        (*buf).last = (*buf).end;
    }

    let mut chain = ngx_chain_t {
        buf,
        next: ptr::null_mut(),
    };

    let r: *mut ngx_http_request_t = r.into();
    unsafe { ngx_http_finalize_request(r, ngx_http_output_filter(r, &mut chain)) }

    Status::NGX_DONE
});
