// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_char, c_void, CStr};
use core::{mem, ptr};

use nginx_sys::{
    ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_decode_base64url, ngx_http_core_srv_conf_t,
    ngx_str_t, ngx_uint_t, NGX_CONF_1MORE, NGX_CONF_BLOCK, NGX_CONF_FLAG, NGX_CONF_NOARGS,
    NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,
    NGX_HTTP_SRV_CONF, NGX_HTTP_SRV_CONF_OFFSET, NGX_LOG_EMERG,
};
use ngx::collections::Vec;
use ngx::core::{Pool, Status, NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::{HttpModuleMainConf, HttpModuleServerConf};
use ngx::{ngx_conf_log_error, ngx_log_error, ngx_string};

use self::ext::NgxConfExt;
use self::issuer::Issuer;
use self::order::CertificateOrder;
use self::pkey::PrivateKey;
use self::shared_zone::{SharedZone, ACME_ZONE_NAME, ACME_ZONE_SIZE};
use self::ssl::NgxSsl;
use crate::acme::types::ChallengeKind;
use crate::state::AcmeSharedData;

pub mod ext;
pub mod identifier;
pub mod issuer;
pub mod order;
pub mod pkey;
pub mod shared_zone;
pub mod ssl;

const NGX_CONF_DUPLICATE: *mut c_char = c"is duplicate".as_ptr().cast_mut();
const NGX_CONF_INVALID_VALUE: *mut c_char = c"invalid value".as_ptr().cast_mut();

/// Main (http block) level configuration.
#[derive(Debug, Default)]
pub struct AcmeMainConfig {
    pub issuers: Vec<Issuer>,
    pub ssl: NgxSsl,
    pub data: Option<&'static AcmeSharedData>,
    pub shm_zone: shared_zone::SharedZone,
}

/// Server level configuration.
#[derive(Debug, Default)]
pub struct AcmeServerConfig {
    pub issuer: ngx_str_t,
    // Only one certificate order per server block is currently allowed. For multiple entries we
    // will have to implement certificate selection in the variable handler.
    pub order: Option<CertificateOrder<ngx_str_t, Pool>>,
}

pub static mut NGX_HTTP_ACME_COMMANDS: [ngx_command_t; 4] = [
    ngx_command_t {
        name: ngx_string!("acme_issuer"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1 | NGX_CONF_BLOCK) as ngx_uint_t,
        set: Some(cmd_add_issuer),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("acme_shared_zone"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(cmd_set_shared_zone),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("acme_certificate"),
        type_: (NGX_HTTP_SRV_CONF | NGX_CONF_1MORE) as ngx_uint_t,
        set: Some(cmd_add_certificate),
        conf: NGX_HTTP_SRV_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static mut NGX_HTTP_ACME_ISSUER_COMMANDS: [ngx_command_t; 10] = [
    ngx_command_t {
        name: ngx_string!("uri"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_issuer_set_uri),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("account_key"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_issuer_set_account_key),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("challenge"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_issuer_set_challenge),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("contact"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_issuer_add_contact),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("external_account_key"),
        type_: NGX_CONF_TAKE2 as ngx_uint_t,
        set: Some(cmd_issuer_set_external_account_key),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("ssl_trusted_certificate"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: 0,
        offset: mem::offset_of!(Issuer, ssl_trusted_certificate),
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("ssl_verify"),
        type_: NGX_CONF_FLAG as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_flag_slot),
        conf: 0,
        offset: mem::offset_of!(Issuer, ssl_verify),
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("state_path"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_path_slot),
        conf: 0,
        offset: mem::offset_of!(Issuer, state_path),
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("accept_terms_of_service"),
        type_: NGX_CONF_NOARGS as ngx_uint_t,
        set: Some(cmd_issuer_set_accept_tos),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

/* command handlers */

extern "C" fn cmd_add_issuer(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().expect("cf") };
    let amcf = unsafe { conf.cast::<AcmeMainConfig>().as_mut() }.expect("acme main config");
    let alloc = cf.pool();

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    if amcf.issuer(&args[1]).is_some() {
        return NGX_CONF_DUPLICATE;
    }

    let Ok(mut issuer) = Issuer::new_in(args[1], alloc) else {
        return NGX_CONF_ERROR;
    };
    let mut block_cf: ngx_conf_t = *cf;
    block_cf.handler = Some(cmd_add_issuer_block);
    block_cf.handler_conf = ptr::addr_of_mut!(issuer).cast();

    let rv = unsafe { ngx_conf_parse(&mut block_cf, ptr::null_mut()) };
    if rv != NGX_CONF_OK {
        return rv;
    }

    if let Err(err) = issuer.init(cf) {
        return cf.error("acme_issuer", &err);
    }

    amcf.issuers.push(issuer);

    NGX_CONF_OK
}

extern "C" fn cmd_add_issuer_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    let args = unsafe { (*cf).args() };

    for cmd in unsafe { &mut NGX_HTTP_ACME_ISSUER_COMMANDS[..] } {
        if args[0] != cmd.name {
            continue;
        }

        if !conf_check_nargs(cmd, args.len()) {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                cf,
                "invalid number of arguments in \"{}\"",
                args[0]
            );
            return NGX_CONF_ERROR;
        }

        let handler = cmd.set.expect("command handler");

        return match unsafe { handler(cf, cmd, (*cf).handler_conf) } {
            NGX_CONF_OK => NGX_CONF_OK,
            NGX_CONF_ERROR => NGX_CONF_ERROR,
            rv => {
                let cstr = unsafe { CStr::from_ptr(rv) };
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "\"{}\" directive {:?}", args[0], cstr);
                NGX_CONF_ERROR
            }
        };
    }

    ngx_conf_log_error!(NGX_LOG_EMERG, cf, "unknown directive \"{}\"", args[0]);
    NGX_CONF_ERROR
}

extern "C" fn cmd_set_shared_zone(
    cf: *mut ngx_conf_t,
    cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().unwrap() };
    let amcf = unsafe { conf.cast::<AcmeMainConfig>().as_mut().expect("main config") };

    if amcf.shm_zone.is_configured() {
        return NGX_CONF_DUPLICATE;
    }

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    if let Some(value) = args[1].strip_prefix("zone=") {
        let (name, size) = match SharedZone::parse_name_size(value) {
            Ok((name, size)) => (name, size),
            Err(err) => return cf.error(args[0], &err),
        };

        if let Err(err) = amcf.shm_zone.configure(name, size) {
            return cf.error(args[0], &err);
        }
    }

    if !amcf.shm_zone.is_configured() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            cf,
            "\"{}\" must have \"zone\" parameter",
            unsafe { (*cmd).name }
        );
        return NGX_CONF_ERROR;
    }

    NGX_CONF_OK
}

extern "C" fn cmd_add_certificate(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().unwrap() };
    let ascf = unsafe {
        conf.cast::<AcmeServerConfig>()
            .as_mut()
            .expect("server config")
    };

    if ascf.order.is_some() {
        return NGX_CONF_DUPLICATE;
    }

    let args = cf.args();

    ascf.issuer = args.get(1).copied().unwrap_or_default();
    if ascf.issuer.is_empty() {
        return c"\"issuer\" is missing".as_ptr().cast_mut();
    }

    let mut order = CertificateOrder::<ngx_str_t, Pool>::new_in(cf.pool());

    for value in &args[2..] {
        if let Some(key) = value.strip_prefix(b"key=") {
            order.key = match PrivateKey::try_from(key) {
                Ok(PrivateKey::File(_)) => return c"invalid \"key\" value".as_ptr().cast_mut(),
                Ok(val) => val,
                Err(err) => return cf.error(args[0], &err),
            };
            continue;
        }

        if let Err(err) = order.try_add_identifier(value) {
            return cf.error(args[0], &err);
        }
    }

    // If we haven't found any identifiers in the arguments, we will populate the list from the
    // `server_name` values later, when the server names list is fully initialized.

    ascf.order = Some(order);

    NGX_CONF_OK
}

extern "C" fn cmd_issuer_set_challenge(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().expect("cf") };
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    if issuer.challenge.is_some() {
        return NGX_CONF_DUPLICATE;
    }

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    let Ok(val) = core::str::from_utf8(args[1].as_bytes()) else {
        return NGX_CONF_ERROR;
    };
    let val = ChallengeKind::from(val);
    if !matches!(val, ChallengeKind::Http01 | ChallengeKind::TlsAlpn01) {
        ngx_conf_log_error!(NGX_LOG_EMERG, cf, "unsupported challenge type: {val:?}");
        return NGX_CONF_ERROR;
    };

    issuer.challenge = Some(val);

    NGX_CONF_OK
}

extern "C" fn cmd_issuer_add_contact(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    const MAILTO: &[u8] = b"mailto:";

    fn has_scheme(val: &[u8]) -> bool {
        // scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        if !val[0].is_ascii_alphabetic() {
            return false;
        }

        for c in val {
            if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.') {
                continue;
            }
            return *c == b':';
        }

        false
    }

    let cf = unsafe { cf.as_mut().expect("cf") };
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    if issuer.contacts.try_reserve(1).is_err() {
        return NGX_CONF_ERROR;
    }

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    if args[1].is_empty() {
        return NGX_CONF_INVALID_VALUE;
    };

    let value = if has_scheme(args[1].as_ref()) {
        args[1]
    } else {
        let mut value = ngx_str_t::empty();
        value.len = MAILTO.len() + args[1].len;
        value.data = cf.pool().alloc_unaligned(value.len).cast();
        if value.data.is_null() {
            return NGX_CONF_ERROR;
        }

        value.as_bytes_mut()[..MAILTO.len()].copy_from_slice(MAILTO);
        value.as_bytes_mut()[MAILTO.len()..].copy_from_slice(args[1].as_ref());
        value
    };

    // SAFETY: the value is not empty, well aligned, and the conversion result is assigned to an
    // object in the same pool.
    match unsafe { conf_value_to_str(&value) } {
        Ok(x) => {
            issuer.contacts.push(x);
            NGX_CONF_OK
        }
        Err(_) => NGX_CONF_INVALID_VALUE,
    }
}

extern "C" fn cmd_issuer_set_account_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().expect("cf") };
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    if issuer.account_key != PrivateKey::Unset {
        return NGX_CONF_DUPLICATE;
    }

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    issuer.account_key = match PrivateKey::try_from(args[1]) {
        Ok(x) => x,
        Err(err) => return cf.error(args[0], &err),
    };

    NGX_CONF_OK
}

extern "C" fn cmd_issuer_set_external_account_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().expect("cf") };
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    if issuer.eab_key.is_some() {
        return NGX_CONF_DUPLICATE;
    }

    let mut pool = cf.pool();
    // NGX_CONF_TAKE2 ensures that args contains 3 elements
    let args = cf.args();

    if args[1].is_empty() || args[2].is_empty() {
        return NGX_CONF_INVALID_VALUE;
    }

    // SAFETY: the value is not empty, well aligned, and the conversion result is assigned to an
    // object in the same pool.
    let Ok(kid) = (unsafe { conf_value_to_str(&args[1]) }) else {
        return NGX_CONF_INVALID_VALUE;
    };

    let mut encoded = if let Some(arg) = args[2].strip_prefix(b"data:") {
        arg
    } else {
        match crate::util::read_to_ngx_str(cf, &args[2]) {
            Ok(x) => x,
            Err(e) => return cf.error(args[0], &e),
        }
    };

    crate::util::ngx_str_trim(&mut encoded);

    let len = encoded.len.div_ceil(4) * 3;
    let mut key = ngx_str_t {
        data: pool.alloc_unaligned(len).cast(),
        len,
    };

    if key.data.is_null() {
        return NGX_CONF_ERROR;
    }

    if !Status(unsafe { ngx_decode_base64url(&mut key, &mut encoded) }).is_ok() {
        return c"invalid base64url encoded value".as_ptr().cast_mut();
    }

    issuer.eab_key = Some(issuer::ExternalAccountKey { kid, key });

    NGX_CONF_OK
}

extern "C" fn cmd_issuer_set_uri(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let cf = unsafe { cf.as_mut().expect("cf") };
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    // NGX_CONF_TAKE1 ensures that args contains 2 elements
    let args = cf.args();

    let Ok(val) = core::str::from_utf8(args[1].as_bytes()) else {
        return c"contains invalid UTF-8 sequence".as_ptr().cast_mut();
    };

    let Ok(val) = val.parse() else {
        return NGX_CONF_ERROR;
    };

    issuer.uri.clone_from(&val);

    NGX_CONF_OK
}

extern "C" fn cmd_issuer_set_accept_tos(
    _cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let issuer = unsafe { conf.cast::<Issuer>().as_mut().expect("issuer conf") };

    if issuer.accept_tos.is_some() {
        return NGX_CONF_DUPLICATE;
    }

    issuer.accept_tos = Some(true);

    NGX_CONF_OK
}

/* Methods and trait implementations */

impl AcmeMainConfig {
    /// Obtains the module configuration from the previous configuration cycle
    pub fn old_config<'a>(cf: &mut ngx_conf_t) -> Option<&'a AcmeMainConfig> {
        let old_cycle = unsafe { cf.cycle.as_ref()?.old_cycle.as_ref()? };

        if old_cycle.conf_ctx.is_null() {
            // Initial cycle
            return None;
        }

        super::HttpAcmeModule::main_conf(old_cycle)
    }

    /// Checks if any certificate issuers are configured
    pub fn is_configured(&self) -> bool {
        !self.issuers.is_empty()
    }

    /// Returns a reference to an issuer with the specified name, if present.
    pub fn issuer(&self, name: &ngx_str_t) -> Option<&Issuer> {
        self.issuers.iter().find(|x| &x.name == name)
    }

    /// Returns a mutable reference to an issuer with the specified name, if present.
    pub fn issuer_mut(&mut self, name: &ngx_str_t) -> Option<&mut Issuer> {
        self.issuers.iter_mut().find(|x| &x.name == name)
    }

    pub fn postconfiguration(&mut self, cf: &mut ngx_conf_t) -> Result<(), Status> {
        let cmcf = ngx::http::NgxHttpCoreModule::main_conf_mut(cf).expect("http core main conf");

        /*
         * Collect certificate orders from all the configured server blocks.
         * Even if there are no issuers configured, we must check that no orders refer to a
         * non-existent issuer.
         */

        let servers: &[&ngx_http_core_srv_conf_t] = unsafe { cmcf.servers.as_slice() };

        for cscfp in servers {
            let ascf = super::HttpAcmeModule::server_conf_mut(*cscfp).expect("acme server conf");
            let Some(ref mut order) = ascf.order else {
                continue;
            };

            // An empty list of identifers should be filled from the `server_name` directive values.
            // At this point, the server names list should be fully initialized.
            if order.identifiers.is_empty() {
                let server_names = unsafe { cscfp.server_names.as_slice() };

                if let Err(err) = order.add_server_names(cf, server_names) {
                    ngx_log_error!(NGX_LOG_EMERG, cf.log, "\"acme_certificate\": {err}");
                    return Err(Status::NGX_ERROR);
                }

                if order.identifiers.is_empty() {
                    ngx_log_error!(
                        NGX_LOG_EMERG,
                        cf.log,
                        "\"acme_certificate\": no identifiers found in \"server_name\""
                    );
                    return Err(Status::NGX_ERROR);
                }
            }

            if let Some(issuer) = self.issuer_mut(&ascf.issuer) {
                issuer.add_certificate_order(cf, order)?;
            } else {
                ngx_log_error!(
                    NGX_LOG_EMERG,
                    cf.log,
                    "issuer \"{}\" is missing",
                    ascf.issuer
                );
                return Err(Status::NGX_ERROR);
            };
        }

        if !self.is_configured() {
            return Ok(());
        }

        /* Run postconfiguration for issuers */

        for issuer in self.issuers.iter_mut() {
            if let Err(err) = issuer.postconfiguration(cf) {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "acme_issuer: {}", err);
                return Err(Status::NGX_ERROR);
            }
        }

        /* Request shared zone allocation */

        if !self.shm_zone.is_configured() {
            self.shm_zone = SharedZone::Configured(ACME_ZONE_NAME, ACME_ZONE_SIZE);
        }

        let amcfp = ptr::from_mut(self).cast();
        let shm_zone = self.shm_zone.request(cf)?;
        shm_zone.init = Some(crate::state::ngx_acme_shared_zone_init);
        shm_zone.data = amcfp;
        shm_zone.noreuse = 1;

        Ok(())
    }
}

impl ngx::http::Merge for AcmeServerConfig {
    fn merge(&mut self, _prev: &Self) -> Result<(), ngx::http::MergeConfigError> {
        Ok(())
    }
}

/* Utility functions */

fn conf_check_nargs(cmd: &ngx_command_t, nargs: ngx_uint_t) -> bool {
    const ARGUMENT_NUMBER: [usize; 8] = [
        nginx_sys::NGX_CONF_NOARGS as _,
        nginx_sys::NGX_CONF_TAKE1 as _,
        nginx_sys::NGX_CONF_TAKE2 as _,
        nginx_sys::NGX_CONF_TAKE3 as _,
        nginx_sys::NGX_CONF_TAKE4 as _,
        nginx_sys::NGX_CONF_TAKE5 as _,
        nginx_sys::NGX_CONF_TAKE6 as _,
        nginx_sys::NGX_CONF_TAKE7 as _,
    ];

    let flags = cmd.type_;

    if (flags & (nginx_sys::NGX_CONF_ANY as ngx_uint_t)) != 0 {
        true
    } else if (flags & (nginx_sys::NGX_CONF_FLAG as ngx_uint_t)) != 0 {
        nargs == 2
    } else if (flags & (nginx_sys::NGX_CONF_1MORE as ngx_uint_t)) != 0 {
        nargs >= 2
    } else if (flags & (nginx_sys::NGX_CONF_2MORE as ngx_uint_t)) != 0 {
        nargs >= 3
    } else {
        nargs <= ARGUMENT_NUMBER.len() && (flags & ARGUMENT_NUMBER[nargs - 1]) != 0
    }
}

/// Unsafely converts `ngx_str_t` into a static UTF-8 string reference.
///
/// # Safety
///
/// `value` must be allocated on the configuration (cycle) pool, and stored in another object on the
/// same pool. With that, we can expect that both the borrowed string and the owning object will be
/// destroyed simultaneously.
///
/// In the worker process this happens at the process exit, making the `'static` lifetime specifier
/// accurate.
/// In the master process, the cycle pool is destroyed after reloading the configuration, along with
/// all the configuration objects. But this process role is not capable of serving connections or
/// running background tasks, and thus will not create additional borrows with potentially extended
/// lifetime.
unsafe fn conf_value_to_str(value: &ngx_str_t) -> Result<&'static str, core::str::Utf8Error> {
    if value.len == 0 {
        Ok("")
    } else {
        let bytes = core::slice::from_raw_parts(value.data, value.len);
        core::str::from_utf8(bytes)
    }
}
