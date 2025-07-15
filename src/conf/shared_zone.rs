use core::ffi::c_void;
use core::ptr::{self, NonNull};

use nginx_sys::{ngx_conf_t, ngx_int_t, ngx_shm_zone_t, ngx_str_t, NGX_ERROR};
use ngx::core::Status;
use ngx::http::HttpModule;
use ngx::log::ngx_cycle_log;
use ngx::{ngx_log_debug, ngx_string};
use thiserror::Error;

pub const ACME_ZONE_NAME: ngx_str_t = ngx_string!("ngx_acme_shared");
pub const ACME_ZONE_SIZE: usize = 1 << 18;

#[derive(Clone, Debug, Default)]
#[allow(unused)]
pub enum SharedZone {
    #[default]
    Unset,
    Configured(ngx_str_t, usize),
    Requested(NonNull<ngx_shm_zone_t>),
    Ready(NonNull<ngx_shm_zone_t>),
}

#[derive(Debug, Error)]
pub enum SharedZoneError {
    #[error("is duplicate")]
    AlreadyConfigured,
    #[error("invalid zone size \"{0}\"")]
    InvalidSize(ngx_str_t),
    #[error("zone {0} is too small")]
    TooSmall(ngx_str_t),
}

impl SharedZone {
    pub fn is_configured(&self) -> bool {
        !matches!(self, Self::Unset)
    }

    pub fn parse_name_size(value: ngx_str_t) -> Result<(ngx_str_t, usize), SharedZoneError> {
        let pos = value
            .as_bytes()
            .iter()
            .position(|x| *x == b':')
            .ok_or(SharedZoneError::InvalidSize(value))?;

        let (name, mut size) = value
            .split_at(pos)
            .ok_or(SharedZoneError::InvalidSize(value))?;

        size.len -= 1; // ':'
        size.data = unsafe { size.data.add(1) };

        let size = unsafe { nginx_sys::ngx_parse_size(&mut size) };
        if size == (NGX_ERROR as ngx_int_t) {
            return Err(SharedZoneError::InvalidSize(value));
        }

        Ok((name, size as usize))
    }

    pub fn configure(&mut self, name: ngx_str_t, size: usize) -> Result<(), SharedZoneError> {
        if self.is_configured() {
            return Err(SharedZoneError::AlreadyConfigured);
        }

        if size < unsafe { nginx_sys::ngx_pagesize * 8 } {
            return Err(SharedZoneError::TooSmall(name));
        }

        *self = SharedZone::Configured(name, size);

        Ok(())
    }

    pub fn request(&mut self, cf: &mut ngx_conf_t) -> Result<&mut ngx_shm_zone_t, Status> {
        if let Self::Configured(name, size) = self {
            let mut shm_zone = NonNull::new(unsafe {
                nginx_sys::ngx_shared_memory_add(
                    cf,
                    name,
                    *size,
                    ptr::from_ref(crate::HttpAcmeModule::module())
                        .cast_mut()
                        .cast(),
                )
            })
            .ok_or(Status::NGX_ERROR)?;

            *self = Self::Requested(shm_zone);

            let shm_zone = unsafe { shm_zone.as_mut() };

            // a placeholder init to avoid instant crash
            shm_zone.init = Some(Self::shm_dummy_init);
            shm_zone.data = ptr::from_mut(self).cast();

            return Ok(shm_zone);
        }

        Err(Status::NGX_DECLINED)
    }

    extern "C" fn shm_dummy_init(shm_zone: *mut ngx_shm_zone_t, _data: *mut c_void) -> ngx_int_t {
        // SAFETY: shm_zone is always valid in this callback
        let shm_zone = unsafe { &mut *shm_zone };
        let zone = match unsafe { shm_zone.data.cast::<SharedZone>().as_mut() } {
            Some(zone) => zone,
            None => return Status::NGX_ERROR.into(),
        };

        ngx_log_debug!(
            ngx_cycle_log().as_ptr(),
            "shared zone \"{}\" initialized with size {}",
            shm_zone.shm.name,
            shm_zone.shm.size
        );

        *zone = Self::Ready(NonNull::from(shm_zone));

        Status::NGX_OK.into()
    }
}
