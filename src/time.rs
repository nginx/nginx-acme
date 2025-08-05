use core::ops;
use core::time::Duration;

use nginx_sys::{ngx_parse_http_time, ngx_random, ngx_time, time_t, NGX_ERROR};
use openssl::asn1::Asn1TimeRef;
use openssl::x509::X509Ref;
use openssl_foreign_types::ForeignTypeRef;
use thiserror::Error;

pub const NGX_INVALID_TIME: time_t = NGX_ERROR as _;

#[derive(Debug, Error)]
#[error("invalid time")]
pub struct InvalidTime;

/// Unix timestamp value in seconds.
///
/// We could take a more complete implementation, like `::time::UtcDateTime`,
/// but it wolud be noticeably larger with unnecessary for this scenario precision.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Time(time_t);

impl TryFrom<&Asn1TimeRef> for Time {
    type Error = InvalidTime;

    #[cfg(openssl = "openssl111")]
    fn try_from(asn1time: &Asn1TimeRef) -> Result<Self, Self::Error> {
        let val = unsafe {
            let mut tm: libc::tm = core::mem::zeroed();
            if openssl_sys::ASN1_TIME_to_tm(asn1time.as_ptr(), &mut tm) != 1 {
                return Err(InvalidTime);
            }
            libc::timegm(&mut tm) as _
        };

        Ok(Time(val))
    }

    #[cfg(any(openssl = "awslc", openssl = "boringssl"))]
    fn try_from(asn1time: &Asn1TimeRef) -> Result<Self, Self::Error> {
        let mut val: time_t = 0;
        if unsafe { openssl_sys::ASN1_TIME_to_time_t(asn1time.as_ptr(), &mut val) } != 1 {
            return Err(InvalidTime);
        }
        Ok(Time(val))
    }

    #[cfg(not(any(openssl = "openssl111", openssl = "awslc", openssl = "boringssl")))]
    fn try_from(asn1time: &Asn1TimeRef) -> Result<Self, Self::Error> {
        use openssl_sys::{
            ASN1_TIME_print, BIO_free, BIO_get_mem_data, BIO_new, BIO_s_mem, BIO_write,
        };

        let val = unsafe {
            let bio = BIO_new(BIO_s_mem());
            if bio.is_null() {
                openssl::error::ErrorStack::get(); // clear errors
                return Err(InvalidTime);
            }

            let mut value: *mut core::ffi::c_char = core::ptr::null_mut();
            /* fake weekday prepended to match C asctime() format */
            let prefix = c"Tue ";
            BIO_write(bio, prefix.as_ptr().cast(), prefix.count_bytes() as _);
            ASN1_TIME_print(bio, asn1time.as_ptr());
            let len = BIO_get_mem_data(bio, &mut value);
            let val = ngx_parse_http_time(value.cast(), len as _);

            BIO_free(bio);
            val
        };

        if val == NGX_INVALID_TIME {
            return Err(InvalidTime);
        }

        Ok(Time(val))
    }
}

impl Time {
    pub const MAX: Self = Self(time_t::MAX);
    // time_t can be signed, but is not supposed to be negative
    pub const MIN: Self = Self(0);

    pub fn now() -> Self {
        Self(ngx_time())
    }

    pub fn parse(value: &str) -> Result<Self, InvalidTime> {
        let p = value.as_ptr().cast_mut();

        let tm = unsafe { ngx_parse_http_time(p, value.len()) };
        if tm == NGX_INVALID_TIME {
            return Err(InvalidTime);
        }

        Ok(Self(tm))
    }
}

/// This type represents an open-ended interval of time measured in seconds.
#[derive(Clone, Debug, Default)]
pub struct TimeRange {
    pub start: Time,
    pub end: Time,
}

impl TimeRange {
    pub fn new(start: Time, end: Time) -> Self {
        // ensure that end >= start
        let end = end.max(start);
        Self { start, end }
    }

    pub fn from_x509(x509: &X509Ref) -> Option<Self> {
        let start = Time::try_from(x509.not_before()).ok()?;
        let end = Time::try_from(x509.not_after()).ok()?;
        Some(Self::new(start, end))
    }

    /// Returns duration between the start and the end of the interval.
    #[inline]
    pub fn duration(&self) -> Duration {
        self.end - self.start
    }
}

/// Randomizes the duration within the specified percentage, with a 1s accuracy.
pub fn jitter(value: Duration, pct: u8) -> Duration {
    let var = value * (pct as u32) / 100;

    let var_secs = var.as_secs();
    if var_secs == 0 {
        return value;
    }

    let diff = Duration::from_secs(ngx_random() as u64 % (var_secs * 2));

    value + diff - var
}

/* A reasonable set of arithmetic operations:
 *  time + duration = time
 *  time - duration = time
 *  time - time = duration
 *  time + time = ???
 */

impl ops::Add<Duration> for Time {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs.as_secs() as _))
    }
}

impl ops::Sub<Duration> for Time {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        // time_t is not supposed to be negative
        Self(self.0 - rhs.as_secs() as time_t).max(Self::MIN)
    }
}

impl ops::Sub for Time {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        // duration cannot be negative
        let diff = (self.0 - rhs.0).max(0) as u64;
        Duration::from_secs(diff)
    }
}
