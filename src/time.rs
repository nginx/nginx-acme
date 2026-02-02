// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::str::FromStr;
use core::time::Duration;
use core::{fmt, ops};

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
pub struct Timestamp(time_t);

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl serde::de::Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("date format defined in RFC3339")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Timestamp::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

impl FromStr for Timestamp {
    type Err = InvalidTime;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_rfc3339_time(s).map(Self).ok_or(InvalidTime)
    }
}

impl TryFrom<&Asn1TimeRef> for Timestamp {
    type Error = InvalidTime;

    #[cfg(openssl = "openssl111")]
    fn try_from(asn1time: &Asn1TimeRef) -> Result<Self, Self::Error> {
        let val = unsafe {
            let mut tm: libc::tm = core::mem::zeroed();
            if openssl_sys::ASN1_TIME_to_tm(asn1time.as_ptr(), &mut tm) != 1 {
                return Err(InvalidTime);
            }
            timegm(&mut tm).ok_or(InvalidTime)?
        };

        Ok(Timestamp(val))
    }

    #[cfg(any(openssl = "awslc", openssl = "boringssl"))]
    fn try_from(asn1time: &Asn1TimeRef) -> Result<Self, Self::Error> {
        let mut val: time_t = 0;
        if unsafe { openssl_sys::ASN1_TIME_to_time_t(asn1time.as_ptr(), &mut val) } != 1 {
            return Err(InvalidTime);
        }
        Ok(Timestamp(val))
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

        Ok(Timestamp(val))
    }
}

impl Timestamp {
    pub const MAX: Self = Self::new(time_t::MAX);
    // time_t can be signed, but is not supposed to be negative
    pub const MIN: Self = Self::new(0);

    pub const fn new(value: time_t) -> Self {
        Self(value)
    }

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
pub struct Interval {
    pub start: Timestamp,
    pub end: Timestamp,
}

impl Interval {
    pub fn new(start: Timestamp, end: Timestamp) -> Self {
        // ensure that end >= start
        let end = end.max(start);
        Self { start, end }
    }

    pub fn from_x509(x509: &X509Ref) -> Option<Self> {
        let start = Timestamp::try_from(x509.not_before()).ok()?;
        let end = Timestamp::try_from(x509.not_after()).ok()?;
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

fn timegm(tm: &mut libc::tm) -> Option<time_t> {
    /*
     * timegm was not standardized until C23, but it is present in all libc implementations
     * we want to support.
     */
    let val = unsafe { libc::timegm(core::ptr::from_mut(tm)) } as time_t;

    if val == NGX_INVALID_TIME {
        return None;
    }

    Some(val)
}

fn parse_rfc3339_time(mut s: &str) -> Option<time_t> {
    #[inline]
    fn parse_fixed_num<N: FromStr + Ord>(
        p: &mut &str,
        width: usize,
        range: impl core::ops::RangeBounds<N>,
    ) -> Option<N> {
        let (x, rest) = p.split_at_checked(width)?;

        let x: N = x.parse().ok()?;
        if !range.contains(&x) {
            return None;
        }

        *p = rest;
        Some(x)
    }

    let mut tm: libc::tm = unsafe { core::mem::zeroed() };

    // years since 1900
    tm.tm_year = parse_fixed_num(&mut s, 4, 1900..=9999)? - 1900;
    s = s.strip_prefix('-')?;
    // months since January — [0, 11]
    tm.tm_mon = parse_fixed_num(&mut s, 2, 1..=12)? - 1;
    s = s.strip_prefix('-')?;
    // day of the month — [1, 31]
    tm.tm_mday = parse_fixed_num(&mut s, 2, 1..=31)?;

    s = s.strip_prefix(['T', 't'])?;

    // hours since midnight — [0, 23]
    tm.tm_hour = parse_fixed_num(&mut s, 2, 0..=23)?;
    s = s.strip_prefix(':')?;
    // minutes after the hour — [0, 59]
    tm.tm_min = parse_fixed_num(&mut s, 2, 0..=59)?;
    s = s.strip_prefix(':')?;
    // seconds after the minute — [0, 60]
    tm.tm_sec = parse_fixed_num(&mut s, 2, 0..=60)?;

    let tm = timegm(&mut tm)?;

    // skip time-secfrac

    if let Some(frac) = s.strip_prefix(".") {
        s = frac.trim_start_matches(|x: char| x.is_ascii_digit());
    }

    let (off, mut s) = s.split_at_checked(1)?;

    match off {
        "Z" | "z" if s.is_empty() => Some(tm),
        "+" | "-" if s.len() == 5 => {
            let hour = parse_fixed_num(&mut s, 2, 0..=23)?;
            s = s.strip_prefix(':')?;
            let min = parse_fixed_num(&mut s, 2, 0..=59)?;

            let off = if off == "+" { -60 } else { 60 } * (hour * 60 + min);
            Some(tm + off)
        }
        _ => None,
    }
}

/* A reasonable set of arithmetic operations:
 *  time + duration = time
 *  time - duration = time
 *  time - time = duration
 *  time + time = ???
 */

impl ops::Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs.as_secs() as _))
    }
}

impl ops::Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        // time_t is not supposed to be negative
        Self(self.0 - rhs.as_secs() as time_t).max(Self::MIN)
    }
}

impl ops::Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        // duration cannot be negative
        let diff = (self.0 - rhs.0).max(0) as u64;
        Duration::from_secs(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    #[test]
    fn test_timestamp_from_str() {
        use core::str::FromStr;

        assert_eq!(
            Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
            Timestamp::new(1767225600)
        );

        assert_eq!(
            Timestamp::from_str("2025-12-31t23:59:59z").unwrap(),
            Timestamp::new(1767225599)
        );

        assert_eq!(
            Timestamp::from_str("2026-01-01T01:01:01.001Z").unwrap(),
            Timestamp::new(1767229261)
        );

        assert_eq!(
            Timestamp::from_str("2026-01-01T08:01:01+07:00").unwrap(),
            Timestamp::new(1767229261)
        );

        assert_eq!(
            Timestamp::from_str("2025-12-31T17:01:01-08:00").unwrap(),
            Timestamp::new(1767229261)
        );

        assert_eq!(
            Timestamp::from_str("2026-01-01T08:01:01.001+07:00").unwrap(),
            Timestamp::new(1767229261)
        );

        assert!(Timestamp::from_str("26-01-01T01:01:01Z").is_err());
        assert!(Timestamp::from_str("30014-01-01T01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-001-01T01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-001T01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01T001:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01T01:001:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01T01:01:001Z").is_err());
        assert!(Timestamp::from_str("2026-13-31T01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-12-32T01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01Z01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01TT01:01:01Z").is_err());
        assert!(Timestamp::from_str("2026-01-01T01:01:01ZZ").is_err());
        assert!(Timestamp::from_str("2026-01-01T08:01:01+07:00Z").is_err());
        assert!(Timestamp::from_str("2026-01-01T08:01:01+24:00").is_err());
        assert!(Timestamp::from_str("2026-01-01T08:01:01+00:60").is_err());
    }
}
