use core::ops;
use core::time::Duration;

use nginx_sys::{ngx_random, ngx_time, time_t};
use thiserror::Error;

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

impl Time {
    // time_t can be signed, but is not supposed to be negative
    pub const MIN: Self = Self(0);

    pub fn now() -> Self {
        Self(ngx_time())
    }
}

/// This type represents an open-ended interval of time measured in seconds.
#[derive(Clone, Debug, Default)]
pub struct TimeRange {
    pub start: Time,
    pub end: Time,
}

impl TimeRange {
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
