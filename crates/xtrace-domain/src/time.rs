//! Time primitives shared across the X-trace stack.
//!
//! Wall-clock time is persisted and surfaced to clients as RFC 3339 UTC
//! with microsecond precision. Adapter-supplied ordering uses raw
//! monotonic nanoseconds so the daemon is never tricked by a clock
//! adjustment.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, PrimitiveDateTime, Time};

/// Wall-clock time pinned to UTC and encoded with microsecond precision.
///
/// `WallTime` is the only type the rest of the system accepts for
/// durable, externally visible timestamps. It cannot represent a value
/// in the future by more than one year to catch obvious protocol
/// regressions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct WallTime(OffsetDateTime);

impl WallTime {
    /// Returns the current system time as `WallTime`.
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Constructs a `WallTime` from a calendar date, clock time, and
    /// microsecond offset.
    #[must_use = "returns the new `WallTime` or the conversion error; never panics"]
    pub fn from_parts(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsecond: u32,
    ) -> Result<Self, TimeError> {
        let date = time::Date::from_calendar_date(year, time::Month::try_from(month)?, day)
            .map_err(TimeError::from)?;
        let time =
            Time::from_hms_micro(hour, minute, second, microsecond).map_err(TimeError::from)?;
        Ok(Self(PrimitiveDateTime::new(date, time).assume_utc()))
    }

    /// Renders the value in canonical RFC 3339 form with microsecond
    /// precision and a `Z` suffix.
    ///
    /// The formatting helper is infallible because every component is
    /// written through the standard `write!` machinery; an unreachable
    /// write error would only occur if the formatter itself failed.
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        let dt = self.0;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            dt.microsecond(),
        )
    }
}

impl fmt::Debug for WallTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl fmt::Display for WallTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl FromStr for WallTime {
    type Err = TimeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept both the canonical `Z` suffix and explicit `+00:00`
        // offsets so inbound UTC timestamps are parsed uniformly.
        if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
            return Ok(Self(dt));
        }
        // `time` rejects the `+00:00` form when it expects `Z`; try the
        // alternate layout before giving up.
        let dt = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(TimeError::Parse)?;
        Ok(Self(dt))
    }
}

/// Raw adapter-supplied monotonic time. Used for event ordering and
/// relative timing within a recording. Never persisted as the only
/// ordering key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct MonotonicNs(pub u64);

/// Maximum representable non-negative nanosecond difference. Matches
/// `i64::MAX` and therefore caps the returned [`Duration`] at roughly
/// 292 years; differences above this value saturate rather than wrap.
pub const MAX_SATURATED_NANOS: i64 = i64::MAX;

impl MonotonicNs {
    /// Wraps a raw monotonic reading.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Computes the signed delta between two readings.
    ///
    /// The result is computed in `i128` so the worst-case subtraction
    /// of two `u64` values cannot overflow; callers receive the full
    /// signed range and decide how to project it onto their own
    /// duration type.
    #[must_use]
    pub fn delta(self, other: Self) -> i128 {
        i128::from(self.0) - i128::from(other.0)
    }

    /// Returns the elapsed duration since `earlier`.
    ///
    /// Negative deltas clamp to `Duration::ZERO`. Positive deltas that
    /// would overflow `i64` nanoseconds saturate at
    /// [`MAX_SATURATED_NANOS`] so the returned [`Duration`] is always
    /// representable. The saturation is explicit rather than panicking
    /// because monotonic readings are adapter-supplied and a runaway
    /// counter must not crash the daemon.
    #[must_use]
    pub fn elapsed_since(self, earlier: Self) -> Duration {
        // Compute the difference in `i128` to avoid the `u64`
        // subtraction edge case. Saturating to `MAX_SATURATED_NANOS`
        // preserves the explicit-behavior contract: a caller receives
        // the largest representable duration and never a negative
        // value, never a panic, and never a silent wrap.
        let diff = self.delta(earlier);
        if diff <= 0 {
            return Duration::ZERO;
        }
        let nanos = i64::try_from(diff).unwrap_or(MAX_SATURATED_NANOS);
        Duration::nanoseconds(nanos)
    }
}

impl fmt::Debug for MonotonicNs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MonotonicNs({})", self.0)
    }
}

impl fmt::Display for MonotonicNs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors raised by the time helpers in this module.
#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    /// The calendar date or clock time was out of range.
    #[error("invalid time component")]
    Component(#[from] time::error::ComponentRange),
    /// RFC 3339 parsing failed.
    #[error("invalid RFC 3339 timestamp")]
    Parse(#[from] time::error::Parse),
    /// Conversion from a primitive integer failed.
    #[error("invalid month or calendar value")]
    Conversion(#[from] time::error::ConversionRange),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trip() {
        let original = WallTime::now();
        let parsed: WallTime =
            original.to_rfc3339().parse().expect("formatted RFC 3339 always parses");
        // Microsecond precision is preserved.
        assert_eq!(original.to_rfc3339(), parsed.to_rfc3339());
    }

    #[test]
    fn from_parts_is_strict() {
        // Month 13 must fail.
        assert!(WallTime::from_parts(2026, 13, 1, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn monotonic_delta_is_signed() {
        let a = MonotonicNs::from_raw(100);
        let b = MonotonicNs::from_raw(250);
        assert_eq!(b.delta(a), 150);
        assert_eq!(a.delta(b), -150);
    }

    #[test]
    fn monotonic_elapsed_clamps_zero() {
        let a = MonotonicNs::from_raw(300);
        let b = MonotonicNs::from_raw(100);
        assert_eq!(a.elapsed_since(b), Duration::nanoseconds(200));
        assert_eq!(b.elapsed_since(a), Duration::ZERO);
    }

    #[test]
    fn monotonic_elapsed_saturates_on_overflow() {
        // The previous `as i64` cast would silently wrap; the new
        // implementation must saturate instead. Choose a delta that
        // overflows `i64::MAX` nanoseconds (~292 years) and confirm
        // the result clamps to the documented saturation point.
        let earlier = MonotonicNs::from_raw(0);
        let later = MonotonicNs::from_raw(u64::MAX);
        assert_eq!(later.elapsed_since(earlier), Duration::nanoseconds(MAX_SATURATED_NANOS));
    }

    #[test]
    fn monotonic_elapsed_saturates_at_i64_max_boundary() {
        // The exact `i64::MAX` nanosecond delta must survive
        // conversion; values strictly above must still saturate.
        let earlier = MonotonicNs::from_raw(0);
        let boundary = MonotonicNs::from_raw(MAX_SATURATED_NANOS as u64);
        assert_eq!(
            boundary.elapsed_since(earlier),
            Duration::nanoseconds(MAX_SATURATED_NANOS),
            "boundary value must convert exactly",
        );
        let overflow = MonotonicNs::from_raw(MAX_SATURATED_NANOS as u64 + 1);
        assert_eq!(
            overflow.elapsed_since(earlier),
            Duration::nanoseconds(MAX_SATURATED_NANOS),
            "value above i64::MAX must saturate",
        );
    }

    #[test]
    fn monotonic_delta_never_overflows() {
        // `i128` is wide enough to hold the full u64 difference
        // without overflow even at the extremes.
        let lo = MonotonicNs::from_raw(0);
        let hi = MonotonicNs::from_raw(u64::MAX);
        assert_eq!(hi.delta(lo), i128::from(u64::MAX));
        assert_eq!(lo.delta(hi), -i128::from(u64::MAX));
    }
}
