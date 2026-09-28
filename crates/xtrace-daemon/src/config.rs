//! Daemon configuration.
//!
//! The daemon exposes one configuration record with explicit defaults
//! so a test harness, a launcher, and an attach helper share a single
//! reviewed surface. New tunables require an ADR; defaults match the
//! architecture-level budgets documented in
//! `docs/plans/x-trace/02-architecture.md` §6 and
//! `docs/plans/x-trace/03b-protocol-and-api.md` §2.

use std::time::Duration;

use xtrace_protocol::envelope::{DEFAULT_MAX_BATCH_EVENTS, DEFAULT_MAX_ENVELOPE_BYTES};

/// Default loopback host for the [`LoopbackPolicy::Any`] variant. The
/// daemon prefers IPv4 loopback unless the caller explicitly selects
/// [`LoopbackPolicy::V6Only`].
pub const LOOPBACK_HOST: &str = "127.0.0.1";

/// Default ingress channel capacity for one connection. Matches the
/// `adapter socket decode` row of `02-architecture.md` §6
/// (`64 batches`) so a slow consumer experiences TCP/TLS backpressure
/// rather than unbounded buffering.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 64;

/// Default health interval. The architecture requires a `Health`
/// message every ten seconds while idle; the constant is shared with
/// the connection supervisor.
pub const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(10);

/// Bounded queue capacity for the ingress channel feeding the
/// per-connection task.
///
/// The wrapper exists so configuration can be deserialized in a later
/// slice without breaking the public signature. The current
/// constructor validates the lower bound because a zero capacity
/// would deadlock the supervisor at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelCapacity(usize);

impl ChannelCapacity {
    /// Constructs a capacity from the supplied value. Returns
    /// `None` when the value is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 { None } else { Some(Self(capacity)) }
    }

    /// Returns the capacity in messages.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

impl Default for ChannelCapacity {
    fn default() -> Self {
        Self(DEFAULT_CHANNEL_CAPACITY)
    }
}

/// Loopback enforcement policy.
///
/// The daemon must bind to `127.0.0.1` and `::1` only. Constructors
/// reject non-loopback addresses so a misconfigured launch command
/// fails fast before any TCP socket is created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackPolicy {
    /// Bind to `127.0.0.1` on an OS-assigned port.
    V4Only,
    /// Bind to `::1` on an OS-assigned port.
    V6Only,
    /// Bind to whichever family the OS reports as loopback.
    Any,
}

impl Default for LoopbackPolicy {
    fn default() -> Self {
        Self::Any
    }
}

impl LoopbackPolicy {
    /// Returns the textual loopback host for the policy.
    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::V4Only => "127.0.0.1",
            Self::V6Only => "::1",
            Self::Any => LOOPBACK_HOST,
        }
    }
}

/// Top-level daemon configuration.
///
/// Every field carries an explicit default. Callers override only
/// what they need; the configuration is otherwise immutable.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Maximum envelope size in bytes accepted on the wire. Defaults
    /// to the architecture-level one-mebibyte cap.
    pub max_envelope_bytes: u32,
    /// Maximum batch size in events. Surfaces in [`DaemonHello`].
    pub max_batch_events: u32,
    /// Capacity of the per-connection ingress channel.
    pub channel_capacity: ChannelCapacity,
    /// Health interval sent back to the adapter.
    pub health_interval: Duration,
    /// Loopback enforcement policy.
    pub loopback_policy: LoopbackPolicy,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES,
            max_batch_events: DEFAULT_MAX_BATCH_EVENTS,
            channel_capacity: ChannelCapacity::default(),
            health_interval: DEFAULT_HEALTH_INTERVAL,
            loopback_policy: LoopbackPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_capacity_rejects_zero() {
        assert!(ChannelCapacity::new(0).is_none());
        let cap = ChannelCapacity::new(64).expect("non-zero is accepted");
        assert_eq!(cap.as_usize(), 64);
    }

    #[test]
    fn loopback_policy_host_is_loopback_for_every_variant() {
        assert_eq!(LoopbackPolicy::V4Only.host(), "127.0.0.1");
        assert_eq!(LoopbackPolicy::V6Only.host(), "::1");
        assert!(LoopbackPolicy::Any.host().starts_with("127.")
            || LoopbackPolicy::Any.host() == "::1");
    }

    #[test]
    fn defaults_match_architecture_values() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.max_envelope_bytes, DEFAULT_MAX_ENVELOPE_BYTES);
        assert_eq!(cfg.max_batch_events, DEFAULT_MAX_BATCH_EVENTS);
        assert_eq!(cfg.health_interval, DEFAULT_HEALTH_INTERVAL);
    }
}