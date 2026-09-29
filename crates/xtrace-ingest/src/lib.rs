//! Recording assembler boundary.
//!
//! `xtrace-ingest` is the protocol validation boundary that sits between
//! an authenticated XTP-Agent session and the durable recording store.
//! It accepts generated [`RecordingStarted`], [`EventBatch`], and
//! [`RecordingFinished`] wire payloads and returns typed acceptance or
//! rejection decisions without performing I/O, networking, or storage
//! writes.
//!
//! The crate owns three responsibilities and no others:
//!
//! 1. **Per-recording lifecycle.** Each `RecordingId` is tracked in
//!    [`RecordingLifecycle::Recording`] until its matching
//!    [`RecordingFinished`] arrives, then it transitions to
//!    [`RecordingLifecycle::Finalizing`]. Finalizing entries and the
//!    event digests they retain stay in the validator's map for the
//!    lifetime of the [`IngestValidator`] because this slice does not
//!    expose a drain or removal API; they are never evicted or silently
//!    dropped by this crate. Multiple recording IDs interleave
//!    independently inside one [`IngestValidator`].
//! 2. **Per-recording sequence ordering.** Strictly ascending
//!    `recording_seq` values are required inside every batch. Duplicates
//!    are accepted as idempotent retries only when the deterministic
//!    payload digest matches; a mismatching duplicate is a typed
//!    session-fatal replay-payload mismatch. Forward gaps return a
//!    retransmission hint without mutating state. The preflight is
//!    written so exact replays at `u64::MAX` and a final contiguous
//!    event at `u64::MAX` from `u64::MAX - 1` are both accepted without
//!    checked arithmetic overflow.
//! 3. **Bounded capacity.** The validator rejects new recordings or
//!    new events without mutating state when its active or per-recording
//!    event budget is exhausted. Digests for accepted events remain in
//!    the map after finalization for the validator's lifetime so exact
//!    replays stay idempotent; this crate does not release or evict
//!    them.
//!
//! The crate is IO-free, framework-neutral, and asynchronous-free. It
//! does not own SQLite, XTF, the daemon loop, or the `xtrace-application`
//! facade. The domain crate stays protocol-free: it never imports any
//! generated wire type. This crate is the single seam where the two
//! meet, and the seam is explicit so other slices can attach durable
//! storage, throttling, capability gating, and policy decisions
//! (including `DropNotice` handling or priority-based degradation)
//! behind the same typed contract. This crate surfaces the typed
//! capacity reasons but does not apply the policy itself.
//!
//! [`RecordingStarted`]: xtrace_protocol::generated::agent::RecordingStarted
//! [`EventBatch`]: xtrace_protocol::generated::agent::EventBatch
//! [`RecordingFinished`]: xtrace_protocol::generated::agent::RecordingFinished

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod error;
pub mod validator;

pub use error::IngestError;
pub use validator::{Acceptance, IngestConfig, IngestValidator, RecordingLifecycle};
