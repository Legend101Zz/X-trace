use std::io::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};

/// An opt-in, run-scoped record of authenticated finish traffic on the daemon side.
#[derive(Default)]
pub(super) struct FinishCensus {
    nonce: String,
    pub(super) sessions: AtomicU32,
    pub(super) decoded: AtomicU32,
    pub(super) admitted: AtomicU32,
    pub(super) ack_ready: AtomicU32,
    pub(super) ack_queued: AtomicU32,
    pub(super) ack_flushed: AtomicU32,
}

impl FinishCensus {
    pub(super) fn from_env() -> Option<Self> {
        let nonce = std::env::var("XTRACE_MEDUSA_CAPTURE_DIAGNOSTIC").ok()?;
        if nonce.len() != 48
            || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(Self { nonce, ..Self::default() })
    }

    pub(super) fn count(counter: &AtomicU32) {
        let _ = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1));
    }

    /// The supervisor calls this only after every participating connection and writer joins.
    pub(super) fn emit(&self) {
        let load = |value: &AtomicU32| value.load(Ordering::Relaxed);
        let _ = writeln!(
            std::io::stderr().lock(),
            "XTR-MEDUSA-DAEMON-FINISH-V1 {{\"nonce\":\"{}\",\"sessions\":{},\"decoded\":{},\"admitted\":{},\"ackReady\":{},\"ackQueued\":{},\"ackFlushed\":{}}}",
            self.nonce,
            load(&self.sessions),
            load(&self.decoded),
            load(&self.admitted),
            load(&self.ack_ready),
            load(&self.ack_queued),
            load(&self.ack_flushed),
        );
    }
}
