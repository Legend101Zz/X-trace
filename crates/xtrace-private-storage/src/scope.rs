//! Admission scope: a thread-bound guard under which operations share one verdict memo.
//!
//! See ADR 0008 Amendment 1. The scope never extends an operation's deadline and never
//! replaces an identity check; it only lets operations created on this thread while the scope
//! is live reuse directory verdicts and the batched listing, until the scope is dropped or its
//! wall-clock cap passes.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Wall-clock cap of one scope, measured from its start (ADR 0008 Amendment 1, decision 5).
pub(crate) const ADMISSION_SCOPE_CAP: Duration = Duration::from_secs(10);

static NEXT_SCOPE_ID: AtomicU64 = AtomicU64::new(1);

/// Guard for one store call. Operations created on this thread while it is live share the
/// directory verdict memo and the batched listing. It is neither `Send` nor `Sync`; entering
/// while a scope is live on this thread joins that scope. Dropping the last guard forgets
/// everything the scope remembered.
#[must_use = "an admission scope ends as soon as its guard is dropped"]
pub struct AdmissionScope {
    _single_thread: PhantomData<*const ()>,
}

/// State of the live scope on one thread.
pub(crate) struct ScopeState {
    id: u64,
    depth: u32,
    started: Instant,
    cap: Duration,
    lapsed: bool,
    /// Directory verdicts earned under this scope.
    pub(crate) memo: Vec<crate::probe::MemoKey>,
    /// The scope's single batched listing, once taken.
    #[cfg(target_os = "macos")]
    pub(crate) batch: Option<crate::probe::Prefetched>,
    /// Whether the scope's one batch has been attempted (successful or not).
    #[cfg(target_os = "macos")]
    pub(crate) batch_attempted: bool,
}

impl ScopeState {
    fn lapse_if_due(&mut self) {
        if !self.lapsed && self.started.elapsed() >= self.cap {
            self.lapsed = true;
            self.memo.clear();
            #[cfg(target_os = "macos")]
            {
                self.batch = None;
            }
        }
    }
}

thread_local! {
    static SCOPE: RefCell<Option<ScopeState>> = const { RefCell::new(None) };
}

impl AdmissionScope {
    /// Opens a scope on this thread, or joins the live one.
    pub fn enter() -> Self {
        Self::open(ADMISSION_SCOPE_CAP)
    }

    /// Test constructor with a short cap; production code always uses [`ADMISSION_SCOPE_CAP`].
    #[cfg(test)]
    pub(crate) fn enter_with_cap(cap: Duration) -> Self {
        Self::open(cap)
    }

    fn open(cap: Duration) -> Self {
        SCOPE.with(|cell| {
            let mut slot = cell.borrow_mut();
            if let Some(state) = slot.as_mut() {
                state.depth += 1;
            } else {
                *slot = Some(ScopeState {
                    id: NEXT_SCOPE_ID.fetch_add(1, Ordering::Relaxed),
                    depth: 1,
                    started: Instant::now(),
                    cap,
                    lapsed: false,
                    memo: Vec::new(),
                    #[cfg(target_os = "macos")]
                    batch: None,
                    #[cfg(target_os = "macos")]
                    batch_attempted: false,
                });
            }
        });
        Self { _single_thread: PhantomData }
    }
}

impl Drop for AdmissionScope {
    fn drop(&mut self) {
        // During thread teardown the slot may already be gone; there is then nothing to forget.
        let _ = SCOPE.try_with(|cell| {
            let mut slot = cell.borrow_mut();
            if let Some(state) = slot.as_mut() {
                state.depth -= 1;
                if state.depth == 0 {
                    *slot = None;
                }
            }
        });
    }
}

/// Id of the scope that is live and inside its cap on this thread, if any. A scope found past
/// its cap drops its memo and batch here.
pub(crate) fn live_scope_id() -> Option<u64> {
    SCOPE
        .try_with(|cell| {
            let mut slot = cell.borrow_mut();
            let state = slot.as_mut()?;
            state.lapse_if_due();
            (!state.lapsed).then_some(state.id)
        })
        .ok()
        .flatten()
}

/// Runs `f` on the state of scope `id` when it is still live on this thread and inside its cap.
pub(crate) fn with_scope<R>(id: u64, f: impl FnOnce(&mut ScopeState) -> R) -> Option<R> {
    SCOPE
        .try_with(|cell| {
            let mut slot = cell.borrow_mut();
            let state = slot.as_mut()?;
            state.lapse_if_due();
            (!state.lapsed && state.id == id).then(|| f(state))
        })
        .ok()
        .flatten()
}
