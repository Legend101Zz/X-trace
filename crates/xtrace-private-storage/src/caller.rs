//! Fixed caller categories for the private CI channel; never part of an admission verdict.

/// Store entry points and admission sites. No caller-supplied text is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCaller {
    /// Opening the SQLite store.
    SqliteOpen,
    /// Wrapping an existing SQLite connection.
    SqliteWrap,
    /// Checking SQLite files before using a connection.
    SqliteFiles,
    /// Starting a recording.
    Begin,
    /// Acknowledging a batch.
    Append,
    /// Finishing a recording.
    Finish,
    /// Recovering an interrupted recording.
    Recover,
    /// Reading a published recording.
    Read,
    /// Binding the project root and database.
    RootBinding,
    /// Preparing segment staging.
    SegmentStage,
    /// Publishing a segment object.
    SegmentPublish,
    /// Removing segment staging.
    SegmentCleanup,
    /// Checking a managed directory.
    ManagedDirectory,
    /// Checking a managed directory tree.
    ManagedTree,
    /// Checking a managed file.
    ManagedFile,
    /// Acquiring the journal publication file lock.
    JournalLock,
    /// Opening or creating the journals directory.
    JournalDirectory,
    /// Preparing an unpublished checkpoint.
    JournalPrepare,
    /// Publishing a checkpoint.
    JournalPublish,
    /// Reading journal snapshot files.
    JournalRead,
    /// Appending journal events.
    JournalAppend,
    /// Persisting the recording capture ceiling.
    JournalCaptureCap,
    /// Removing journal files.
    JournalRemove,
    /// Syncing the journal directory.
    JournalSync,
}

#[cfg(feature = "ci-diagnostics")]
type Callers = (Option<AdmissionCaller>, Option<AdmissionCaller>);

#[cfg(feature = "ci-diagnostics")]
thread_local! {
    static CALLERS: std::cell::Cell<Callers> = const { std::cell::Cell::new((None, None)) };
}

/// Thread-bound diagnostic scope. Nested sites retain the outermost store phase.
/// With CI diagnostics disabled this guard retains no caller state.
#[must_use]
pub struct AdmissionCallerGuard {
    #[cfg(feature = "ci-diagnostics")]
    previous: Option<Callers>,
    _thread: std::marker::PhantomData<*const ()>,
}

impl AdmissionCallerGuard {
    /// Labels observations on this thread until the guard is dropped.
    pub fn enter(caller: AdmissionCaller) -> Self {
        #[cfg(feature = "ci-diagnostics")]
        let previous = CALLERS
            .try_with(|slot| {
                let previous = slot.get();
                slot.set((previous.0.or(Some(caller)), Some(caller)));
                previous
            })
            .ok();
        let _ = caller;
        Self {
            #[cfg(feature = "ci-diagnostics")]
            previous,
            _thread: std::marker::PhantomData,
        }
    }
}

impl Drop for AdmissionCallerGuard {
    fn drop(&mut self) {
        #[cfg(feature = "ci-diagnostics")]
        if let Some(previous) = self.previous {
            let _ = CALLERS.try_with(|slot| slot.set(previous));
        }
    }
}

#[cfg(feature = "ci-diagnostics")]
pub(crate) fn current() -> Callers {
    CALLERS.try_with(std::cell::Cell::get).unwrap_or((None, None))
}

#[cfg(all(test, feature = "ci-diagnostics"))]
mod tests {
    use super::*;

    #[test]
    fn nested_sites_restore_the_phase_and_do_not_cross_threads() {
        assert_eq!(current(), (None, None));
        let phase = AdmissionCallerGuard::enter(AdmissionCaller::Append);
        {
            let _site = AdmissionCallerGuard::enter(AdmissionCaller::JournalPublish);
            assert_eq!(
                current(),
                (Some(AdmissionCaller::Append), Some(AdmissionCaller::JournalPublish))
            );
            assert!(matches!(std::thread::spawn(current).join(), Ok((None, None))));
        }
        assert_eq!(current(), (Some(AdmissionCaller::Append), Some(AdmissionCaller::Append)));
        drop(phase);
        assert_eq!(current(), (None, None));
    }
}
