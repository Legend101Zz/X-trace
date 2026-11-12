//! Test-only facts where segment object and journal errors lose their source.

use std::{cell::Cell, fmt, io, marker::PhantomData, rc::Rc};

use xtrace_domain::CorrelationId;
use xtrace_private_storage::{AdmissionFailure, PrivateStorageError};

use super::{RecordingStoreError, object_io_error};

#[derive(Clone, Copy, Debug)]
pub(super) enum ObjectIoSite {
    StagingProjectRootOpen,
    StagingRootOpenOrCreate,
    StagingRecordingOpenOrCreate,
    StagingDirectoryCreate,
    StagingRecordingSync,
    ObjectProjectRootOpen,
    ObjectParentOpenOrCreate,
    ObjectParentRevalidate,
    StageFileParent,
    StageFileName,
    StageFileParentOpen,
    StageFileCreate,
    StageFileWrite,
    StageFileFlush,
    StageFileSync,
    StageFileBinding,
    StageFileParentSync,
    JournalSnapshotRegistryLock,
    JournalSnapshotReadLock,
    JournalSnapshotWriteLock,
    JournalLockDirectoryOpen,
    JournalFlock,
    JournalLockRevalidate,
    JournalDirectoryOpen,
    JournalDirectoryOpenOrCreate,
    JournalDirectoryMetadata,
    JournalDirectoryMissing,
    JournalParentOpen,
    JournalSyncDirectoryOpen,
    JournalSyncDirectoryRevalidate,
    JournalDirectorySync,
    CheckpointMetadata,
    CheckpointRead,
    CheckpointOpenOrCreate,
    CheckpointTruncate,
    CheckpointWrite,
    CheckpointSync,
    CheckpointPendingBinding,
    CheckpointTargetAdmission,
    CheckpointDirectoryRevalidate,
    CheckpointRename,
    CheckpointPublishedBinding,
    CheckpointDirectorySync,
    JournalNamedMetadata,
    JournalRead,
    JournalOpenOrCreate,
    JournalFileMetadata,
    JournalTruncate,
    JournalSeek,
    JournalHeaderWrite,
    JournalWrite,
    JournalSync,
    JournalBinding,
    JournalCleanupMetadata,
    JournalCleanupRemove,
    CommitFailpoint,
}

#[derive(Clone, Copy, Default)]
struct Observation {
    site: Option<ObjectIoSite>,
    private_error: Option<PrivateStorageError>,
    kind: Option<io::ErrorKind>,
    errno: Option<i32>,
}

thread_local! {
    // None means no acknowledgement is being observed on this thread.
    static FIRST: Cell<Option<Option<Observation>>> = const { Cell::new(None) };
}

pub(crate) struct Scope {
    previous: Option<Option<Observation>>,
    _thread: PhantomData<Rc<()>>,
}

impl Scope {
    pub(crate) fn enter() -> Self {
        Self { previous: FIRST.with(|slot| slot.replace(Some(None))), _thread: PhantomData }
    }

    pub(crate) fn report(&self, iteration: u64) -> String {
        let facts = FIRST.with(|slot| slot.get().flatten()).unwrap_or_default();
        let admission = match facts.private_error {
            Some(PrivateStorageError::Admission(failure)) => Some(failure),
            _ => None,
        };
        let error = match facts.private_error {
            Some(PrivateStorageError::Admission(_)) => "Admission",
            Some(PrivateStorageError::Unavailable) => "Unavailable",
            Some(PrivateStorageError::InvalidName) => "InvalidName",
            Some(PrivateStorageError::AlreadyExists) => "AlreadyExists",
            Some(PrivateStorageError::Operation) => "Operation",
            None => "unavailable",
        };
        format!(
            "iteration={iteration} operation={:?} error={error} admission={:?} kind={:?} errno={:?} context={}",
            Available(facts.site),
            Available(admission.map(|failure| failure.operation)),
            Available(facts.kind),
            Available(facts.errno),
            AdmissionFailure::diagnostic_context(admission)
        )
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        FIRST.with(|slot| slot.set(self.previous));
    }
}

struct Available<T>(Option<T>);

impl<T: fmt::Debug> fmt::Debug for Available<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => fmt::Debug::fmt(value, formatter),
            None => formatter.write_str("unavailable"),
        }
    }
}

fn observe(facts: Observation) {
    FIRST.with(|slot| {
        if matches!(slot.get(), Some(None)) {
            slot.set(Some(Some(facts)));
        }
    });
}

pub(super) fn private<T>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    call: impl FnOnce() -> Result<T, PrivateStorageError>,
) -> Result<T, RecordingStoreError> {
    if !FIRST.with(|slot| matches!(slot.get(), Some(None))) {
        return call().map_err(|_| object_io_error(correlation_id));
    }
    let (result, discarded) = PrivateStorageError::with_io_diagnostic(call);
    result.map_err(|error| {
        let (kind, errno) = match error {
            PrivateStorageError::Admission(failure) => (failure.kind, failure.raw_os_error),
            _ => discarded.map_or((None, None), |(kind, errno)| (Some(kind), errno)),
        };
        observe(Observation { site: Some(site), private_error: Some(error), kind, errno });
        object_io_error(correlation_id)
    })
}

pub(super) fn direct<T, E: Into<io::Error>>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    call: impl FnOnce() -> Result<T, E>,
) -> Result<T, RecordingStoreError> {
    call().map_err(|error| {
        let error = error.into();
        observe(Observation {
            site: Some(site),
            kind: Some(error.kind()),
            errno: error.raw_os_error(),
            ..Observation::default()
        });
        object_io_error(correlation_id)
    })
}

pub(super) fn missing<T, E>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    call: impl FnOnce() -> Result<T, E>,
) -> Result<T, RecordingStoreError> {
    call().map_err(|_| {
        observe(Observation { site: Some(site), ..Observation::default() });
        object_io_error(correlation_id)
    })
}

pub(super) fn observe_failpoint() {
    observe(Observation { site: Some(ObjectIoSite::CommitFailpoint), ..Observation::default() });
}

#[cfg(test)]
mod tests {
    use super::super::{COMMIT_FAILPOINT, COMMIT_FAILPOINT_FIRED, commit_failpoint};
    use super::*;
    use xtrace_private_storage::AdmissionOperation;

    #[test]
    fn first_object_io_survives_cleanup_and_other_threads_and_resets() {
        let inject = |site, error| {
            let id = CorrelationId::new();
            let result = direct(site, id, || Err::<(), _>(error));
            assert!(matches!(result, Err(failure) if failure.code() == "XTR-STORE-OBJECT-IO"
                && failure.kind() == super::super::RecordingStoreErrorKind::Transport));
        };
        let scope = Scope::enter();
        inject(ObjectIoSite::StageFileWrite, io::Error::from_raw_os_error(13));
        let expected = "iteration=2 operation=StageFileWrite error=unavailable admission=unavailable kind=PermissionDenied errno=13 context=unavailable";
        std::thread::scope(|threads| {
            let other = threads.spawn(|| {
                let other_scope = Scope::enter();
                inject(ObjectIoSite::StageFileSync, io::ErrorKind::Interrupted.into());
                assert!(other_scope.report(1).contains("operation=StageFileSync"));
            });
            inject(ObjectIoSite::StageFileParentSync, io::ErrorKind::Other.into());
            assert!(other.join().is_ok());
        });
        assert_eq!(scope.report(2), expected);
        drop(scope);

        let scope = Scope::enter();
        let cleanup_point = "cleanup-staging-directory-fsync";
        let previous = COMMIT_FAILPOINT.with(|slot| slot.replace(Some(cleanup_point)));
        let cleanup = commit_failpoint(cleanup_point, CorrelationId::new(), false);
        COMMIT_FAILPOINT.with(|slot| slot.replace(previous));
        assert!(COMMIT_FAILPOINT_FIRED.with(|fired| fired.replace(false)));
        assert!(matches!(cleanup, Err(error) if error.code() == "XTR-STORE-OBJECT-IO"));
        assert_eq!(
            scope.report(3),
            "iteration=3 operation=unavailable error=unavailable admission=unavailable kind=unavailable errno=unavailable context=unavailable"
        );
        inject(
            ObjectIoSite::StageFileFlush,
            io::Error::other("/private/path payload-canary ACL-canary"),
        );
        assert_eq!(
            scope.report(3),
            "iteration=3 operation=StageFileFlush error=unavailable admission=unavailable kind=Other errno=unavailable context=unavailable"
        );
    }

    #[test]
    fn private_storage_variant_and_only_available_facts_survive_mapping() {
        let id = CorrelationId::new();
        {
            let scope = Scope::enter();
            let failure = AdmissionFailure::io(
                AdmissionOperation::NamedMetadata,
                io::Error::new(io::ErrorKind::PermissionDenied, "identity-canary /private/path"),
            );
            let result = private(ObjectIoSite::StagingProjectRootOpen, id, || {
                Err::<(), _>(PrivateStorageError::Admission(failure))
            });
            assert!(matches!(result, Err(error) if error.code() == "XTR-STORE-OBJECT-IO"));
            assert_eq!(
                scope.report(1),
                "iteration=1 operation=StagingProjectRootOpen error=Admission admission=NamedMetadata kind=PermissionDenied errno=unavailable context=unavailable"
            );
        }

        let scope = Scope::enter();
        let result = private(ObjectIoSite::StagingRecordingSync, id, || {
            Err::<(), _>(PrivateStorageError::Operation)
        });
        assert!(matches!(result, Err(error) if error.code() == "XTR-STORE-OBJECT-IO"));
        assert_eq!(
            scope.report(1),
            "iteration=1 operation=StagingRecordingSync error=Operation admission=unavailable kind=unavailable errno=unavailable context=unavailable"
        );
    }
}
