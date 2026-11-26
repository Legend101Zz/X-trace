//! Test-only bounded facts for recording acknowledgement errors.

use std::{cell::Cell, fmt, io, marker::PhantomData, rc::Rc};

use xtrace_domain::CorrelationId;
use xtrace_private_storage::{AdmissionFailure, PrivateStorageError};

use super::RecordingStoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectIoSite {
    BindingRootOpen,
    BindingRootRevalidate,
    BindingDatabaseValidate,
    SqliteFileBinding,
    SqlitePrivateFiles,
    StagingProjectRootOpen,
    StagingRootOpenOrCreate,
    StagingRecordingOpenOrCreate,
    StagingDirectoryCreate,
    StagingRecordingRevalidate,
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
    ManagedDirectoryOpen,
    ManagedDirectoryRevalidate,
    ManagedTreeOpen,
    ManagedTreeChild,
    ManagedTreeRevalidate,
    ManagedFileParentOpen,
    ManagedFileBinding,
    PublishStagingRoot,
    PublishStagingFile,
    PublishStagingBinding,
    PublishDestinationRoot,
    PublishStagingRevalidate,
    PublishDestinationRevalidate,
    PublishHardLink,
    PublishedFileOpen,
    PublishedFileBinding,
    PublishedDirectorySync,
    CommitFailpoint,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observation {
    site: Option<ObjectIoSite>,
    private_error: Option<PrivateStorageError>,
    kind: Option<io::ErrorKind>,
    errno: Option<i32>,
}

thread_local! {
    // None means no acknowledgement is being observed on this thread.
    static FIRST: Cell<Option<Option<Observation>>> = const { Cell::new(None) };
    // Scoped to one singleton call. A second mapped error leaves attribution ambiguous.
    static ADMISSION: Cell<Option<AdmissionResult>> = const { Cell::new(None) };
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
        facts.report(iteration)
    }
}

impl Observation {
    pub(crate) fn admission(site: ObjectIoSite, error: PrivateStorageError) -> Self {
        let (kind, errno) = match error {
            PrivateStorageError::Admission(failure) => (failure.kind, failure.raw_os_error),
            _ => (None, None),
        };
        Self { site: Some(site), private_error: Some(error), kind, errno }
    }

    fn report(self, iteration: u64) -> String {
        let admission = match self.private_error {
            Some(PrivateStorageError::Admission(failure)) => Some(failure),
            _ => None,
        };
        let error = match self.private_error {
            Some(PrivateStorageError::Admission(_)) => "Admission",
            Some(PrivateStorageError::Unavailable) => "Unavailable",
            Some(PrivateStorageError::InvalidName) => "InvalidName",
            Some(PrivateStorageError::AlreadyExists) => "AlreadyExists",
            Some(PrivateStorageError::Operation) => "Operation",
            None => "unavailable",
        };
        format!(
            "iteration={iteration} operation={:?} error={error} admission={:?} kind={:?} errno={:?} context={}",
            Available(self.site),
            Available(admission.map(|failure| failure.operation)),
            Available(self.kind),
            Available(self.errno),
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

#[derive(Clone, Copy, Default)]
enum AdmissionResult {
    #[default]
    NoError,
    One(CorrelationId, Option<Observation>),
    Ambiguous,
}

pub(crate) fn returned_error(id: CorrelationId, facts: Option<Observation>) {
    ADMISSION.with(|slot| {
        slot.set(slot.get().map(|previous| match previous {
            AdmissionResult::NoError => AdmissionResult::One(id, facts),
            _ => AdmissionResult::Ambiguous,
        }))
    });
}

pub(crate) fn observe_acknowledgement<T>(
    iteration: u64,
    call: impl FnOnce() -> Result<T, xtrace_application::PortError>,
    fail: impl FnOnce(&'static str, String),
) -> Result<T, xtrace_application::PortError> {
    struct Restore(Option<AdmissionResult>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ADMISSION.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(ADMISSION.with(|slot| slot.replace(Some(AdmissionResult::NoError))));
    let result = call();
    if let Err(error) = &result
        && let Some(code) = match error.message().split_once(": ").map(|(code, _)| code) {
            Some("XTR-PRIVATE-STORAGE-UNAVAILABLE") => Some("admission"),
            Some("XTR-STORE-OBJECT-IO") => Some("object io"),
            _ => None,
        }
    {
        let facts = match ADMISSION.with(Cell::get) {
            Some(AdmissionResult::One(id, facts)) if id == error.correlation_id() => facts,
            _ => None,
        };
        fail(code, facts.unwrap_or_default().report(iteration));
    }
    result
}

pub(super) fn admission<T>(
    site: ObjectIoSite,
    id: CorrelationId,
    mapped_error: fn(CorrelationId) -> RecordingStoreError,
    call: impl FnOnce() -> Result<T, PrivateStorageError>,
) -> Result<T, RecordingStoreError> {
    call().map_err(|error| {
        let mut mapped = mapped_error(id);
        mapped.admission_facts = Some(Observation::admission(site, error));
        mapped
    })
}

pub(super) fn private<T>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    mapped_error: fn(CorrelationId) -> RecordingStoreError,
    call: impl FnOnce() -> Result<T, PrivateStorageError>,
) -> Result<T, RecordingStoreError> {
    if !FIRST.with(|slot| matches!(slot.get(), Some(None))) {
        // The singleton observer attaches the returned error's own facts. A
        // generic private error has no causal errno once the call returns.
        return call().map_err(|error| {
            let mut mapped = mapped_error(correlation_id);
            mapped.admission_facts = Some(Observation::admission(site, error));
            mapped
        });
    }
    let (result, discarded) = PrivateStorageError::with_io_diagnostic(call);
    result.map_err(|error| {
        let (kind, errno) = match error {
            PrivateStorageError::Admission(failure) => (failure.kind, failure.raw_os_error),
            _ => discarded.map_or((None, None), |(kind, errno)| (Some(kind), errno)),
        };
        let mut mapped = mapped_error(correlation_id);
        // The legacy first-observed report may use the call-scoped discarded
        // I/O signal. The correlated returned error uses only owned facts.
        mapped.admission_facts = Some(Observation::admission(site, error));
        observe(Observation { site: Some(site), private_error: Some(error), kind, errno });
        mapped
    })
}

pub(super) fn direct<T, E: Into<io::Error>>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    mapped_error: fn(CorrelationId) -> RecordingStoreError,
    call: impl FnOnce() -> Result<T, E>,
) -> Result<T, RecordingStoreError> {
    call().map_err(|error| {
        let error = error.into();
        attach(
            mapped_error(correlation_id),
            Observation {
                site: Some(site),
                kind: Some(error.kind()),
                errno: error.raw_os_error(),
                ..Observation::default()
            },
        )
    })
}

pub(super) fn missing<T, E>(
    site: ObjectIoSite,
    correlation_id: CorrelationId,
    mapped_error: fn(CorrelationId) -> RecordingStoreError,
    call: impl FnOnce() -> Result<T, E>,
) -> Result<T, RecordingStoreError> {
    call().map_err(|_| {
        attach(
            mapped_error(correlation_id),
            Observation { site: Some(site), ..Observation::default() },
        )
    })
}

fn attach(mut error: RecordingStoreError, facts: Observation) -> RecordingStoreError {
    observe(facts);
    error.admission_facts = Some(facts);
    error
}

pub(super) fn observe_failpoint() {
    observe(Observation { site: Some(ObjectIoSite::CommitFailpoint), ..Observation::default() });
}

#[cfg(test)]
mod tests {
    use super::super::{
        COMMIT_FAILPOINT, COMMIT_FAILPOINT_FIRED, atomic_install_error, commit_failpoint,
        object_io_error,
    };
    use super::*;
    use xtrace_private_storage::AdmissionOperation;

    #[test]
    fn first_object_io_survives_cleanup_and_other_threads_and_resets() {
        let inject = |site, error| {
            let id = CorrelationId::new();
            let result = direct(site, id, object_io_error, || Err::<(), _>(error));
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
    fn atomic_install_reports_the_syscall_kind_without_paths_or_changing_the_error_code() {
        let scope = Scope::enter();
        let result = direct(
            ObjectIoSite::PublishHardLink,
            CorrelationId::new(),
            atomic_install_error,
            || Err::<(), _>(io::Error::new(io::ErrorKind::PermissionDenied, "/private/path")),
        );
        assert!(matches!(result, Err(error) if error.code() == "XTR-STORE-ATOMIC-INSTALL"
            && error.kind() == super::super::RecordingStoreErrorKind::Compatibility));
        assert_eq!(
            scope.report(1),
            "iteration=1 operation=PublishHardLink error=unavailable admission=unavailable kind=PermissionDenied errno=unavailable context=unavailable"
        );
    }

    #[test]
    fn handled_or_unrelated_refusals_cannot_supply_a_singleton_failure() {
        use xtrace_application::{PortError, PortErrorKind};
        let id = CorrelationId::new();
        let failure = || {
            PortError::new(
                PortErrorKind::Validation,
                "XTR-PRIVATE-STORAGE-UNAVAILABLE: refused",
                id,
            )
        };
        let facts =
            Observation::admission(ObjectIoSite::BindingRootOpen, PrivateStorageError::InvalidName);
        for (events, known) in [
            (vec![(id, Some(facts))], true),
            (vec![], false),
            (vec![(CorrelationId::new(), Some(facts))], false),
            (vec![(id, Some(facts)), (id, None)], false),
        ] {
            let mut report = String::new();
            let result = observe_acknowledgement(
                131_072,
                || {
                    for (id, observation) in events {
                        returned_error(id, observation);
                    }
                    Err::<(), _>(failure())
                },
                |code, line| {
                    assert_eq!(code, "admission");
                    report = line;
                },
            );
            assert!(result.is_err());
            assert_eq!(report.contains("operation=BindingRootOpen error=InvalidName"), known);
            assert_eq!(report.contains("operation=unavailable error=unavailable"), !known);
            assert!(report.starts_with("iteration=131072 "));
        }
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
            let result = private(ObjectIoSite::StagingProjectRootOpen, id, object_io_error, || {
                Err::<(), _>(PrivateStorageError::Admission(failure))
            });
            assert!(matches!(result, Err(error) if error.code() == "XTR-STORE-OBJECT-IO"));
            assert_eq!(
                scope.report(1),
                "iteration=1 operation=StagingProjectRootOpen error=Admission admission=NamedMetadata kind=PermissionDenied errno=unavailable context=unavailable"
            );
        }

        let scope = Scope::enter();
        let result = private(ObjectIoSite::StageFileParentSync, id, object_io_error, || {
            Err::<(), _>(PrivateStorageError::Operation)
        });
        assert!(matches!(result, Err(error) if error.code() == "XTR-STORE-OBJECT-IO"));
        assert_eq!(
            scope.report(1),
            "iteration=1 operation=StageFileParentSync error=Operation admission=unavailable kind=unavailable errno=unavailable context=unavailable"
        );
    }
}
