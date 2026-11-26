//! CLI adapter for owner-private immutable plans and atomic lifecycle updates.

use std::io::Write as _;

use xtrace_application::catalog_discovery::history::CatalogHistoryService;
use xtrace_application::exercise::{
    CreateExercisePlan, ExerciseError, ExerciseOperationBinding, ExercisePlanPort,
    MAX_PLAN_DOCUMENT_BYTES, SelectedCatalogOperation, StoredExercisePlan,
};
use xtrace_application::observed_endpoint_queries::{
    ObservedEndpointReadPort, ObservedRecordingKey,
};
use xtrace_domain::ProjectId;
use xtrace_private_storage::AdmittedPrivateRoot;
use xtrace_store::SqliteStore;
use xtrace_store::catalog_history_store::SqliteCatalogHistoryStore;
use xtrace_store::recording_port::SqliteRecordingReader;

// The project-wide lifecycle lock admits one writer. A crash can strand at most
// one staging file; the next writer refuses it without truncating or unlinking it.
const STAGING: &str = "pending-lifecycle.json";

/// The only local durable adapter in this slice. Viewer wiring is separate.
pub(crate) struct PrivateExerciseStore {
    pub(crate) project: ProjectId,
    pub(crate) plans: AdmittedPrivateRoot,
    pub(crate) catalog: SqliteStore,
    pub(crate) project_data_root: std::path::PathBuf,
}

impl PrivateExerciseStore {
    fn check_project(&self, project: ProjectId) -> Result<(), ExerciseError> {
        if project != self.project {
            return Err(ExerciseError::NotFound);
        }
        Ok(())
    }

    fn locked<T>(
        &self,
        action: impl FnOnce() -> Result<T, ExerciseError>,
    ) -> Result<T, ExerciseError> {
        let lock = self
            .plans
            .open_or_create_private_file("lifecycle.lock")
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => {}
            Err(fs4::TryLockError::WouldBlock) => return Err(ExerciseError::Conflict),
            Err(fs4::TryLockError::Error(_)) => return Err(ExerciseError::StorageUnavailable),
        }
        self.plans
            .validate_file_binding("lifecycle.lock", &lock, false)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        let result = action();
        self.plans
            .validate_file_binding("lifecycle.lock", &lock, false)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        self.plans.revalidate().map_err(|_| ExerciseError::StorageUnavailable)?;
        // Descriptor drop releases the advisory lock on every success/error path.
        result
    }

    fn read(&self, project: ProjectId, hash: &str) -> Result<StoredExercisePlan, ExerciseError> {
        self.check_project(project)?;
        let name = filename(hash)?;
        if !self
            .plans
            .validate_optional_private_file(&name)
            .map_err(|_| ExerciseError::StorageUnavailable)?
        {
            return Err(ExerciseError::NotFound);
        }
        let bytes = self
            .plans
            .read_bounded_file(&name, MAX_PLAN_DOCUMENT_BYTES)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        let plan: StoredExercisePlan =
            serde_json::from_slice(&bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
        if plan.content.binding.project_id != project || plan.plan_hash != hash {
            return Err(ExerciseError::HashMismatch);
        }
        Ok(plan)
    }

    fn publish(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
        self.publish_with_clock(plan, crate::exercise::trusted_now)
    }

    fn publish_with_clock(
        &self,
        plan: &StoredExercisePlan,
        clock: impl Fn() -> Result<u64, ExerciseError>,
    ) -> Result<(), ExerciseError> {
        let bytes = serde_json::to_vec(plan).map_err(|_| ExerciseError::InvalidInput)?;
        if bytes.len() > MAX_PLAN_DOCUMENT_BYTES {
            return Err(ExerciseError::InvalidInput);
        }
        let mut file = self.plans.create_private_file(STAGING).map_err(|error| match error {
            xtrace_private_storage::PrivateStorageError::AlreadyExists => {
                ExerciseError::StagingOccupied
            }
            _ => ExerciseError::StorageUnavailable,
        })?;
        let mut publish = || -> Result<(), ExerciseError> {
            file.write_all(&bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
            file.sync_all().map_err(|_| ExerciseError::StorageUnavailable)?;
            self.plans
                .validate_file_binding(STAGING, &file, true)
                .map_err(|_| ExerciseError::StorageUnavailable)?;
            let before = clock()?;
            plan.ensure_active_at(before)?;
            // This admitted rename includes the directory fsync. An error after
            // rename is ambiguous, so never remove or restore the destination.
            self.plans
                .rename_replace(STAGING, &filename(&plan.plan_hash)?)
                .map_err(|_| ExerciseError::StorageUnavailable)?;
            let after = clock()?;
            if after < before {
                return Err(ExerciseError::Expired);
            }
            plan.ensure_active_at(after)
        };
        let result = publish();
        if result.is_err()
            && self
                .plans
                .validate_optional_private_file(STAGING)
                .map_err(|_| ExerciseError::StorageUnavailable)?
        {
            self.plans
                .remove_private_file_if_matches(STAGING, &file)
                .map_err(|_| ExerciseError::StorageUnavailable)?;
            self.plans.sync().map_err(|_| ExerciseError::StorageUnavailable)?;
        }
        result
    }
}

fn filename(hash: &str) -> Result<String, ExerciseError> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ExerciseError::InvalidInput);
    }
    Ok(format!("{hash}.json"))
}

impl ExercisePlanPort for PrivateExerciseStore {
    fn observed_binding(
        &self,
        project: ProjectId,
        request: &CreateExercisePlan,
    ) -> Result<ExerciseOperationBinding, ExerciseError> {
        self.check_project(project)?;
        let history =
            CatalogHistoryService::new(SqliteCatalogHistoryStore::new(self.catalog.clone()));
        let (revision, operations) = history
            .operations(project, Some(request.revision_id))
            .map_err(|_| ExerciseError::BindingUnavailable)?;
        let operation = operations
            .iter()
            .find(|op| op.operation_id == request.operation_id)
            .ok_or(ExerciseError::BindingUnavailable)?;
        let reader = SqliteRecordingReader::new(self.catalog.clone(), &self.project_data_root);
        let mut after = None;
        let mut linked = false;
        // Bounded keyset lookup: if evidence lies beyond 10,000 rows this adapter
        // reports unavailable, never guesses or calls it unobserved. A direct
        // indexed binding query can replace this adapter in the viewer slice.
        for _ in 0..200 {
            let (rows, has_more) = reader
                .list_operation_recordings(project, request.operation_id, after.as_ref(), 50)
                .map_err(|_| ExerciseError::BindingUnavailable)?;
            if rows.iter().any(|r| {
                r.metadata.recording_id == request.recording_id
                    && r.operation_id == Some(request.operation_id)
            }) {
                linked = true;
                break;
            }
            if !has_more {
                break;
            }
            let last = rows.last().ok_or(ExerciseError::BindingUnavailable)?;
            after = Some(ObservedRecordingKey {
                opened_at: last.metadata.opened_at.clone(),
                recording_id: last.metadata.recording_id,
            });
        }
        if !linked {
            return Err(ExerciseError::BindingUnavailable);
        }
        let catalog =
            serde_json::to_vec(&operations).map_err(|_| ExerciseError::BindingUnavailable)?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"xtrace.exercise.catalog-projection.v1\0");
        digest.update(&catalog);
        Ok(ExerciseOperationBinding {
            project_id: project,
            operation_id: request.operation_id,
            recording_id: request.recording_id,
            selected_catalog: SelectedCatalogOperation {
                revision_id: revision.revision_id,
                catalog_hash: digest.finalize().to_hex().to_string(),
                operation_version_id: operation.operation_version_id.clone(),
                application_component: operation.application_component.clone(),
                binding_key: operation.binding_key.clone(),
                method: operation.method.clone(),
                route_template: operation.route_template.clone(),
                conflicted: operation.handler_conflict,
            },
        })
    }

    fn insert(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
        self.check_project(plan.content.binding.project_id)?;
        self.locked(|| {
            if self
                .plans
                .validate_optional_private_file(&filename(&plan.plan_hash)?)
                .map_err(|_| ExerciseError::StorageUnavailable)?
            {
                return Err(ExerciseError::Conflict);
            }
            self.publish(plan)
        })
    }

    fn load(&self, project: ProjectId, hash: &str) -> Result<StoredExercisePlan, ExerciseError> {
        self.locked(|| self.read(project, hash))
    }

    fn replace(
        &self,
        project: ProjectId,
        hash: &str,
        expected_revision: u64,
        next: &StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        self.locked(|| {
            let previous = self.read(project, hash)?;
            if previous.revision != expected_revision
                || previous.content != next.content
                || next.plan_hash != hash
                || expected_revision.checked_add(1) != Some(next.revision)
            {
                return Err(ExerciseError::Conflict);
            }
            self.publish(next)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "checked private filesystem fixtures")]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use xtrace_application::exercise::*;
    use xtrace_domain::{CatalogRevisionId, OperationId, RecordingId};

    fn stored(project: ProjectId) -> StoredExercisePlan {
        let revision_id = CatalogRevisionId::new();
        let operation_id = OperationId::new();
        let recording_id = RecordingId::new();
        let now = crate::exercise::trusted_now().unwrap();
        StoredExercisePlan {
            content: ExercisePlanContent {
                schema_version: 1,
                plan_id: uuid::Uuid::now_v7().to_string(),
                binding: ExerciseOperationBinding {
                    project_id: project,
                    operation_id,
                    recording_id,
                    selected_catalog: SelectedCatalogOperation {
                        revision_id,
                        catalog_hash: "ab".repeat(32),
                        operation_version_id: "v1".into(),
                        application_component: "storage-fixture".into(),
                        binding_key: "default".into(),
                        method: "GET".into(),
                        route_template: "/orders".into(),
                        conflicted: false,
                    },
                },
                request: CreateExercisePlan {
                    selected_operation_version_id: "v1".into(),
                    revision_id,
                    operation_id,
                    recording_id,
                    target: DevelopmentTarget {
                        base_url: "http://127.0.0.1:8080".into(),
                        operator_owned_development: true,
                    },
                    inputs: vec![],
                    body: ExerciseBody::EmptyByOperator {},
                    lifetime_seconds: 900,
                },
                created_at: now,
                expires_at: now + 900,
                bounds: ExecutionBounds::default(),
            },
            // The port fixture tests atomic publication, not service hashing.
            plan_hash: "a".repeat(64),
            revision: 0,
            phase: ExercisePhase::Draft {},
        }
    }

    fn private_store() -> (tempfile::TempDir, Arc<PrivateExerciseStore>) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::Builder::new()
            .prefix("xt-ex-plan-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(std::env::temp_dir())
            .unwrap();
        let admitted = AdmittedPrivateRoot::open(root.path()).unwrap();
        let catalog = SqliteStore::open(
            &root.path().join("metadata.sqlite3"),
            xtrace_store::OpenOptions::default(),
        )
        .unwrap();
        let project = ProjectId::new();
        let store = Arc::new(PrivateExerciseStore {
            project,
            plans: admitted.create_private_child("exercise-plans").unwrap(),
            catalog,
            project_data_root: root.path().into(),
        });
        (root, store)
    }

    #[test]
    fn expiry_during_staging_cleans_only_owned_staging_and_never_rolls_back_published_state() {
        use std::cell::Cell;
        let (_root, store) = private_store();
        let original = stored(store.project);
        let mut next = original.clone();
        next.revision = 3;
        next.phase = ExercisePhase::Consumed { consumed_at: original.content.created_at };
        store.insert(&original).unwrap();
        let expired = original.content.expires_at;
        assert_eq!(
            store.locked(|| store.publish_with_clock(&next, || Ok(expired))),
            Err(ExerciseError::Expired)
        );
        assert_eq!(store.load(store.project, &original.plan_hash).unwrap(), original);
        let clock = Cell::new(expired - 1);
        assert_eq!(
            store.locked(|| store.publish_with_clock(&next, || Ok(clock.replace(expired)))),
            Err(ExerciseError::Expired)
        );
        assert_eq!(store.load(store.project, &original.plan_hash).unwrap(), next);
        assert!(
            std::fs::read_dir(store.plans.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("pending-"))
        );
    }

    #[test]
    fn occupied_staging_blocks_writes_until_owner_preserves_it() {
        let (_root, store) = private_store();
        let unique = "unrelated-private.json";
        let mut other = store.plans.create_private_file(unique).unwrap();
        other.write_all(b"untouched").unwrap();
        drop(other);
        let mut interrupted = store.plans.create_private_file(STAGING).unwrap();
        interrupted.write_all(b"partial-private-content").unwrap();
        interrupted.sync_all().unwrap();
        drop(interrupted);
        let original = stored(store.project);
        for _ in 0..2 {
            assert_eq!(store.insert(&original), Err(ExerciseError::StagingOccupied));
            assert_eq!(
                store.load(store.project, &original.plan_hash),
                Err(ExerciseError::NotFound)
            );
            assert_eq!(
                store.plans.read_bounded_file(STAGING, 64).unwrap(),
                b"partial-private-content"
            );
        }
        // Simulate explicit owner recovery while there is no writer.
        let saved = "owner-preserved-staging.json";
        std::fs::rename(store.plans.path().join(STAGING), store.plans.path().join(saved)).unwrap();
        store.insert(&original).unwrap();
        assert_eq!(store.load(store.project, &original.plan_hash).unwrap(), original);
        assert_eq!(store.plans.read_bounded_file(saved, 64).unwrap(), b"partial-private-content");
        assert_eq!(store.plans.read_bounded_file(unique, 64).unwrap(), b"untouched");
    }

    #[test]
    fn actual_private_port_refuses_contending_and_stale_revision_writers() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_root, store) = private_store();
        let project = store.project;
        let original = stored(project);
        store.insert(&original).unwrap();
        let mut next = original.clone();
        next.revision = 1;
        next.phase = ExercisePhase::Consumed { consumed_at: original.content.created_at };
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer_store = Arc::clone(&store);
        let writer_next = next.clone();
        let contested = std::thread::scope(|scope| {
            let writer = scope.spawn(move || {
                writer_store.locked(|| {
                    // Signal after admission/lock, before any namespace mutation, so
                    // the contender observes the actual lock without timing sleeps.
                    ready_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    writer_store.publish(&writer_next)
                })
            });
            ready_rx.recv().unwrap();
            let contested = store.replace(project, &original.plan_hash, 0, &next);
            release_tx.send(()).unwrap();
            writer.join().unwrap().unwrap();
            contested
        });
        assert_eq!(contested, Err(ExerciseError::Conflict));
        let read_back = store.load(project, &original.plan_hash).unwrap();
        assert_eq!(read_back.revision, 1);
        assert!(matches!(read_back.phase, ExercisePhase::Consumed { .. }));
        assert_eq!(
            store.replace(project, &original.plan_hash, 0, &original),
            Err(ExerciseError::Conflict)
        );
        assert_eq!(store.load(ProjectId::new(), &original.plan_hash), Err(ExerciseError::NotFound));
        let file = store.plans.path().join(filename(&original.plan_hash).unwrap());
        assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
