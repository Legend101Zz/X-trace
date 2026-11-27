//! Project-scoped durable plan adapter shared by CLI commands and the foreground viewer.

mod edit;

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

/// A capability constructed from a validated local project. No HTTP field
/// selects a directory, catalog connection, or project identity.
pub(crate) struct ExerciseProject {
    id: ProjectId,
    root: AdmittedPrivateRoot,
    catalog: SqliteStore,
}

impl ExerciseProject {
    pub(crate) fn new(id: ProjectId, root: AdmittedPrivateRoot, catalog: SqliteStore) -> Self {
        Self { id, root, catalog }
    }

    pub(crate) fn provenance_store(&self) -> xtrace_store::SqliteExerciseProvenanceStore {
        xtrace_store::SqliteExerciseProvenanceStore::new(self.catalog.clone())
    }

    pub(crate) fn open(
        &self,
        create_directory: bool,
    ) -> Result<PrivateExerciseStore, xtrace_private_storage::PrivateStorageError> {
        let plans = if create_directory {
            self.root.open_or_create_private_child("exercise-plans")?
        } else {
            self.root.open_private_child("exercise-plans")?
        };
        Ok(PrivateExerciseStore {
            project: self.id,
            plans,
            catalog: self.catalog.clone(),
            project_data_root: self.root.path().to_owned(),
        })
    }

    /// Invoked on the viewer's bounded worker only after session authorization.
    /// Reading or editing an unknown plan cannot create a plans directory.
    pub(crate) fn handle_viewer_action(
        &self,
        action: xtrace_daemon::ViewerExerciseAction,
    ) -> Result<serde_json::Value, ExerciseError> {
        use crate::exercise::trusted_now;
        use xtrace_application::exercise::{ExercisePlanService, review_document};
        use xtrace_daemon::ViewerExerciseAction as Action;

        let store = self
            .open(matches!(action, Action::Create(_)))
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        let service = ExercisePlanService::new(store);
        let plan = match action {
            Action::Create(request) => service.create(self.id, request, trusted_now()?)?,
            Action::Edit { hash, replacement } => {
                service.edit(self.id, &hash, replacement, trusted_now()?)?
            }
            Action::Show { hash } => service.show(self.id, &hash)?,
            Action::Review { hash } => service.review(self.id, &hash, trusted_now()?)?,
            Action::Approve { hash, plan_id, item_ids, confirm_owned_development } => {
                let current = service.show(self.id, &hash)?;
                if current.content.plan_id != plan_id {
                    return Err(ExerciseError::HashMismatch);
                }
                service.approve(
                    self.id,
                    &hash,
                    &item_ids,
                    confirm_owned_development,
                    trusted_now()?,
                )?
            }
        };
        review_document(&plan, trusted_now()?)
    }
}

/// All command and viewer writes serialize through the same project lock.
pub(crate) struct PrivateExerciseStore {
    project: ProjectId,
    plans: AdmittedPrivateRoot,
    catalog: SqliteStore,
    project_data_root: std::path::PathBuf,
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
        self.recover_edit()?;
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
        let plan = match serde_json::from_slice::<StoredExercisePlan>(&bytes) {
            Ok(plan) => {
                if matches!(
                    plan.phase,
                    xtrace_application::exercise::ExercisePhase::Superseded { .. }
                ) {
                    return Err(ExerciseError::StorageUnavailable);
                }
                self.check_incoming_edit(&plan)?;
                plan
            }
            Err(_) => self.read_revocation(&bytes)?,
        };
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

    fn supersede(
        &self,
        predecessor: &StoredExercisePlan,
        replacement: &StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        self.locked(|| self.commit_edit(predecessor, replacement, crate::exercise::trusted_now))
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
            if matches!(
                previous.phase,
                xtrace_application::exercise::ExercisePhase::Superseded { .. }
            ) {
                return Err(ExerciseError::Superseded);
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
                supersedes: None,
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

    const EXERCISE_SCRATCH_SLOTS: usize = 16;

    static EXERCISE_SLOTS: std::sync::OnceLock<Vec<AdmittedPrivateRoot>> =
        std::sync::OnceLock::new();
    static NEXT_EXERCISE_SLOT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// Pre-allocate exclusive private slots before any test starts so sibling tests never
    /// mutate shared `TMPDIR`/`XTRACE_TEST_PRIVATE_SCRATCH` metadata (`nlink`/`mtime`) during
    /// another test's `AdmittedPrivateRoot` ancestor walk.
    fn init_exercise_slots() -> Vec<AdmittedPrivateRoot> {
        use std::os::unix::fs::PermissionsExt as _;
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let family_name = format!("xt-ex-plan-{}-{nanos}", std::process::id());
        let family = if let Some(scratch) = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH") {
            let root = AdmittedPrivateRoot::open(std::path::Path::new(&scratch))
                .expect("admitted private test scratch");
            root.create_private_child(&family_name).expect("private exercise test family")
        } else {
            let path = std::env::temp_dir().join(&family_name);
            std::fs::create_dir(&path).expect("create exercise test family");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("chmod exercise test family");
            AdmittedPrivateRoot::open(&path).expect("admitted exercise test family")
        };
        (0..EXERCISE_SCRATCH_SLOTS)
            .map(|slot| {
                family
                    .create_private_child(&format!("s{slot:02}"))
                    .expect("pre-allocated private exercise test slot")
            })
            .collect()
    }

    fn private_store() -> Arc<PrivateExerciseStore> {
        let slots = EXERCISE_SLOTS.get_or_init(init_exercise_slots);
        let index = NEXT_EXERCISE_SLOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(
            index < slots.len(),
            "exercise_store::tests::EXERCISE_SCRATCH_SLOTS ({EXERCISE_SCRATCH_SLOTS}) exhausted"
        );
        let admitted = &slots[index];
        let catalog = SqliteStore::open(
            &admitted.path().join("metadata.sqlite3"),
            xtrace_store::OpenOptions::default(),
        )
        .unwrap();
        let project = ProjectId::new();
        Arc::new(PrivateExerciseStore {
            project,
            plans: admitted.create_private_child("exercise-plans").unwrap(),
            catalog,
            project_data_root: admitted.path().into(),
        })
    }

    struct EditClockFixture<'a> {
        store: &'a PrivateExerciseStore,
        binding: ExerciseOperationBinding,
        before: u64,
        after: u64,
    }

    impl ExercisePlanPort for EditClockFixture<'_> {
        fn observed_binding(
            &self,
            project: ProjectId,
            _request: &CreateExercisePlan,
        ) -> Result<ExerciseOperationBinding, ExerciseError> {
            self.store.check_project(project)?;
            Ok(self.binding.clone())
        }

        fn insert(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
            self.store.insert(plan)
        }

        fn load(
            &self,
            project: ProjectId,
            hash: &str,
        ) -> Result<StoredExercisePlan, ExerciseError> {
            self.store.load(project, hash)
        }

        fn replace(
            &self,
            project: ProjectId,
            hash: &str,
            revision: u64,
            next: &StoredExercisePlan,
        ) -> Result<(), ExerciseError> {
            self.store.replace(project, hash, revision, next)
        }

        fn supersede(
            &self,
            previous: &StoredExercisePlan,
            next: &StoredExercisePlan,
        ) -> Result<(), ExerciseError> {
            let times = std::cell::Cell::new(self.before);
            self.store
                .locked(|| self.store.commit_edit(previous, next, || Ok(times.replace(self.after))))
        }
    }

    #[test]
    fn edit_expiry_on_each_side_of_the_commit_never_acknowledges_or_rearms_consent() {
        for expire_before_commit in [true, false] {
            let store = private_store();
            let sample = stored(store.project).content;
            let now = sample.created_at;
            let expiry = sample.expires_at;
            let service = ExercisePlanService::new(EditClockFixture {
                store: &store,
                binding: sample.binding,
                before: if expire_before_commit { expiry } else { now },
                after: expiry,
            });
            let original = service.create(store.project, sample.request.clone(), now).unwrap();
            service.review(store.project, &original.plan_hash, now).unwrap();
            let item = review_document(&original, now).unwrap()["preview"]["items"][0]["item_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let approved =
                service.approve(store.project, &original.plan_hash, &[item], true, now).unwrap();
            assert_eq!(
                service.edit(store.project, &original.plan_hash, sample.request, now),
                Err(ExerciseError::Expired)
            );
            let current = service.show(store.project, &original.plan_hash).unwrap();
            if expire_before_commit {
                assert_eq!(current, approved);
            } else {
                let view = review_document(&current, now).unwrap();
                assert_eq!(view["phase"]["phase"], "superseded");
                assert_eq!(
                    view["phase"]["previous"],
                    serde_json::to_value(&approved.phase).unwrap()
                );
                let replacement = service
                    .show(store.project, view["phase"]["replacement_hash"].as_str().unwrap())
                    .unwrap();
                assert!(matches!(replacement.phase, ExercisePhase::Draft {}));
                assert_eq!(
                    service.consume_once(store.project, &original.plan_hash, now),
                    Err(ExerciseError::Superseded)
                );
            }
        }
    }

    #[test]
    fn expiry_during_staging_cleans_only_owned_staging_and_never_rolls_back_published_state() {
        use std::cell::Cell;
        let store = private_store();
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
        let store = private_store();
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
        let store = private_store();
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
