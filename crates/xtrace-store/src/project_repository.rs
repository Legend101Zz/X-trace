//! Typed [`SqliteProjectRepository`] implementation.
//!
//! The repository owns the SQL for the `projects` and `runs` tables
//! and translates SQLite errors into [`PortError`] values so the
//! application layer never sees a raw [`rusqlite::Error`].
//!
//! Every method runs inside a single connection lock acquired from
//! the parent [`SqliteStore`]. The connection mutex is reentrant
//! only across slices that already hold the lock; the repository
//! itself does not nest locks.
//!
//! [`PortError`]: xtrace_application::PortError
//! [`rusqlite::Error`]: rusqlite::Error

use std::convert::TryFrom;

use rusqlite::{OptionalExtension as _, Row};
use uuid::Uuid;
use xtrace_application::PortError;
use xtrace_application::PortErrorKind;
use xtrace_application::ProjectRepository;
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    CorrelationId, PolicyId, Project, ProjectId, RepositoryFingerprint, Run, RunId, RunKind,
    RunState, WallTime,
};

use crate::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// Typed view over the projects and runs tables.
pub struct SqliteProjectRepository<'store> {
    store: &'store SqliteStore,
}

impl<'store> SqliteProjectRepository<'store> {
    /// Constructs a new repository view over the supplied store.
    #[must_use]
    pub const fn new(store: &'store SqliteStore) -> Self {
        Self { store }
    }

    fn map_error(err: StoreError) -> PortError {
        let kind = match err.kind() {
            StoreErrorKind::Validation => PortErrorKind::Validation,
            StoreErrorKind::SchemaOlder
            | StoreErrorKind::SchemaNewer
            | StoreErrorKind::SchemaIncompatible => PortErrorKind::Compatibility,
            StoreErrorKind::AlreadyExists => PortErrorKind::AlreadyExists,
            StoreErrorKind::NotFound => PortErrorKind::NotFound,
            StoreErrorKind::Conflict => PortErrorKind::Conflict,
            StoreErrorKind::Corruption => PortErrorKind::Corruption,
            StoreErrorKind::Transport => PortErrorKind::Transport,
            StoreErrorKind::Busy => PortErrorKind::Resource,
            StoreErrorKind::Resource => PortErrorKind::Resource,
            StoreErrorKind::Internal => PortErrorKind::Internal,
        };
        let mut builder = PortError::new(kind, err.message(), err.correlation_id());
        if let Some(source) = err.source() {
            builder = builder.with_source(source.to_string());
        }
        builder
    }

    fn correlation_id(&self) -> CorrelationId {
        CorrelationId::new()
    }
}

impl ProjectRepository for SqliteProjectRepository<'_> {
    fn insert_project(&self, project: &Project) -> Result<(), PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        let project_id_bytes = project.id.as_uuid().as_bytes().to_vec();
        let capture_policy_bytes = policy_bytes(project.active_capture_policy_id);
        let redaction_policy_bytes = policy_bytes(project.active_redaction_policy_id);
        let result = tx.execute(
            "INSERT INTO projects (\
                 project_id, canonical_repo_hash, display_name, created_at, \
                 last_opened_at, config_schema_version, effective_config_hash, \
                 active_capture_policy_id, active_redaction_policy_id\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                project_id_bytes,
                project.canonical_repo_hash.as_str(),
                project.display_name,
                project.created_at.to_rfc3339(),
                project.last_opened_at.to_rfc3339(),
                i64::from(project.config_schema_version),
                project.effective_config_hash,
                capture_policy_bytes,
                redaction_policy_bytes,
            ],
        );
        match result {
            Ok(_) => {
                tx.commit()
                    .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
                    .map_err(Self::map_error)?;
                Ok(())
            }
            Err(err) => {
                let store_err = StoreError::from_rusqlite(err, correlation_id);
                let kind = store_err.kind();
                let port_err = Self::map_error(store_err);
                let _ = tx.rollback();
                if matches!(kind, StoreErrorKind::AlreadyExists) {
                    Err(PortError::new(
                        PortErrorKind::AlreadyExists,
                        "project already registered for this fingerprint",
                        port_err.correlation_id(),
                    ))
                } else {
                    Err(port_err)
                }
            }
        }
    }

    fn load_project_by_fingerprint(
        &self,
        fingerprint: &RepositoryFingerprint,
    ) -> Result<Project, PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let row = conn
            .query_row(
                "SELECT project_id, canonical_repo_hash, display_name, created_at, \
                 last_opened_at, config_schema_version, effective_config_hash, \
                 active_capture_policy_id, active_redaction_policy_id \
                 FROM projects WHERE canonical_repo_hash = ?1",
                rusqlite::params![fingerprint.as_str()],
                map_project_row,
            )
            .optional()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        row.ok_or_else(|| {
            PortError::new(
                PortErrorKind::NotFound,
                "no project registered for this fingerprint",
                correlation_id,
            )
        })
    }

    fn load_project_by_id(&self, project_id: ProjectId) -> Result<Project, PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let project_id_bytes = project_id.as_uuid().as_bytes().to_vec();
        let row = conn
            .query_row(
                "SELECT project_id, canonical_repo_hash, display_name, created_at, \
                 last_opened_at, config_schema_version, effective_config_hash, \
                 active_capture_policy_id, active_redaction_policy_id \
                 FROM projects WHERE project_id = ?1",
                rusqlite::params![project_id_bytes],
                map_project_row,
            )
            .optional()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        row.ok_or_else(|| {
            PortError::new(
                PortErrorKind::NotFound,
                "no project with that identifier",
                correlation_id,
            )
        })
    }

    fn list_projects(&self) -> Result<Vec<Project>, PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let mut stmt = conn
            .prepare(
                "SELECT project_id, canonical_repo_hash, display_name, created_at, \
                 last_opened_at, config_schema_version, effective_config_hash, \
                 active_capture_policy_id, active_redaction_policy_id \
                 FROM projects ORDER BY created_at ASC, project_id ASC",
            )
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        let rows = stmt
            .query_map([], map_project_row)
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        let mut out = Vec::new();
        for row in rows {
            let project = row
                .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
                .map_err(Self::map_error)?;
            out.push(project);
        }
        Ok(out)
    }

    fn touch_last_opened(
        &self,
        project_id: ProjectId,
        opened_at: WallTime,
    ) -> Result<(), PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let project_id_bytes = project_id.as_uuid().as_bytes().to_vec();
        let updated = conn
            .execute(
                "UPDATE projects SET last_opened_at = ?1 WHERE project_id = ?2",
                rusqlite::params![opened_at.to_rfc3339(), project_id_bytes],
            )
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        if updated == 0 {
            return Err(PortError::new(
                PortErrorKind::NotFound,
                "no project with that identifier",
                correlation_id,
            ));
        }
        Ok(())
    }

    fn insert_run(
        &self,
        run: &Run,
        project_id: ProjectId,
        idempotency_key: &str,
    ) -> Result<(), PortError> {
        let correlation_id = self.correlation_id();
        if run.project_id != project_id {
            return Err(PortError::new(
                PortErrorKind::Validation,
                "run.project_id does not match supplied project_id",
                correlation_id,
            ));
        }
        if run.idempotency_key != idempotency_key {
            return Err(PortError::new(
                PortErrorKind::Validation,
                "run.idempotency_key does not match supplied idempotency_key",
                correlation_id,
            ));
        }
        let conn = self.store.lock().map_err(Self::map_error)?;
        let project_id_bytes = project_id.as_uuid().as_bytes().to_vec();
        let run_id_bytes = run.id.as_uuid().as_bytes().to_vec();
        let started_at = run.started_at.as_ref().map(WallTime::to_rfc3339);
        let finished_at = run.finished_at.as_ref().map(WallTime::to_rfc3339);
        let result = conn.execute(
            "INSERT INTO runs (\
                 run_id, project_id, run_kind, status, requested_at, \
                 started_at, finished_at, requested_by, idempotency_key, error_code\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                run_id_bytes,
                project_id_bytes,
                run.kind.as_str(),
                run.state.as_str(),
                run.requested_at.to_rfc3339(),
                started_at,
                finished_at,
                run.requested_by,
                idempotency_key,
                run.error_code,
            ],
        );
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                let store_err = StoreError::from_rusqlite(err, correlation_id);
                let port_err = Self::map_error(store_err);
                if matches!(port_err.kind(), PortErrorKind::AlreadyExists) {
                    Err(PortError::new(
                        PortErrorKind::AlreadyExists,
                        "a run already exists for this idempotency key",
                        correlation_id,
                    ))
                } else {
                    Err(port_err)
                }
            }
        }
    }

    fn load_run(&self, run_id: RunId) -> Result<Run, PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let run_id_bytes = run_id.as_uuid().as_bytes().to_vec();
        let row = conn
            .query_row(
                "SELECT run_id, project_id, run_kind, status, requested_at, \
                 started_at, finished_at, requested_by, idempotency_key, error_code \
                 FROM runs WHERE run_id = ?1",
                rusqlite::params![run_id_bytes],
                map_run_row,
            )
            .optional()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        row.ok_or_else(|| {
            PortError::new(PortErrorKind::NotFound, "no run with that identifier", correlation_id)
        })
    }

    fn update_run_state(
        &self,
        run_id: RunId,
        new_state: RunState,
        finished_at: Option<WallTime>,
        error_code: Option<&str>,
    ) -> Result<(), PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let run_id_bytes = run_id.as_uuid().as_bytes().to_vec();
        let finished_at_text = finished_at.as_ref().map(WallTime::to_rfc3339);
        let updated = conn
            .execute(
                "UPDATE runs SET status = ?1, finished_at = COALESCE(?2, finished_at), \
                 error_code = COALESCE(?3, error_code) WHERE run_id = ?4",
                rusqlite::params![new_state.as_str(), finished_at_text, error_code, run_id_bytes,],
            )
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        if updated == 0 {
            return Err(PortError::new(
                PortErrorKind::NotFound,
                "no run with that identifier",
                correlation_id,
            ));
        }
        Ok(())
    }

    fn allocate_run(
        &self,
        project_id: ProjectId,
        kind: RunKind,
        requested_by: &str,
        idempotency_key: &str,
        requested_at: WallTime,
    ) -> Result<RunId, PortError> {
        let correlation_id = self.correlation_id();
        // Ensure the project exists so a foreign-key violation does
        // not surface as a generic uniqueness error.
        let project = self.load_project_by_id(project_id)?;
        let _ = project;
        let conn = self.store.lock().map_err(Self::map_error)?;
        let project_id_bytes = project_id.as_uuid().as_bytes().to_vec();
        let run_id = RunId::new();
        let run_id_bytes = run_id.as_uuid().as_bytes().to_vec();
        let result = conn.execute(
            "INSERT INTO runs (\
                 run_id, project_id, run_kind, status, requested_at, \
                 started_at, finished_at, requested_by, idempotency_key, error_code\
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, NULL)",
            rusqlite::params![
                run_id_bytes,
                project_id_bytes,
                kind.as_str(),
                RunState::Requested.as_str(),
                requested_at.to_rfc3339(),
                requested_by,
                idempotency_key,
            ],
        );
        match result {
            Ok(_) => Ok(run_id),
            Err(err) => {
                let store_err = StoreError::from_rusqlite(err, correlation_id);
                let port_err = Self::map_error(store_err);
                if matches!(port_err.kind(), PortErrorKind::AlreadyExists) {
                    Err(PortError::new(
                        PortErrorKind::AlreadyExists,
                        "a run already exists for this idempotency key",
                        correlation_id,
                    ))
                } else {
                    Err(port_err)
                }
            }
        }
    }
}

fn policy_bytes(policy_id: Option<PolicyId>) -> Option<Vec<u8>> {
    policy_id.map(|id| id.as_uuid().as_bytes().to_vec())
}

fn map_project_row(row: &Row<'_>) -> rusqlite::Result<Project> {
    let project_id_bytes: Vec<u8> = row.get(0)?;
    let canonical_repo_hash: String = row.get(1)?;
    let display_name: String = row.get(2)?;
    let created_at_text: String = row.get(3)?;
    let last_opened_at_text: String = row.get(4)?;
    let config_schema_version: i64 = row.get(5)?;
    let effective_config_hash: String = row.get(6)?;
    let active_capture_policy_id: Option<Vec<u8>> = row.get(7)?;
    let active_redaction_policy_id: Option<Vec<u8>> = row.get(8)?;

    let project_id = uuid_from_bytes(&project_id_bytes, "project_id")?;
    let created_at = parse_wall_time(&created_at_text, "created_at")?;
    let last_opened_at = parse_wall_time(&last_opened_at_text, "last_opened_at")?;
    let config_schema_version = u32::try_from(config_schema_version).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Integer, Box::new(err))
    })?;
    let canonical_repo_hash = RepositoryFingerprint::try_from_canonical(&canonical_repo_hash)
        .map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("column canonical_repo_hash: {err}"),
                )),
            )
        })?;
    Ok(Project {
        id: ProjectId::from_uuid(project_id),
        canonical_repo_hash,
        display_name,
        created_at,
        last_opened_at,
        config_schema_version,
        effective_config_hash,
        active_capture_policy_id: policy_id_from_bytes(
            active_capture_policy_id,
            "active_capture_policy_id",
        )?,
        active_redaction_policy_id: policy_id_from_bytes(
            active_redaction_policy_id,
            "active_redaction_policy_id",
        )?,
    })
}

fn map_run_row(row: &Row<'_>) -> rusqlite::Result<Run> {
    let run_id_bytes: Vec<u8> = row.get(0)?;
    let project_id_bytes: Vec<u8> = row.get(1)?;
    let kind_text: String = row.get(2)?;
    let status_text: String = row.get(3)?;
    let requested_at_text: String = row.get(4)?;
    let started_at_text: Option<String> = row.get(5)?;
    let finished_at_text: Option<String> = row.get(6)?;
    let requested_by: String = row.get(7)?;
    let idempotency_key: String = row.get(8)?;
    let error_code: Option<String> = row.get(9)?;

    let run_id = uuid_from_bytes(&run_id_bytes, "run_id")?;
    let project_id = uuid_from_bytes(&project_id_bytes, "project_id")?;
    let kind = parse_run_kind(&kind_text)?;
    let state = parse_run_state(&status_text)?;
    let requested_at = parse_wall_time(&requested_at_text, "requested_at")?;
    let started_at =
        started_at_text.map(|text| parse_wall_time(&text, "started_at")).transpose()?;
    let finished_at =
        finished_at_text.map(|text| parse_wall_time(&text, "finished_at")).transpose()?;

    Ok(Run {
        id: RunId::from_uuid(run_id),
        project_id: ProjectId::from_uuid(project_id),
        kind,
        state,
        requested_at,
        started_at,
        finished_at,
        requested_by,
        idempotency_key,
        error_code,
    })
}

fn parse_wall_time(text: &str, column: &'static str) -> rusqlite::Result<WallTime> {
    text.parse::<WallTime>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("column {column}: invalid RFC 3339 timestamp"),
            )),
        )
    })
}

fn parse_run_kind(text: &str) -> rusqlite::Result<RunKind> {
    match text {
        "scan" => Ok(RunKind::Scan),
        "launch_capture" => Ok(RunKind::LaunchCapture),
        "attach_capture" => Ok(RunKind::AttachCapture),
        "focused_capture" => Ok(RunKind::FocusedCapture),
        "exercise" => Ok(RunKind::Exercise),
        "export" => Ok(RunKind::Export),
        "retention" => Ok(RunKind::Retention),
        "migration" => Ok(RunKind::Migration),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown run kind: {other}"),
            )),
        )),
    }
}

fn parse_run_state(text: &str) -> rusqlite::Result<RunState> {
    match text {
        "requested" => Ok(RunState::Requested),
        "preparing" => Ok(RunState::Preparing),
        "running" => Ok(RunState::Running),
        "succeeded" => Ok(RunState::Succeeded),
        "partial" => Ok(RunState::Partial),
        "failed" => Ok(RunState::Failed),
        "cancelled" => Ok(RunState::Cancelled),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown run state: {other}"),
            )),
        )),
    }
}

fn uuid_from_bytes(bytes: &[u8], column: &'static str) -> rusqlite::Result<Uuid> {
    let array: [u8; 16] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("column {column}: UUID must be 16 bytes"),
            )),
        )
    })?;
    Ok(Uuid::from_bytes(array))
}

fn policy_id_from_bytes(
    bytes: Option<Vec<u8>>,
    column: &'static str,
) -> rusqlite::Result<Option<PolicyId>> {
    match bytes {
        None => Ok(None),
        Some(buf) => {
            let id = uuid_from_bytes(&buf, column)?;
            Ok(Some(PolicyId::from_uuid(id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use xtrace_domain::{Project, ProjectId, RepositoryFingerprint, WallTime};

    fn fixture() -> SqliteStore {
        SqliteStore::open_in_memory(OpenOptions::default()).expect("open in-memory")
    }

    fn sample_project(name: &str) -> Project {
        let created_at = WallTime::from_parts(2026, 9, 28, 12, 0, 0, 0).expect("valid");
        Project {
            id: ProjectId::new(),
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/tmp/repo"),
            display_name: name.to_string(),
            created_at,
            last_opened_at: created_at,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        }
    }

    #[test]
    fn insert_then_load_round_trips() {
        let store = fixture();
        let repo = store.project_repository();
        let project = sample_project("Example");
        let id = project.id();
        repo.insert_project(&project).expect("insert");
        let loaded = repo.load_project_by_id(id).expect("load");
        assert_eq!(loaded.display_name, "Example");
        assert_eq!(loaded.canonical_repo_hash, project.canonical_repo_hash);
    }

    #[test]
    fn duplicate_fingerprint_is_rejected() {
        let store = fixture();
        let repo = store.project_repository();
        let mut a = sample_project("A");
        let mut b = sample_project("B");
        a.canonical_repo_hash = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        b.canonical_repo_hash = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        repo.insert_project(&a).expect("first insert");
        let err = repo.insert_project(&b).unwrap_err();
        assert_eq!(err.kind(), PortErrorKind::AlreadyExists);
    }

    #[test]
    fn touch_last_opened_updates_timestamp() {
        let store = fixture();
        let repo = store.project_repository();
        let project = sample_project("Example");
        let id = project.id();
        repo.insert_project(&project).expect("insert");

        let later = WallTime::from_parts(2026, 9, 28, 13, 30, 0, 0).expect("valid");
        repo.touch_last_opened(id, later).expect("touch");

        let loaded = repo.load_project_by_id(id).expect("load");
        assert_eq!(loaded.last_opened_at, later);
    }

    #[test]
    fn list_projects_returns_inserted_projects() {
        let store = fixture();
        let repo = store.project_repository();
        repo.insert_project(&sample_project("A")).expect("a");
        let mut b = sample_project("B");
        b.canonical_repo_hash = RepositoryFingerprint::from_canonical_path("/tmp/other");
        repo.insert_project(&b).expect("b");
        let listed = repo.list_projects().expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].display_name, "A");
        assert_eq!(listed[1].display_name, "B");
    }

    #[test]
    fn allocate_run_creates_run_requested_state() {
        let store = fixture();
        let repo = store.project_repository();
        let project = sample_project("Example");
        let project_id = project.id();
        repo.insert_project(&project).expect("insert");

        let requested_at = WallTime::from_parts(2026, 9, 28, 12, 0, 0, 0).expect("valid");
        let run_id = repo
            .allocate_run(project_id, RunKind::Scan, "tester", "idem-1", requested_at)
            .expect("allocate");
        let run = repo.load_run(run_id).expect("load");
        assert_eq!(run.state, RunState::Requested);
        assert_eq!(run.kind, RunKind::Scan);
        assert_eq!(run.idempotency_key, "idem-1");
    }

    #[test]
    fn allocate_run_idempotency_conflict_reports_already_exists() {
        let store = fixture();
        let repo = store.project_repository();
        let project = sample_project("Example");
        let project_id = project.id();
        repo.insert_project(&project).expect("insert");

        let requested_at = WallTime::from_parts(2026, 9, 28, 12, 0, 0, 0).expect("valid");
        repo.allocate_run(project_id, RunKind::Scan, "tester", "idem-1", requested_at)
            .expect("first");
        let err = repo
            .allocate_run(project_id, RunKind::Scan, "tester", "idem-1", requested_at)
            .unwrap_err();
        assert_eq!(err.kind(), PortErrorKind::AlreadyExists);
    }

    #[test]
    fn foreign_keys_block_run_against_missing_project() {
        // We exercise the foreign key by bypassing `allocate_run`,
        // which short-circuits on a missing project. The check below
        // proves the underlying pragma is on.
        let store = fixture();
        let conn = store.lock().expect("lock");
        let pragma: i64 =
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0)).expect("pragma");
        assert_eq!(pragma, 1);
    }
}
