//! Ephemeral exercise execution provenance store (`v0011_exercise_provenance`).
//!
//! Persists explicit exercise runs, items, statuses, typed failure classes, plan hashes,
//! sanitized loopback origins, and explicit `exercise_item_id -> recording_id` linkage.
//! Private operator inputs, request/response bodies, headers, and credential handles or
//! secrets are never stored in SQLite.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use xtrace_application::exercise::{
    ExerciseError, ExerciseFailureClass, ExerciseItemRecord, ExerciseItemStatus,
    ExerciseProvenancePort, ExerciseRecordingLink, ExerciseRunDetail, ExerciseRunRecord,
    ExerciseRunStatus, FinishExerciseRun, NewExerciseItem, NewExerciseRecordingLink,
    NewExerciseRun,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CorrelationId, ProjectId, RunId};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// SQLite implementation of [`ExerciseProvenancePort`].
#[derive(Clone, Debug)]
pub struct SqliteExerciseProvenanceStore {
    store: SqliteStore,
}

impl SqliteExerciseProvenanceStore {
    /// Creates a provenance store view over the shared [`SqliteStore`].
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
    }
}

fn map_store_err(error: StoreError) -> ExerciseError {
    match error.kind() {
        StoreErrorKind::Validation => ExerciseError::InvalidInput,
        StoreErrorKind::NotFound => ExerciseError::NotFound,
        StoreErrorKind::AlreadyExists | StoreErrorKind::Conflict => ExerciseError::Conflict,
        _ => ExerciseError::StorageUnavailable,
    }
}

fn map_sql_err(error: rusqlite::Error) -> ExerciseError {
    map_store_err(StoreError::from_rusqlite(error, CorrelationId::new()))
}

fn is_valid_plan_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_sanitized_loopback_origin(origin: &str) -> bool {
    if origin.len() > 128
        || origin.contains(['?', '#', '@', '\\'])
        || origin.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return false;
    }
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    if authority.contains('/') {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    (host == "127.0.0.1" || host == "[::1]")
        && port.parse::<u16>().ok().is_some_and(|p| p != 0 && p.to_string() == port)
}

fn parse_uuid_bytes<T: From<uuid::Uuid>>(bytes: &[u8]) -> Result<T, ExerciseError> {
    let uuid = uuid::Uuid::from_slice(bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
    Ok(T::from(uuid))
}

fn parse_raw_uuid_bytes(bytes: &[u8]) -> Result<uuid::Uuid, ExerciseError> {
    uuid::Uuid::from_slice(bytes).map_err(|_| ExerciseError::StorageUnavailable)
}

type RunRow =
    (Vec<u8>, Vec<u8>, Vec<u8>, String, String, String, Option<String>, String, Option<String>);
type ItemRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);
type LinkRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String);

fn decode_run_row(row: RunRow) -> Result<ExerciseRunRecord, ExerciseError> {
    let status = ExerciseRunStatus::parse(&row.5).ok_or(ExerciseError::StorageUnavailable)?;
    if let Some(ref fc) = row.6 {
        if ExerciseFailureClass::parse(fc).is_none() {
            return Err(ExerciseError::StorageUnavailable);
        }
    }
    Ok(ExerciseRunRecord {
        exercise_run_id: parse_uuid_bytes(&row.0)?,
        project_id: parse_uuid_bytes(&row.1)?,
        plan_id: parse_raw_uuid_bytes(&row.2)?,
        plan_hash: row.3,
        target_origin: row.4,
        status,
        failure_class: row.6,
        started_at: row.7,
        finished_at: row.8,
    })
}

fn decode_item_row(row: ItemRow) -> Result<ExerciseItemRecord, ExerciseError> {
    let status = ExerciseItemStatus::parse(&row.7).ok_or(ExerciseError::StorageUnavailable)?;
    if let Some(ref fc) = row.8 {
        if ExerciseFailureClass::parse(fc).is_none() {
            return Err(ExerciseError::StorageUnavailable);
        }
    }
    Ok(ExerciseItemRecord {
        exercise_run_id: parse_uuid_bytes(&row.0)?,
        project_id: parse_uuid_bytes(&row.1)?,
        exercise_item_id: parse_raw_uuid_bytes(&row.2)?,
        operation_id: parse_uuid_bytes(&row.3)?,
        method: row.4,
        route_template: row.5,
        effect: row.6,
        status,
        failure_class: row.8,
        http_status: row
            .9
            .map(u16::try_from)
            .transpose()
            .map_err(|_| ExerciseError::StorageUnavailable)?,
        request_bytes: row
            .10
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ExerciseError::StorageUnavailable)?,
        response_bytes: row
            .11
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ExerciseError::StorageUnavailable)?,
        duration_ms: row
            .12
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ExerciseError::StorageUnavailable)?,
    })
}

fn decode_link_row(row: LinkRow) -> Result<ExerciseRecordingLink, ExerciseError> {
    Ok(ExerciseRecordingLink {
        project_id: parse_uuid_bytes(&row.0)?,
        exercise_run_id: parse_uuid_bytes(&row.1)?,
        exercise_item_id: parse_raw_uuid_bytes(&row.2)?,
        recording_id: parse_uuid_bytes(&row.3)?,
        linked_at: row.4,
    })
}

fn load_detail(
    connection: &rusqlite::Connection,
    run: ExerciseRunRecord,
) -> Result<ExerciseRunDetail, ExerciseError> {
    let run_bytes = run.exercise_run_id.as_uuid().as_bytes().to_vec();
    let project_bytes = run.project_id.as_uuid().as_bytes().to_vec();

    let mut item_stmt = connection
        .prepare(
            "SELECT exercise_run_id, project_id, exercise_item_id, operation_id, method, \
                    route_template, effect, status, failure_class, http_status, request_bytes, \
                    response_bytes, duration_ms \
             FROM exercise_items \
             WHERE project_id = ?1 AND exercise_run_id = ?2 \
             ORDER BY exercise_item_id ASC",
        )
        .map_err(map_sql_err)?;
    let items_raw = item_stmt
        .query_map(params![&project_bytes, &run_bytes], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ))
        })
        .map_err(map_sql_err)?
        .collect::<Result<Vec<ItemRow>, _>>()
        .map_err(map_sql_err)?;
    let items = items_raw.into_iter().map(decode_item_row).collect::<Result<Vec<_>, _>>()?;

    let mut link_stmt = connection
        .prepare(
            "SELECT project_id, exercise_run_id, exercise_item_id, recording_id, linked_at \
             FROM exercise_recording_links \
             WHERE project_id = ?1 AND exercise_run_id = ?2 \
             ORDER BY exercise_item_id ASC, recording_id ASC",
        )
        .map_err(map_sql_err)?;
    let links_raw = link_stmt
        .query_map(params![&project_bytes, &run_bytes], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })
        .map_err(map_sql_err)?
        .collect::<Result<Vec<LinkRow>, _>>()
        .map_err(map_sql_err)?;
    let recording_links =
        links_raw.into_iter().map(decode_link_row).collect::<Result<Vec<_>, _>>()?;

    Ok(ExerciseRunDetail { run, items, recording_links })
}

impl ExerciseProvenancePort for SqliteExerciseProvenanceStore {
    fn begin_run(&self, run: &NewExerciseRun, item: &NewExerciseItem) -> Result<(), ExerciseError> {
        if run.exercise_run_id != item.exercise_run_id
            || run.project_id != item.project_id
            || !is_valid_plan_hash(&run.plan_hash)
            || !is_sanitized_loopback_origin(&run.target_origin)
            || run.plan_id.get_version_num() != 7
            || !matches!(item.exercise_item_id.get_version_num(), 7 | 8)
            || item.method.is_empty()
            || item.method.len() > 16
            || !item.method.bytes().all(|b| b.is_ascii_uppercase())
            || item.route_template.is_empty()
            || item.route_template.len() > 2048
            || !matches!(item.effect.as_str(), "read_only" | "mutating" | "unknown")
        {
            return Err(ExerciseError::InvalidInput);
        }

        let mut connection = self.store.lock().map_err(map_store_err)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_err)?;

        tx.execute(
            "INSERT INTO exercise_runs \
             (exercise_run_id, project_id, plan_id, plan_hash, target_origin, status, failure_class, started_at, finished_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', NULL, ?6, NULL)",
            params![
                run.exercise_run_id.as_uuid().as_bytes().as_slice(),
                run.project_id.as_uuid().as_bytes().as_slice(),
                run.plan_id.as_bytes().as_slice(),
                &run.plan_hash,
                &run.target_origin,
                run.started_at.to_rfc3339(),
            ],
        )
        .map_err(map_sql_err)?;

        tx.execute(
            "INSERT INTO exercise_items \
             (exercise_run_id, project_id, exercise_item_id, operation_id, method, route_template, \
              effect, status, failure_class, http_status, request_bytes, response_bytes, duration_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'reserved', NULL, NULL, NULL, NULL, NULL)",
            params![
                item.exercise_run_id.as_uuid().as_bytes().as_slice(),
                item.project_id.as_uuid().as_bytes().as_slice(),
                item.exercise_item_id.as_bytes().as_slice(),
                item.operation_id.as_uuid().as_bytes().as_slice(),
                &item.method,
                &item.route_template,
                &item.effect,
            ],
        )
        .map_err(map_sql_err)?;

        tx.commit().map_err(map_sql_err)?;
        Ok(())
    }

    fn finish_run(&self, c: &FinishExerciseRun) -> Result<(), ExerciseError> {
        if !matches!(
            c.run_status,
            ExerciseRunStatus::Succeeded
                | ExerciseRunStatus::Failed
                | ExerciseRunStatus::DeliveryUnknown
        ) || !matches!(
            c.item_status,
            ExerciseItemStatus::Succeeded
                | ExerciseItemStatus::Failed
                | ExerciseItemStatus::DeliveryUnknown
        ) {
            return Err(ExerciseError::InvalidInput);
        }
        let needs_failure =
            matches!(c.run_status, ExerciseRunStatus::Failed | ExerciseRunStatus::DeliveryUnknown);
        match (&c.failure_class, needs_failure) {
            (Some(fc), true) if ExerciseFailureClass::parse(fc).is_some() => {}
            (None, false) => {}
            _ => return Err(ExerciseError::InvalidInput),
        }
        if let Some(status) = c.http_status {
            if !(100..=599).contains(&status) {
                return Err(ExerciseError::InvalidInput);
            }
        }
        let duration_ms = c
            .duration_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| ExerciseError::InvalidInput)?;

        let mut connection = self.store.lock().map_err(map_store_err)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_err)?;

        let run_updated = tx
            .execute(
                "UPDATE exercise_runs \
                 SET status = ?1, failure_class = ?2, finished_at = ?3 \
                 WHERE project_id = ?4 AND exercise_run_id = ?5 AND status IN ('reserved', 'running')",
                params![
                    c.run_status.as_str(),
                    c.failure_class.as_deref(),
                    c.finished_at.to_rfc3339(),
                    c.project_id.as_uuid().as_bytes().as_slice(),
                    c.exercise_run_id.as_uuid().as_bytes().as_slice(),
                ],
            )
            .map_err(map_sql_err)?;
        if run_updated != 1 {
            return Err(ExerciseError::Conflict);
        }

        let item_updated = tx
            .execute(
                "UPDATE exercise_items \
                 SET status = ?1, failure_class = ?2, http_status = ?3, \
                     request_bytes = ?4, response_bytes = ?5, duration_ms = ?6 \
                 WHERE project_id = ?7 AND exercise_run_id = ?8 AND exercise_item_id = ?9 \
                   AND status IN ('reserved', 'sending')",
                params![
                    c.item_status.as_str(),
                    c.failure_class.as_deref(),
                    c.http_status.map(i64::from),
                    c.request_bytes.map(i64::from),
                    c.response_bytes.map(i64::from),
                    duration_ms,
                    c.project_id.as_uuid().as_bytes().as_slice(),
                    c.exercise_run_id.as_uuid().as_bytes().as_slice(),
                    c.exercise_item_id.as_bytes().as_slice(),
                ],
            )
            .map_err(map_sql_err)?;
        if item_updated != 1 {
            return Err(ExerciseError::Conflict);
        }

        tx.commit().map_err(map_sql_err)?;
        Ok(())
    }

    fn link_recording(
        &self,
        link: &NewExerciseRecordingLink,
    ) -> Result<ExerciseRecordingLink, ExerciseError> {
        let mut connection = self.store.lock().map_err(map_store_err)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_err)?;

        let project_uuid = link.project_id.as_uuid();
        let run_uuid = link.exercise_run_id.as_uuid();
        let rec_uuid = link.recording_id.as_uuid();
        let project_bytes = project_uuid.as_bytes().as_slice();
        let run_bytes = run_uuid.as_bytes().as_slice();
        let item_bytes = link.exercise_item_id.as_bytes().as_slice();
        let rec_bytes = rec_uuid.as_bytes().as_slice();

        let existing: Option<(Vec<u8>, Vec<u8>, String)> = tx
            .query_row(
                "SELECT exercise_run_id, exercise_item_id, linked_at \
                 FROM exercise_recording_links \
                 WHERE project_id = ?1 AND recording_id = ?2",
                params![project_bytes, rec_bytes],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(map_sql_err)?;

        if let Some((existing_run, existing_item, existing_at)) = existing {
            if existing_run == run_bytes && existing_item == item_bytes {
                return Ok(ExerciseRecordingLink {
                    project_id: link.project_id,
                    exercise_run_id: link.exercise_run_id,
                    exercise_item_id: link.exercise_item_id,
                    recording_id: link.recording_id,
                    linked_at: existing_at,
                });
            }
            return Err(ExerciseError::Conflict);
        }

        let linked_at = link.linked_at.to_rfc3339();
        tx.execute(
            "INSERT INTO exercise_recording_links \
             (project_id, exercise_run_id, exercise_item_id, recording_id, linked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![project_bytes, run_bytes, item_bytes, rec_bytes, &linked_at],
        )
        .map_err(map_sql_err)?;
        tx.commit().map_err(map_sql_err)?;

        Ok(ExerciseRecordingLink {
            project_id: link.project_id,
            exercise_run_id: link.exercise_run_id,
            exercise_item_id: link.exercise_item_id,
            recording_id: link.recording_id,
            linked_at,
        })
    }

    fn get_run(
        &self,
        project: ProjectId,
        exercise_run_id: RunId,
    ) -> Result<Option<ExerciseRunDetail>, ExerciseError> {
        let connection = self.store.lock().map_err(map_store_err)?;
        let row: Option<RunRow> = connection
            .query_row(
                "SELECT exercise_run_id, project_id, plan_id, plan_hash, target_origin, \
                        status, failure_class, started_at, finished_at \
                 FROM exercise_runs \
                 WHERE project_id = ?1 AND exercise_run_id = ?2",
                params![
                    project.as_uuid().as_bytes().as_slice(),
                    exercise_run_id.as_uuid().as_bytes().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sql_err)?;
        row.map(decode_run_row).transpose()?.map(|run| load_detail(&connection, run)).transpose()
    }

    fn list_runs_for_plan(
        &self,
        project: ProjectId,
        plan_hash: &str,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
        if !is_valid_plan_hash(plan_hash) || limit == 0 || limit > 100 {
            return Err(ExerciseError::InvalidInput);
        }
        let connection = self.store.lock().map_err(map_store_err)?;
        let mut stmt = connection
            .prepare(
                "SELECT exercise_run_id, project_id, plan_id, plan_hash, target_origin, \
                        status, failure_class, started_at, finished_at \
                 FROM exercise_runs \
                 WHERE project_id = ?1 AND plan_hash = ?2 \
                 ORDER BY exercise_run_id DESC \
                 LIMIT ?3",
            )
            .map_err(map_sql_err)?;
        let rows = stmt
            .query_map(
                params![project.as_uuid().as_bytes().as_slice(), plan_hash, i64::from(limit),],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .map_err(map_sql_err)?
            .collect::<Result<Vec<RunRow>, _>>()
            .map_err(map_sql_err)?;
        rows.into_iter()
            .map(decode_run_row)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|run| load_detail(&connection, run))
            .collect()
    }

    fn list_runs_for_project(
        &self,
        project: ProjectId,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
        if limit == 0 || limit > 100 {
            return Err(ExerciseError::InvalidInput);
        }
        let connection = self.store.lock().map_err(map_store_err)?;
        let mut stmt = connection
            .prepare(
                "SELECT exercise_run_id, project_id, plan_id, plan_hash, target_origin, \
                        status, failure_class, started_at, finished_at \
                 FROM exercise_runs \
                 WHERE project_id = ?1 \
                 ORDER BY exercise_run_id DESC \
                 LIMIT ?2",
            )
            .map_err(map_sql_err)?;
        let rows = stmt
            .query_map(params![project.as_uuid().as_bytes().as_slice(), i64::from(limit)], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })
            .map_err(map_sql_err)?
            .collect::<Result<Vec<RunRow>, _>>()
            .map_err(map_sql_err)?;
        rows.into_iter()
            .map(decode_run_row)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|run| load_detail(&connection, run))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "in-memory SQLite provenance tests")]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use xtrace_domain::{OperationId, RecordingId, RuntimeSessionId, WallTime};

    fn seed_project_and_recording(store: &SqliteStore) -> (ProjectId, RecordingId) {
        let project = ProjectId::new();
        let recording = RecordingId::new();
        let session = RuntimeSessionId::new();
        let conn = store.lock().unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, \
             last_opened_at, config_schema_version, effective_config_hash) \
             VALUES (?1, ?2, 'proj', 't', 't', 1, 'cfg')",
            params![project.as_uuid().as_bytes().as_slice(), format!("b3:{}", project)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) \
             VALUES (?1, ?2, ?3, 'complete', 't')",
            params![
                recording.as_uuid().as_bytes().as_slice(),
                project.as_uuid().as_bytes().as_slice(),
                session.as_uuid().as_bytes().as_slice(),
            ],
        )
        .unwrap();
        (project, recording)
    }

    fn item_v8_uuid(seed: u8) -> uuid::Uuid {
        let mut bytes = [seed; 16];
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(bytes)
    }

    #[test]
    fn persists_run_item_failure_and_recording_linkage_with_project_isolation() {
        let store = SqliteStore::open_in_memory(OpenOptions::default()).unwrap();
        let (project, recording) = seed_project_and_recording(&store);
        let (other_project, other_recording) = seed_project_and_recording(&store);
        let prov = SqliteExerciseProvenanceStore::new(store);

        let run_id = RunId::new();
        let plan_id = uuid::Uuid::now_v7();
        let plan_hash = "a".repeat(64);
        let op_id = OperationId::new();
        let item_id = item_v8_uuid(0x42);

        prov.begin_run(
            &NewExerciseRun {
                exercise_run_id: run_id,
                project_id: project,
                plan_id,
                plan_hash: plan_hash.clone(),
                target_origin: "http://127.0.0.1:8080".into(),
                started_at: WallTime::now(),
            },
            &NewExerciseItem {
                exercise_run_id: run_id,
                project_id: project,
                exercise_item_id: item_id,
                operation_id: op_id,
                method: "POST".into(),
                route_template: "/orders/{id}".into(),
                effect: "mutating".into(),
            },
        )
        .unwrap();

        prov.finish_run(&FinishExerciseRun {
            project_id: project,
            exercise_run_id: run_id,
            exercise_item_id: item_id,
            run_status: ExerciseRunStatus::Failed,
            item_status: ExerciseItemStatus::Failed,
            failure_class: Some("redirect_refused".into()),
            http_status: Some(302),
            request_bytes: Some(256),
            response_bytes: None,
            duration_ms: Some(12),
            finished_at: WallTime::now(),
        })
        .unwrap();

        // Repeated finish_run must fail with Conflict (terminal immutability).
        assert_eq!(
            prov.finish_run(&FinishExerciseRun {
                project_id: project,
                exercise_run_id: run_id,
                exercise_item_id: item_id,
                run_status: ExerciseRunStatus::Succeeded,
                item_status: ExerciseItemStatus::Succeeded,
                failure_class: None,
                http_status: Some(200),
                request_bytes: Some(256),
                response_bytes: Some(10),
                duration_ms: Some(12),
                finished_at: WallTime::now(),
            }),
            Err(ExerciseError::Conflict)
        );

        // Cross-project recording cannot be linked.
        assert_eq!(
            prov.link_recording(&NewExerciseRecordingLink {
                project_id: project,
                exercise_run_id: run_id,
                exercise_item_id: item_id,
                recording_id: other_recording,
                linked_at: WallTime::now(),
            }),
            Err(ExerciseError::Conflict)
        );

        let link = prov
            .link_recording(&NewExerciseRecordingLink {
                project_id: project,
                exercise_run_id: run_id,
                exercise_item_id: item_id,
                recording_id: recording,
                linked_at: WallTime::now(),
            })
            .unwrap();
        assert_eq!(link.recording_id, recording);

        // Idempotent replay of exact same link returns existing row.
        assert_eq!(
            prov.link_recording(&NewExerciseRecordingLink {
                project_id: project,
                exercise_run_id: run_id,
                exercise_item_id: item_id,
                recording_id: recording,
                linked_at: WallTime::now(),
            })
            .unwrap()
            .recording_id,
            recording
        );

        assert!(prov.get_run(other_project, run_id).unwrap().is_none());
        let detail = prov.get_run(project, run_id).unwrap().unwrap();
        assert_eq!(detail.run.status, ExerciseRunStatus::Failed);
        assert_eq!(detail.run.failure_class.as_deref(), Some("redirect_refused"));
        assert_eq!(detail.items[0].http_status, Some(302));
        assert_eq!(detail.recording_links.len(), 1);
        assert_eq!(prov.list_runs_for_plan(project, &plan_hash, 10).unwrap().len(), 1);
        assert_eq!(prov.list_runs_for_project(project, 10).unwrap().len(), 1);
    }
}
