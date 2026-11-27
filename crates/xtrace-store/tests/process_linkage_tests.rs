//! Integration tests for runtime session process linkage and migration v11 -> v12.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration tests assert on fixed fixtures and checked SQL outcomes"
)]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use rusqlite::params;
use xtrace_application::{
    ChildHandshakeClaim, ParentSpawnClaim, PortErrorKind, ProcessLinkageService,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    GapReason, ProjectId, RecordingId, RuntimeSessionId, RuntimeSessionLink, SessionLinkId,
    SessionLinkStatus, SpawnKind, WallTime, hash_correlation_token,
};
use xtrace_private_storage::AdmittedPrivateRoot;
use xtrace_store::{
    CURRENT_SCHEMA_VERSION, Migrations, OpenOptions, SqliteProcessLinkageStore, SqliteStore,
};

struct ScratchSlots {
    upgrade: AdmittedPrivateRoot,
    crud: AdmittedPrivateRoot,
}

fn scratch_slots() -> &'static ScratchSlots {
    static SLOTS: OnceLock<ScratchSlots> = OnceLock::new();
    SLOTS.get_or_init(|| {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("XTRACE_TEST_PRIVATE_SCRATCH must point to private test storage"),
        );
        let root = AdmittedPrivateRoot::open(&scratch).expect("private scratch is admitted");
        let name = format!("process-linkage-{}-{}", std::process::id(), uuid::Uuid::now_v7());
        let family = root.create_private_child(&name).expect("private linkage test family");
        ScratchSlots {
            upgrade: family.create_private_child("upgrade").expect("upgrade slot"),
            crud: family.create_private_child("crud").expect("crud slot"),
        }
    })
}

fn create_v11_database(
    path: &std::path::Path,
) -> (ProjectId, RecordingId, RecordingId, RuntimeSessionId, RuntimeSessionId) {
    let v11_records = &Migrations::catalog()[..11];
    let v11_checksum = Migrations::prefix_checksum(v11_records);
    let conn = rusqlite::Connection::open(path).expect("open raw v11 sqlite file");
    conn.pragma_update(None, "foreign_keys", true).expect("foreign keys on");
    for record in v11_records {
        for stmt in record.statements {
            conn.execute_batch(stmt).expect("apply v1..v11 statement");
        }
    }
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta \
         (singleton, schema_version, min_reader_version, migrated_at, app_version, applied_checksum) \
         VALUES (1, 11, 11, ?1, '0.1.0-v11-fixture', ?2)",
        params![WallTime::now().to_rfc3339(), v11_checksum],
    )
    .expect("seed v11 schema_meta");

    let project = ProjectId::new();
    let parent_rec = RecordingId::new();
    let child_rec = RecordingId::new();
    let parent_session = RuntimeSessionId::new();
    let child_session = RuntimeSessionId::new();

    conn.execute(
        "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, \
         last_opened_at, config_schema_version, effective_config_hash) \
         VALUES (?1, ?2, 'proj', 't', 't', 1, 'cfg')",
        params![project.as_uuid().as_bytes().as_slice(), format!("b3:{project}")],
    )
    .expect("seed v11 project");

    for (rec, sess) in [(parent_rec, parent_session), (child_rec, child_session)] {
        conn.execute(
            "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) \
             VALUES (?1, ?2, ?3, 'complete', 't')",
            params![
                rec.as_uuid().as_bytes().as_slice(),
                project.as_uuid().as_bytes().as_slice(),
                sess.as_uuid().as_bytes().as_slice(),
            ],
        )
        .expect("seed v11 recording");
    }
    drop(conn);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict v11 fixture sqlite file mode");
    }
    (project, parent_rec, child_rec, parent_session, child_session)
}

#[test]
fn v11_database_upgrades_cleanly_to_v12_and_preserves_existing_rows() {
    let dir = scratch_slots().upgrade.create_private_child("db").expect("private store dir");
    let path = dir.path().join("metadata.sqlite3");
    let (_project, parent_rec, child_rec, parent_session, child_session) =
        create_v11_database(&path);

    let store = SqliteStore::open(&path, OpenOptions::default().with_must_exist(true))
        .expect("upgrade v11 -> v12");
    assert_eq!(store.bootstrap().schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(CURRENT_SCHEMA_VERSION, 12);

    let linkage = SqliteProcessLinkageStore::new(store.clone());
    assert!(linkage.list_child_links(parent_session).expect("empty child links").is_empty());
    assert!(linkage.find_parent_link(child_session).expect("no parent link yet").is_none());

    let token_hash = hash_correlation_token("upgrade-worker-token").unwrap();
    let link = RuntimeSessionLink::linked(
        SessionLinkId::new(),
        parent_session,
        Some(parent_rec),
        child_session,
        Some(child_rec),
        SpawnKind::NodeWorker,
        Some(token_hash),
        1_700_000_001_000,
    )
    .unwrap();
    linkage.record_session_link(&link).expect("persist link after v12 upgrade");
    assert_eq!(linkage.find_parent_link(child_session).expect("query parent"), Some(link));

    // Confirm existing v11 recording rows survived untouched.
    let conn = rusqlite::Connection::open(&path).expect("raw read");
    let rec_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0)).unwrap();
    assert_eq!(rec_count, 2);
}

#[test]
fn disk_store_records_queries_and_enforces_constraints_via_application_service() {
    let dir = scratch_slots().crud.create_private_child("db").expect("private store dir");
    let path = dir.path().join("metadata.sqlite3");
    let store = SqliteStore::open(&path, OpenOptions::default()).expect("open v12 store");
    assert_eq!(store.bootstrap().schema_version, 12);

    let project = ProjectId::new();
    let parent_rec = RecordingId::new();
    let child_rec = RecordingId::new();
    let parent_session = RuntimeSessionId::new();
    let child_session = RuntimeSessionId::new();
    {
        let conn = rusqlite::Connection::open(&path).expect("seed connection");
        conn.pragma_update(None, "foreign_keys", true).expect("foreign keys on");
        conn.execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, \
             last_opened_at, config_schema_version, effective_config_hash) \
             VALUES (?1, ?2, 'proj', 't', 't', 1, 'cfg')",
            params![project.as_uuid().as_bytes().as_slice(), format!("b3:{project}")],
        )
        .unwrap();
        for (rec, sess) in [(parent_rec, parent_session), (child_rec, child_session)] {
            conn.execute(
                "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) \
                 VALUES (?1, ?2, ?3, 'complete', 't')",
                params![
                    rec.as_uuid().as_bytes().as_slice(),
                    project.as_uuid().as_bytes().as_slice(),
                    sess.as_uuid().as_bytes().as_slice(),
                ],
            )
            .unwrap();
        }
    }

    let port = Arc::new(SqliteProcessLinkageStore::new(store));
    let service = ProcessLinkageService::new(port.clone());
    let raw_secret_token = "xtrace-canary-token-never-persisted-raw";
    let expected_hash = hash_correlation_token(raw_secret_token).unwrap();

    let linked = service
        .reconcile_child_session(
            Some(&ParentSpawnClaim {
                parent_session_id: parent_session,
                parent_recording_id: Some(parent_rec),
                spawn_kind: SpawnKind::NodeWorker,
                expected_token_hash: expected_hash,
            }),
            &ChildHandshakeClaim {
                child_session_id: child_session,
                child_recording_id: Some(child_rec),
                spawn_kind: SpawnKind::NodeWorker,
                correlation_token: Some(raw_secret_token.to_string()),
                created_at_ms: 100,
            },
        )
        .expect("reconcile linked child");
    assert_eq!(linked.status, SessionLinkStatus::Linked);
    assert_eq!(linked.correlation_token_hash, Some(expected_hash));

    let gap = service
        .record_uninstrumented_gap(
            parent_session,
            Some(parent_rec),
            SpawnKind::JvmFork,
            GapReason::ChildProcessNotInstrumented,
            200,
        )
        .expect("record jvm_fork gap");
    assert_eq!(gap.status, SessionLinkStatus::UninstrumentedGap);
    assert_eq!(gap.gap_reason, Some(GapReason::ChildProcessNotInstrumented));

    let lost = service
        .reconcile_child_session(
            Some(&ParentSpawnClaim {
                parent_session_id: parent_session,
                parent_recording_id: Some(parent_rec),
                spawn_kind: SpawnKind::NodeChildProcess,
                expected_token_hash: expected_hash,
            }),
            &ChildHandshakeClaim {
                child_session_id: RuntimeSessionId::new(),
                child_recording_id: Some(RecordingId::new()),
                spawn_kind: SpawnKind::NodeChildProcess,
                correlation_token: Some("mismatched-token".to_string()),
                created_at_ms: 300,
            },
        )
        .expect("mismatched token records correlation_lost");
    assert_eq!(lost.status, SessionLinkStatus::CorrelationLost);
    assert_eq!(lost.gap_reason, Some(GapReason::CorrelationLost));

    assert_eq!(service.list_child_links(parent_session).unwrap(), vec![linked, gap, lost]);
    assert_eq!(service.find_parent_link(child_session).unwrap(), Some(linked));
    assert_eq!(service.find_parent_link_by_recording(child_rec).unwrap(), Some(linked));

    // Nonexistent parent_recording_id fails closed via foreign-key constraint.
    let bad_recording = RuntimeSessionLink::uninstrumented_gap(
        SessionLinkId::new(),
        parent_session,
        Some(RecordingId::new()),
        SpawnKind::NodeChildProcess,
        GapReason::ChildProcessNotInstrumented,
        400,
    )
    .unwrap();
    assert_eq!(
        port.record_session_link(&bad_recording).unwrap_err().kind(),
        PortErrorKind::Conflict
    );

    // Raw token bytes must never appear anywhere in the SQLite file.
    let raw_bytes = std::fs::read(&path).expect("read sqlite file");
    assert!(
        !raw_bytes.windows(raw_secret_token.len()).any(|w| w == raw_secret_token.as_bytes()),
        "raw correlation token must never be persisted to disk"
    );
}
