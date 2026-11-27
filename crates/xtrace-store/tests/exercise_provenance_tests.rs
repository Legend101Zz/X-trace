//! Ephemeral exercise provenance persistence & recording linkage against real on-disk private SQLite stores.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration tests assert on fixed fixtures and checked SQL outcomes"
)]

use std::path::PathBuf;
use std::sync::OnceLock;

use rusqlite::params;
use xtrace_application::exercise::{
    ExerciseError, ExerciseItemStatus, ExerciseProvenancePort as _, ExerciseRunStatus,
    FinishExerciseRun, NewExerciseItem, NewExerciseRecordingLink, NewExerciseRun,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{OperationId, ProjectId, RecordingId, RunId, RuntimeSessionId, WallTime};
use xtrace_private_storage::AdmittedPrivateRoot;
use xtrace_store::{OpenOptions, SqliteExerciseProvenanceStore, SqliteStore};

struct ScratchSlots {
    roundtrip: AdmittedPrivateRoot,
    isolation: AdmittedPrivateRoot,
}

fn scratch_slots() -> &'static ScratchSlots {
    static SLOTS: OnceLock<ScratchSlots> = OnceLock::new();
    SLOTS.get_or_init(|| {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("XTRACE_TEST_PRIVATE_SCRATCH must point to private test storage"),
        );
        let root = AdmittedPrivateRoot::open(&scratch).expect("private scratch is admitted");
        let name = format!("exercise-prov-{}-{}", std::process::id(), uuid::Uuid::now_v7());
        let family = root.create_private_child(&name).expect("private exercise test family");
        ScratchSlots {
            roundtrip: family.create_private_child("roundtrip").expect("roundtrip slot"),
            isolation: family.create_private_child("isolation").expect("isolation slot"),
        }
    })
}

fn seed_private_store(
    slot: &AdmittedPrivateRoot,
    count: usize,
) -> (SqliteStore, Vec<(ProjectId, RecordingId)>) {
    let dir = slot.create_private_child("db").expect("private store dir");
    let path = dir.path().join("metadata.sqlite3");
    {
        let initial = SqliteStore::open(&path, OpenOptions::default()).expect("store opens at v11");
        assert_eq!(initial.bootstrap().schema_version, xtrace_store::CURRENT_SCHEMA_VERSION);
    }
    let mut seeded = Vec::with_capacity(count);
    {
        let conn = rusqlite::Connection::open(&path).expect("raw connection");
        conn.pragma_update(None, "foreign_keys", true).expect("foreign keys on");
        for _ in 0..count {
            let project = ProjectId::new();
            let recording = RecordingId::new();
            let session = RuntimeSessionId::new();
            conn.execute(
                "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, \
                 last_opened_at, config_schema_version, effective_config_hash) \
                 VALUES (?1, ?2, 'proj', 't', 't', 1, 'cfg')",
                params![project.as_uuid().as_bytes().as_slice(), format!("b3:{project}")],
            )
            .expect("seed project");
            conn.execute(
                "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) \
                 VALUES (?1, ?2, ?3, 'complete', 't')",
                params![
                    recording.as_uuid().as_bytes().as_slice(),
                    project.as_uuid().as_bytes().as_slice(),
                    session.as_uuid().as_bytes().as_slice(),
                ],
            )
            .expect("seed recording");
            seeded.push((project, recording));
        }
    }
    let store = SqliteStore::open(&path, OpenOptions::default().with_must_exist(true))
        .expect("reopen seeded store");
    (store, seeded)
}

fn item_v8(seed: u8) -> uuid::Uuid {
    let mut b = [seed; 16];
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b)
}

#[test]
fn private_disk_store_persists_run_item_and_recording_linkage() {
    let (store, seeded) = seed_private_store(&scratch_slots().roundtrip, 1);
    let (project, recording) = seeded[0];
    let prov = SqliteExerciseProvenanceStore::new(store);

    let run_id = RunId::new();
    let plan_id = uuid::Uuid::now_v7();
    let plan_hash = "b".repeat(64);
    let item_id = item_v8(0x21);
    let op_id = OperationId::new();

    prov.begin_run(
        &NewExerciseRun {
            exercise_run_id: run_id,
            project_id: project,
            plan_id,
            plan_hash: plan_hash.clone(),
            target_origin: "http://[::1]:8080".into(),
            started_at: WallTime::now(),
        },
        &NewExerciseItem {
            exercise_run_id: run_id,
            project_id: project,
            exercise_item_id: item_id,
            operation_id: op_id,
            method: "GET".into(),
            route_template: "/items/{id}".into(),
            effect: "read_only".into(),
        },
    )
    .expect("begin run");

    prov.finish_run(&FinishExerciseRun {
        project_id: project,
        exercise_run_id: run_id,
        exercise_item_id: item_id,
        run_status: ExerciseRunStatus::Succeeded,
        item_status: ExerciseItemStatus::Succeeded,
        failure_class: None,
        http_status: Some(200),
        request_bytes: Some(180),
        response_bytes: Some(512),
        duration_ms: Some(4),
        finished_at: WallTime::now(),
    })
    .expect("finish run");

    let link = prov
        .link_recording(&NewExerciseRecordingLink {
            project_id: project,
            exercise_run_id: run_id,
            exercise_item_id: item_id,
            recording_id: recording,
            linked_at: WallTime::now(),
        })
        .expect("link recording");
    assert_eq!(link.recording_id, recording);

    let loaded = prov.get_run(project, run_id).expect("query").expect("exists");
    assert_eq!(loaded.run.status, ExerciseRunStatus::Succeeded);
    assert_eq!(loaded.items[0].response_bytes, Some(512));
    assert_eq!(loaded.recording_links[0].exercise_item_id, item_id);
}

#[test]
fn private_disk_store_enforces_project_isolation_and_recording_fk() {
    let (store, seeded) = seed_private_store(&scratch_slots().isolation, 2);
    let (project_a, _rec_a) = seeded[0];
    let (_project_b, rec_b) = seeded[1];
    let prov = SqliteExerciseProvenanceStore::new(store);

    let run_id = RunId::new();
    let item_id = item_v8(0x33);
    prov.begin_run(
        &NewExerciseRun {
            exercise_run_id: run_id,
            project_id: project_a,
            plan_id: uuid::Uuid::now_v7(),
            plan_hash: "c".repeat(64),
            target_origin: "http://127.0.0.1:9000".into(),
            started_at: WallTime::now(),
        },
        &NewExerciseItem {
            exercise_run_id: run_id,
            project_id: project_a,
            exercise_item_id: item_id,
            operation_id: OperationId::new(),
            method: "POST".into(),
            route_template: "/orders".into(),
            effect: "mutating".into(),
        },
    )
    .expect("begin run");

    // Linking a recording belonging to another project or nonexistent recording fails closed.
    for bad_recording in [rec_b, RecordingId::new()] {
        assert_eq!(
            prov.link_recording(&NewExerciseRecordingLink {
                project_id: project_a,
                exercise_run_id: run_id,
                exercise_item_id: item_id,
                recording_id: bad_recording,
                linked_at: WallTime::now(),
            }),
            Err(ExerciseError::Conflict)
        );
    }
}
