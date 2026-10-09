//! Migration v9 (general endpoint links) proof, run against a real store database.
//!
//! The SQL lives in `src/lane_sql/catalog_v9.sql`. These tests apply it to a database that the
//! store itself created and seeded with v3-shaped rows, so they hold both before the contracts
//! lane registers the migration (the SQL is applied here) and after (the rebuild is then a
//! faithful no-op copy).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration tests assert on fixed fixtures and checked SQL results"
)]

use rusqlite::{Connection, params, types::Value};
use uuid::Uuid;
use xtrace_private_storage::AdmittedPrivateRoot;
use xtrace_store::{OpenOptions, SqliteStore};

const V9_SQL: &str = include_str!("../src/lane_sql/catalog_v9.sql");

fn uuid7() -> Vec<u8> {
    Uuid::now_v7().as_bytes().to_vec()
}

/// Private scratch directory (owner-only, admitted) the store requires; the leased runner exports
/// `XTRACE_TEST_PRIVATE_SCRATCH` for it.
fn fresh_database() -> (AdmittedPrivateRoot, Connection) {
    let scratch = std::path::PathBuf::from(
        std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .expect("XTRACE_TEST_PRIVATE_SCRATCH must point to private test storage"),
    );
    let root = AdmittedPrivateRoot::open(&scratch).expect("private scratch is admitted");
    let name = format!("catalog-link-{}-{}", std::process::id(), Uuid::now_v7());
    let dir = root.create_private_child(&name).expect("private child");
    let path = dir.path().join("xtrace.sqlite3");
    drop(SqliteStore::open(&path, OpenOptions::default()).expect("store opens and migrates"));
    let connection = Connection::open(&path).expect("raw connection");
    connection.pragma_update(None, "foreign_keys", true).expect("foreign keys on");
    (dir, connection)
}

struct Seed {
    project: Vec<u8>,
    legacy_operation: Vec<u8>,
    linked: Vec<u8>,
    unmatched: Vec<u8>,
}

fn seed_v3_rows(connection: &Connection) -> Seed {
    let seed =
        Seed { project: uuid7(), legacy_operation: uuid7(), linked: uuid7(), unmatched: uuid7() };
    connection
        .execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, config_schema_version, effective_config_hash) VALUES (?1, 'h-repo', 'p', 't', 't', 1, 'h-config')",
            params![seed.project],
        )
        .expect("project");
    for recording in [&seed.linked, &seed.unmatched] {
        connection
            .execute(
                "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) VALUES (?1, ?2, ?3, 'complete', 't')",
                params![recording, seed.project, uuid7()],
            )
            .expect("recording");
    }
    connection
        .execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'POST', '/orders', 'spring-fixture', 'default', 1, zeroblob(32), '2026-10-04T00:00:00Z')",
            params![seed.legacy_operation, seed.project],
        )
        .expect("legacy operation");
    connection
        .execute(
            "INSERT INTO recording_endpoint_observations (recording_id, project_id, disposition, observation_policy_id, operation_id, application_component, binding_key, method, route_template, reason_code) VALUES (?1, ?2, 'linked', 'spring-orders-v1', ?3, 'spring-fixture', 'default', 'POST', '/orders', NULL)",
            params![seed.linked, seed.project, seed.legacy_operation],
        )
        .expect("linked sidecar row");
    connection
        .execute(
            "INSERT INTO recording_endpoint_observations (recording_id, project_id, disposition, reason_code) VALUES (?1, ?2, 'unmatched', 'observation_policy_missing')",
            params![seed.unmatched, seed.project],
        )
        .expect("unmatched sidecar row");
    seed
}

fn snapshot(connection: &Connection, table: &str, order_by: &str) -> Vec<Vec<Value>> {
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY {order_by}"))
        .expect("prepare snapshot");
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|index| row.get::<_, Value>(index)).collect())
        .expect("query snapshot")
        .collect::<Result<_, _>>()
        .expect("collect snapshot")
}

fn apply_v9(connection: &mut Connection) {
    let transaction = connection.transaction().expect("transaction");
    transaction.execute_batch(V9_SQL).expect("v9 SQL applies with foreign keys enforced");
    transaction.commit().expect("v9 commits with deferred foreign keys satisfied");
}

#[test]
fn migration_v9_preserves_v3_operations_and_sidecar_bytes() {
    let (_dir, mut connection) = fresh_database();
    let seed = seed_v3_rows(&connection);
    let operations_before = snapshot(&connection, "operations", "operation_id");
    let sidecar_before = snapshot(&connection, "recording_endpoint_observations", "recording_id");
    assert_eq!(operations_before.len(), 1);
    assert_eq!(sidecar_before.len(), 2);

    apply_v9(&mut connection);

    assert_eq!(snapshot(&connection, "operations", "operation_id"), operations_before);
    assert_eq!(
        snapshot(&connection, "recording_endpoint_observations", "recording_id"),
        sidecar_before
    );
    let violations: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))
        .expect("foreign key check");
    assert_eq!(violations, 0);
    let recordings: i64 = connection
        .query_row("SELECT count(*) FROM recordings", [], |row| row.get(0))
        .expect("count");
    assert_eq!(recordings, 2, "recordings are untouched");
    let id: Vec<u8> = connection
        .query_row("SELECT operation_id FROM operations", [], |row| row.get(0))
        .expect("operation id");
    assert_eq!(id, seed.legacy_operation, "operation id bytes are unchanged");
}

#[test]
fn migration_v9_is_repeatable_on_its_own_output() {
    let (_dir, mut connection) = fresh_database();
    seed_v3_rows(&connection);
    apply_v9(&mut connection);
    let operations = snapshot(&connection, "operations", "operation_id");
    let sidecar = snapshot(&connection, "recording_endpoint_observations", "recording_id");
    apply_v9(&mut connection);
    assert_eq!(snapshot(&connection, "operations", "operation_id"), operations);
    assert_eq!(snapshot(&connection, "recording_endpoint_observations", "recording_id"), sidecar);
}

#[test]
fn migration_v9_accepts_general_routes_and_links_with_a_bound_tuple() {
    let (_dir, mut connection) = fresh_database();
    let seed = seed_v3_rows(&connection);
    apply_v9(&mut connection);

    let operation = uuid7();
    connection
        .execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'GET', '/owners/{id}', 'petclinic', 'default', 1, zeroblob(32) || x'', 't')",
            params![operation, seed.project],
        )
        .expect_err("a second operation cannot reuse the fingerprint");
    connection
        .execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'GET', '/owners/{id}', 'petclinic', 'default', 1, randomblob(32), 't')",
            params![operation, seed.project],
        )
        .expect("a non-fixture operation is accepted");
    let recording = uuid7();
    connection
        .execute(
            "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) VALUES (?1, ?2, ?3, 'complete', 't')",
            params![recording, seed.project, uuid7()],
        )
        .expect("recording");
    let link = |route: &str, policy: &str| {
        connection.execute(
            "INSERT INTO recording_endpoint_observations (recording_id, project_id, disposition, observation_policy_id, operation_id, application_component, binding_key, method, route_template, reason_code) VALUES (?1, ?2, 'linked', ?3, ?4, 'petclinic', 'default', 'GET', ?5, NULL)",
            params![recording, seed.project, policy, operation, route],
        )
    };
    link("/owners/other", "runtime-route-v1")
        .expect_err("link tuple must equal the operation tuple");
    link("/owners/{id}", "spring-orders-v1")
        .expect_err("spring-orders-v1 stays confined to the fixture tuple");
    link("/owners/{id}", "runtime-route-v1").expect("general link with runtime-route-v1");
}

#[test]
fn migration_v9_keeps_structural_limits_and_new_reason_codes() {
    let (_dir, mut connection) = fresh_database();
    let seed = seed_v3_rows(&connection);
    apply_v9(&mut connection);
    let insert = |method: &str, route: &str, component: &str| {
        connection.execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', ?3, ?4, ?5, 'default', 1, randomblob(32), 't')",
            params![uuid7(), seed.project, method, route, component],
        )
    };
    insert("FETCH", "/a", "svc").expect_err("unknown method");
    insert("GET", "/a?x=1", "svc").expect_err("query in route");
    insert("GET", "/a#f", "svc").expect_err("fragment in route");
    insert("GET", "a", "svc").expect_err("route without leading slash");
    insert("GET", "/a\u{1}b", "svc").expect_err("control character");
    insert("GET", &format!("/{}", "a".repeat(1024)), "svc").expect_err("route longer than 1024");
    insert("GET", "/a", "has space").expect_err("component outside the safe set");
    insert("GET", "/a", "").expect_err("empty component");
    insert("GET", "/a", "svc").expect("structurally valid operation");

    let recording = uuid7();
    connection
        .execute(
            "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) VALUES (?1, ?2, ?3, 'complete', 't')",
            params![recording, seed.project, uuid7()],
        )
        .expect("recording");
    connection
        .execute(
            "INSERT INTO recording_endpoint_observations (recording_id, project_id, disposition, observation_policy_id, application_component, binding_key, reason_code) VALUES (?1, ?2, 'unmatched', 'runtime-route-v1', 'svc', 'default', 'no_catalog_match')",
            params![recording, seed.project],
        )
        .expect("no_catalog_match is a valid unmatched reason");
    let raw_route_retained = connection.execute(
        "UPDATE recording_endpoint_observations SET route_template = '/raw/secret' WHERE recording_id = ?1",
        params![recording],
    );
    raw_route_retained.expect_err("an unmatched row can never retain the raw route");
}
