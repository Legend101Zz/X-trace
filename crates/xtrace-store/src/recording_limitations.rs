//! Persisted recording limitations (ADR 0011, schema v9).
//!
//! A limitation is a closed-vocabulary code the daemon attached to a recording when it opened
//! (for example `capture_policy_not_armed`). Rows are written in the same transaction as the
//! recording anchor and never updated: a replayed anchor keeps the limitations it was first
//! opened with. Codes carry no captured values, only the vocabulary the SQL `CHECK` allows.
//! A recording opened before schema v9 has no rows, which reads as "none recorded".

use rusqlite::{Connection, params};

/// Inserts the limitation rows of a freshly inserted recording anchor.
///
/// The caller owns the surrounding transaction. `limitations` must already be validated against
/// the application vocabulary; the table `CHECK` is the second line of defence.
pub(crate) fn insert(
    connection: &Connection,
    recording_id: &[u8],
    limitations: &[String],
) -> rusqlite::Result<()> {
    let mut statement = connection
        .prepare_cached("INSERT INTO recording_limitations (recording_id, code) VALUES (?1, ?2)")?;
    for code in limitations {
        statement.execute(params![recording_id, code])?;
    }
    Ok(())
}

/// Loads the limitation codes of one recording in code order.
pub(crate) fn load(connection: &Connection, recording_id: &[u8]) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare_cached(
        "SELECT code FROM recording_limitations WHERE recording_id = ?1 ORDER BY code",
    )?;
    let rows = statement.query_map(params![recording_id], |row| row.get::<_, String>(0))?;
    rows.collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixtures")]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "CREATE TABLE recordings (recording_id BLOB PRIMARY KEY) STRICT;
                 CREATE TABLE recording_limitations (
                     recording_id BLOB NOT NULL REFERENCES recordings(recording_id),
                     code TEXT NOT NULL,
                     PRIMARY KEY (recording_id, code)
                 ) STRICT;",
            )
            .expect("schema");
        connection
    }

    #[test]
    fn rows_round_trip_in_code_order_and_are_per_recording() {
        let connection = connection();
        connection.execute("INSERT INTO recordings VALUES (X'01'), (X'02')", []).expect("rows");
        insert(&connection, &[1], &["b_code".to_owned(), "a_code".to_owned()]).expect("insert");
        assert_eq!(load(&connection, &[1]).expect("load"), vec!["a_code", "b_code"]);
        assert!(load(&connection, &[2]).expect("load other").is_empty());
    }
}
