//! Hosted-only, synthetic measurement copied into xtrace-store/examples by CI.
use std::path::PathBuf;
use std::time::Instant;

use rusqlite::{Connection, Statement, StatementStatus, params};
use xtrace_application::FrameHonestyCounts;
use xtrace_domain::honesty_flags as flags;

const ROWS: u32 = 131_072;
const RECORDING: [u8; 16] = [1; 16];
const DECOY: [u8; 16] = [2; 16];
const MASKS: [i64; 6] = [
    flags::HAS_GAP as i64,
    flags::HAS_REDACTED as i64,
    flags::HAS_TRUNCATED as i64,
    flags::HAS_UNAVAILABLE as i64,
    flags::HAS_DROPPED as i64,
    flags::ORPHAN_PARENT as i64,
];
const FILTER: &str = "SELECT count(*), count(*) FILTER (WHERE indexed_v = 1),
    count(*) FILTER (WHERE (honesty_flags & ?2) != 0),
    count(*) FILTER (WHERE (honesty_flags & ?3) != 0),
    count(*) FILTER (WHERE (honesty_flags & ?4) != 0),
    count(*) FILTER (WHERE (honesty_flags & ?5) != 0),
    count(*) FILTER (WHERE (honesty_flags & ?6) != 0),
    count(*) FILTER (WHERE (honesty_flags & ?7) != 0)
    FROM recording_frame_index WHERE recording_id = ?1";

fn baseline_sql() -> String {
    let source = include_str!("../src/recording_store.rs");
    let (_, function) = source.split_once("fn load_frame_honesty(").expect("production function");
    let (_, query) = function.split_once("\"SELECT count(*),").expect("production aggregate");
    let (rest, _) = query.split_once("\",").expect("end of production aggregate");
    format!("SELECT count(*),{rest}").replace("\\\n", " ")
}

fn production_fixture(connection: &Connection) -> rusqlite::Result<()> {
    let migrations = include_str!("../src/migrations.rs");
    let (_, first) = migrations
        .split_once("CREATE TABLE recording_frame_index (")
        .expect("production frame table");
    let (first, _) =
        first.split_once("CREATE TABLE recording_terminal_evidence").expect("end of frame schema");
    let (_, added) = migrations
        .split_once("const FRAME_INDEX_DEPTH_ASYNC_SCHEMA: &str = \"")
        .expect("production frame-index extension");
    let (added, _) = added.split_once("\";").expect("end of frame-index extension");
    // This isolated query fixture needs no recording or segment parent rows.
    connection.execute_batch("PRAGMA foreign_keys=OFF;")?;
    connection.execute_batch(&format!("CREATE TABLE recording_frame_index ({first}{added}"))
}

fn read(statement: &mut Statement<'_>, id: &[u8]) -> rusqlite::Result<[i64; 8]> {
    let [gap, redacted, truncated, unavailable, dropped, orphan] = MASKS;
    statement.query_row(
        params![id, gap, redacted, truncated, unavailable, dropped, orphan],
        |row| {
            let mut values = [0; 8];
            for (index, value) in values.iter_mut().enumerate() {
                *value = row.get(index)?;
            }
            Ok(values)
        },
    )
}

fn public_counts(raw: [i64; 8]) -> Option<FrameHonestyCounts> {
    let [total, indexed, gap, redacted, truncated, unavailable, dropped, orphan] = raw;
    if total != indexed {
        return None;
    }
    let count = |value| u64::try_from(value).unwrap_or(0);
    Some(FrameHonestyCounts {
        gap: count(gap),
        redacted: count(redacted),
        truncated: count(truncated),
        unavailable: count(unavailable),
        dropped: count(dropped),
        orphan_parent: count(orphan),
    })
}

fn tally(expected: &mut [i64; 8], indexed: Option<i64>, bits: Option<i64>) {
    expected[0] += 1;
    expected[1] += i64::from(indexed == Some(1));
    for (column, mask) in expected[2..].iter_mut().zip(MASKS) {
        *column += i64::from(bits.is_some_and(|bits| bits & mask != 0));
    }
}

fn verify(
    connection: &Connection,
    baseline: &str,
    id: &[u8],
    expected: [i64; 8],
) -> rusqlite::Result<()> {
    let old = read(&mut connection.prepare(baseline)?, id)?;
    let new = read(&mut connection.prepare(FILTER)?, id)?;
    assert_eq!(old, expected);
    assert_eq!(new, expected);
    assert_eq!(public_counts(old), public_counts(new));
    assert_eq!(public_counts(new).is_none(), expected[0] != expected[1]);
    Ok(())
}

fn verify_edges(baseline: &str) -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    // Separate nullable schema exercises SQL NULL semantics. The production
    // schema used below declares both predicate columns NOT NULL.
    connection.execute_batch(
        "CREATE TABLE recording_frame_index (recording_id BLOB, indexed_v INTEGER, honesty_flags INTEGER) STRICT;",
    )?;
    verify(&connection, baseline, &RECORDING, [0; 8])?;
    let mut expected = [0; 8];
    for (indexed, bits) in [
        (Some(1), None),
        (None, Some(-1)),
        (None, None),
        (Some(0), Some(0)),
        (Some(-1), Some(i64::MIN)),
        (Some(2), Some(1 << 61)),
        (Some(1), Some(0b101_0101)),
    ] {
        connection.execute(
            "INSERT INTO recording_frame_index VALUES (?1, ?2, ?3)",
            params![RECORDING.as_slice(), indexed, bits],
        )?;
        tally(&mut expected, indexed, bits);
        verify(&connection, baseline, &RECORDING, expected)?;
    }
    verify(&connection, baseline, &DECOY, [0; 8])
}

fn populate(mut connection: Connection) -> rusqlite::Result<[i64; 8]> {
    production_fixture(&connection)?;
    let transaction = connection.transaction()?;
    let mut expected = [0; 8];
    {
        let mut insert = transaction.prepare(
            "INSERT INTO recording_frame_index             (recording_id, recording_seq, frame_id, segment_ordinal, event_offset, event_id_digest,
             monotonic_ns, indexed_v, honesty_flags)
            VALUES (?1, ?2, ?3, ?4, 0, ?5, ?2, 1, ?6)",
        )?;
        for sequence in 0..ROWS {
            let sequence_bytes = u64::from(sequence + 2).to_be_bytes();
            let mut frame = [0_u8; 16];
            frame[..8].copy_from_slice(&sequence_bytes);
            frame[6] = 0x70;
            frame[8] = 0x80;
            frame[12..].copy_from_slice(&sequence.to_be_bytes());
            let mut digest = [0_u8; 32];
            digest[..8].copy_from_slice(&sequence_bytes);
            let bits = match sequence % 1024 {
                1..=6 => MASKS[(sequence % 1024 - 1) as usize],
                7 => MASKS.into_iter().fold(0, |all, mask| all | mask),
                8 => 1 << 61,
                _ => 0,
            };
            insert.execute(params![
                RECORDING.as_slice(),
                sequence_bytes.as_slice(),
                frame.as_slice(),
                i64::from(sequence),
                digest.as_slice(),
                bits,
            ])?;
            if sequence % 512 == 0 {
                insert.execute(params![
                    DECOY.as_slice(),
                    sequence_bytes.as_slice(),
                    frame.as_slice(),
                    i64::from(sequence),
                    digest.as_slice(),
                    -1_i64,
                ])?;
            }
            tally(&mut expected, Some(1), Some(bits));
        }
    }
    transaction.commit()?;
    Ok(expected)
}

fn query_plan(connection: &Connection, sql: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let [gap, redacted, truncated, unavailable, dropped, orphan] = MASKS;
    let rows = statement.query_map(
        params![RECORDING.as_slice(), gap, redacted, truncated, unavailable, dropped, orphan],
        |row| row.get(3),
    )?;
    rows.collect()
}

fn sample(statement: &mut Statement<'_>, expected: [i64; 8]) -> rusqlite::Result<(u128, i32)> {
    statement.reset_status(StatementStatus::VmStep);
    let started = Instant::now();
    let counts = read(statement, &RECORDING)?;
    let elapsed = started.elapsed().as_nanos();
    assert_eq!(counts, expected);
    let vm_steps = statement.get_status(StatementStatus::VmStep);
    assert!(vm_steps > 0);
    Ok((elapsed, vm_steps))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseline = baseline_sql();
    verify_edges(&baseline)?;
    let root =
        PathBuf::from(std::env::var_os("XTRACE_HONESTY_QUERY_SCRATCH").expect("private scratch"));
    let fixture = tempfile::Builder::new().tempdir_in(root)?;
    let file = fixture.path().join("synthetic.sqlite3");
    let expected = populate(Connection::open(&file)?)?;
    let connection = Connection::open(&file)?;
    connection.execute_batch("PRAGMA foreign_keys=OFF;")?;
    verify(&connection, &baseline, &RECORDING, expected)?;
    let mut decoy_expected = [0; 8];
    for _ in 0..ROWS.div_ceil(512) {
        tally(&mut decoy_expected, Some(1), Some(-1));
    }
    verify(&connection, &baseline, &DECOY, decoy_expected)?;
    connection.execute(
        "UPDATE recording_frame_index SET indexed_v=0 WHERE recording_id=?1 AND recording_seq=?2",
        params![RECORDING.as_slice(), 2_u64.to_be_bytes().as_slice()],
    )?;
    let mut legacy_expected = expected;
    legacy_expected[1] -= 1;
    verify(&connection, &baseline, &RECORDING, legacy_expected)?;
    connection.execute(
        "UPDATE recording_frame_index SET indexed_v=1 WHERE recording_id=?1 AND recording_seq=?2",
        params![RECORDING.as_slice(), 2_u64.to_be_bytes().as_slice()],
    )?;
    println!("fixtures=verified rows={ROWS}");
    let old_plan = query_plan(&connection, &baseline)?;
    let new_plan = query_plan(&connection, FILTER)?;
    assert!(!old_plan.is_empty() && !new_plan.is_empty());
    println!("plan_equal={}", old_plan == new_plan);
    eprintln!("baseline_plan={old_plan:?}\nfilter_plan={new_plan:?}");
    let mut old = connection.prepare(&baseline)?;
    let mut new = connection.prepare(FILTER)?;
    sample(&mut old, expected)?;
    sample(&mut new, expected)?;
    for pair in 1..=8 {
        let (baseline, filter) = if pair % 2 == 1 {
            (sample(&mut old, expected)?, sample(&mut new, expected)?)
        } else {
            let filter = sample(&mut new, expected)?;
            let baseline = sample(&mut old, expected)?;
            (baseline, filter)
        };
        println!(
            "pair={pair} baseline_ns={} filter_ns={} baseline_steps={} filter_steps={}",
            baseline.0, filter.0, baseline.1, filter.1,
        );
    }
    println!("measurement=complete");
    Ok(())
}
