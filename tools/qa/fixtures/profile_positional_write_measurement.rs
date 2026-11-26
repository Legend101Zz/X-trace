//! Hosted-only microbenchmark of the fixed-size active work-profile overwrite.
use std::fs::{File, OpenOptions};
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::Instant;

const WIDTH: usize = 160;
const TRANSITIONS: usize = 7_000_000;
const PAIRS: usize = 4;

fn patterns() -> Vec<[u8; WIDTH]> {
    (0..4096)
        .map(|index| {
            let phase = match index % 2 {
                0 => "checkpoint_publish",
                _ => "connection_file_admission",
            };
            let line = format!("elapsed_ns={} completed={} active={phase}", index * 2001, index);
            let mut record = [b' '; WIDTH];
            record[..line.len()].copy_from_slice(line.as_bytes());
            record[WIDTH - 1] = b'\n';
            record
        })
        .collect()
}

fn fresh(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

fn overwrite(file: &mut File, record: &[u8; WIDTH], positional: bool) -> io::Result<()> {
    if positional {
        file.write_all_at(record, 0)
    } else {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(record)
    }
}

fn verify(file: &File, record: &[u8; WIDTH]) -> io::Result<()> {
    let mut observed = [0; WIDTH];
    file.read_exact_at(&mut observed, 0)?;
    assert!(observed == *record, "active record bytes differ");
    assert_eq!(file.metadata()?.len(), WIDTH as u64, "active record length changed");
    Ok(())
}

fn time(path: &Path, records: &[[u8; WIDTH]], positional: bool) -> io::Result<u128> {
    let mut file = fresh(path)?;
    for record in records {
        overwrite(&mut file, record, positional)?;
    }
    let started = Instant::now();
    for record in records.iter().cycle().take(TRANSITIONS) {
        overwrite(&mut file, record, positional)?;
    }
    let nanos = started.elapsed().as_nanos();
    verify(&File::open(path)?, &records[(TRANSITIONS - 1) % records.len()])?;
    assert_eq!(file.stream_position()?, if positional { 0 } else { WIDTH as u64 });
    Ok(nanos)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::var_os("XTRACE_PROFILE_WRITE_SCRATCH").expect("private fixture directory");
    let root = Path::new(&root);
    let records = patterns();

    // Independently read back every byte after every overwrite. Reading is
    // outside the timed trials so it cannot hide the cost of the extra seek.
    let sequential_path = root.join("validation-sequential");
    let positional_path = root.join("validation-positional");
    let mut sequential = fresh(&sequential_path)?;
    let mut positional = fresh(&positional_path)?;
    let sequential_reader = File::open(sequential_path)?;
    let positional_reader = File::open(positional_path)?;
    for record in records.iter().cycle().take(TRANSITIONS) {
        overwrite(&mut sequential, record, false)?;
        overwrite(&mut positional, record, true)?;
        verify(&sequential_reader, record)?;
        verify(&positional_reader, record)?;
    }
    println!("validated_transitions_per_method={TRANSITIONS}");

    for pair in 1..=PAIRS {
        let seq_path = root.join(format!("sequential-{pair}"));
        let pos_path = root.join(format!("positional-{pair}"));
        let (sequential, positional) = if pair % 2 == 1 {
            (time(&seq_path, &records, false)?, time(&pos_path, &records, true)?)
        } else {
            let positional = time(&pos_path, &records, true)?;
            let sequential = time(&seq_path, &records, false)?;
            (sequential, positional)
        };
        println!(
            "pair={pair} transitions={TRANSITIONS} sequential_ns={sequential} positional_ns={positional}"
        );
    }
    println!("measurement=complete");
    Ok(())
}
