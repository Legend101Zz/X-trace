//! Hosted-only paired measurement over the same admitted root and fixture path.
use std::path::Path;
use std::time::Instant;

use xtrace_private_storage::AdmittedPrivateRoot;

const WARMUP: usize = 2_000;
const ITERATIONS: usize = 50_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var_os("XTRACE_SNAPSHOT_STATE_FIXTURE").expect("private fixture");
    let root = AdmittedPrivateRoot::open(Path::new(&path))?;
    for _ in 0..WARMUP {
        root.revalidate()?;
    }
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        root.revalidate()?;
    }
    let elapsed = started.elapsed().as_nanos();
    println!("completed={ITERATIONS} elapsed_ns={elapsed}");
    Ok(())
}
