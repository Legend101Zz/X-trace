//! Pre-allocated private branch pool for `xtrace-daemon` unit tests.
//!
//! Parallel unit tests that concurrently create and drop directories directly inside
//! `XTRACE_TEST_PRIVATE_SCRATCH` advance the shared scratch directory's metadata
//! (`ctime`/`mtime`, including zero-net-`nlink` create+remove pairs) during a sibling's
//! `AdmittedPrivateRoot::open` or ancestor walk (failing Linux `ProbeSnapshot` and macOS
//! `MemoState` probes). Pre-creating one process-unique family directory and a fixed pool
//! of exclusive private slots inside `OnceLock::get_or_init` ensures neither `$scratch`
//! nor the family directory is mutated once any test begins running, without weakening any
//! admission, ACL, or symlink check.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use xtrace_private_storage::AdmittedPrivateRoot;

const SLOT_COUNT: usize = 64;

static SLOTS: OnceLock<Vec<AdmittedPrivateRoot>> = OnceLock::new();
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

fn init_slots() -> Vec<AdmittedPrivateRoot> {
    let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
        .map(PathBuf::from)
        .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required");
    let root = AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let family_name = format!("xtrace-daemon-{}-{nanos}", std::process::id());
    let family = root.create_private_child(&family_name).expect("private daemon test family");
    (0..SLOT_COUNT)
        .map(|slot| {
            family
                .create_private_child(&format!("s{slot:02}"))
                .expect("pre-allocated private daemon test slot")
        })
        .collect()
}

/// Return an exclusive pre-allocated admitted private branch under `XTRACE_TEST_PRIVATE_SCRATCH`.
#[track_caller]
pub(crate) fn private_branch(_label: &str) -> &'static AdmittedPrivateRoot {
    let slots = SLOTS.get_or_init(init_slots);
    let index = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
    assert!(
        index < slots.len(),
        "xtrace-daemon test_scratch::SLOT_COUNT ({SLOT_COUNT}) exhausted; increase SLOT_COUNT"
    );
    &slots[index]
}
