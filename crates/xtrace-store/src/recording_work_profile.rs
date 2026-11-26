//! Numeric, thread-local CI diagnostics for the two full-cardinality store tests.
//! No worker, sleep, captured value, path or recording identity is recorded.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::time::Instant;

use xtrace_private_storage::spawn_counter::ls_spawns_on_this_thread;
#[cfg(target_os = "linux")]
use xtrace_private_storage::spawn_counter::{linux_acl_probe_counts, set_linux_acl_probe_counting};

thread_local! {
    static PROFILE: RefCell<Option<Profile>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct Measurement {
    spans: u64,
    ns: u128,
    max_ns: u128,
    probes: u64,
}

struct Profile {
    #[cfg(unix)]
    checkpoint_detail: bool,
    #[cfg(unix)]
    checkpoint_prepare_detail: bool,
    segment_sql_detail: bool,
    started: Instant,
    changed: Instant,
    probes: u64,
    active: &'static str,
    completed: usize,
    phases: BTreeMap<&'static str, Measurement>,
    current: File,
    history: File,
}

impl Profile {
    fn transition(&mut self, next: &'static str) {
        let now = Instant::now();
        let probes = ls_spawns_on_this_thread();
        let measurement = self.phases.entry(self.active).or_default();
        let ns = now.duration_since(self.changed).as_nanos();
        measurement.spans += 1;
        measurement.ns += ns;
        measurement.max_ns = measurement.max_ns.max(ns);
        measurement.probes += probes - self.probes;
        self.active = next;
        // Fixed-size overwrite: a timeout retains the entered phase even if
        // that operation never returns. These diagnostic writes are not synced.
        let line = format!(
            "elapsed_ns={} completed={} active={next}",
            now.duration_since(self.started).as_nanos(),
            self.completed,
        );
        assert!(line.len() < 160);
        let mut record = [b' '; 160];
        record[..line.len()].copy_from_slice(line.as_bytes());
        record[159] = b'\n';
        self.current.seek(SeekFrom::Start(0)).expect("seek work profile");
        self.current.write_all(&record).expect("write active work phase");
        // Exclude the profiler's own write cost from the phase being measured.
        self.changed = Instant::now();
        self.probes = probes;
    }

    fn report(&mut self, state: &'static str) {
        let active = self.active;
        self.transition(active);
        writeln!(
            self.history,
            "state={state} completed={} elapsed_ns={}",
            self.completed,
            self.started.elapsed().as_nanos(),
        )
        .expect("write work progress");
        for (name, value) in &self.phases {
            writeln!(
                self.history,
                "phase={name} spans={} total_ns={} max_ns={} acl_probes={}",
                value.spans, value.ns, value.max_ns, value.probes,
            )
            .expect("write work measurements");
        }
        #[cfg(target_os = "linux")]
        if let Some([directory, named_file, descriptor_file]) = linux_acl_probe_counts() {
            writeln!(
                self.history,
                "linux_acl_directory={directory} linux_acl_named_file={named_file} linux_acl_descriptor_file={descriptor_file}",
            )
            .expect("write Linux ACL probe counts");
        }
        self.changed = Instant::now();
    }
}

/// Owns a profile only when the existing CI artifact directory is available.
pub(crate) struct WorkProfile;

impl WorkProfile {
    pub(crate) fn start(
        name: &'static str,
        expected_admissions: usize,
        counted_syncs: bool,
    ) -> Self {
        if let Some(root) = std::env::var_os("XTRACE_CI_PRIVATE_ROOT") {
            let directory = std::path::PathBuf::from(root).join("frag");
            let open = |suffix| {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                options
                    .open(directory.join(format!("store-{name}-{suffix}.txt")))
                    .expect("create numeric work artifact")
            };
            #[cfg(unix)]
            let checkpoint_detail = std::env::var_os("XTRACE_CHECKPOINT_PROFILE_DETAIL")
                .is_some_and(|value| value == "1");
            #[cfg(target_os = "linux")]
            set_linux_acl_probe_counting(checkpoint_detail);
            let now = Instant::now();
            let mut profile = Profile {
                #[cfg(unix)]
                checkpoint_detail,
                #[cfg(unix)]
                checkpoint_prepare_detail: std::env::var_os("XTRACE_CHECKPOINT_PREPARE_DETAIL")
                    .is_some_and(|value| value == "1"),
                segment_sql_detail: std::env::var_os("XTRACE_SEGMENT_SQL_DETAIL")
                    .is_some_and(|value| value == "1"),
                started: now,
                changed: now,
                probes: ls_spawns_on_this_thread(),
                active: "fixture",
                completed: 0,
                phases: BTreeMap::new(),
                current: open("active"),
                history: open("progress"),
            };
            writeln!(
                profile.history,
                "expected_admissions={expected_admissions} counted_journal_syncs={counted_syncs}"
            )
            .expect("write workload description");
            profile.report("started");
            PROFILE.with(|slot| assert!(slot.replace(Some(profile)).is_none()));
        }
        Self
    }

    pub(crate) fn progress(&self, completed: usize) {
        PROFILE.with(|slot| {
            if let Some(profile) = slot.borrow_mut().as_mut() {
                profile.completed = completed;
                profile.report("progress");
            }
        });
    }
}

impl Drop for WorkProfile {
    fn drop(&mut self) {
        PROFILE.with(|slot| {
            if let Some(mut profile) = slot.take() {
                profile.report(if std::thread::panicking() { "unwinding" } else { "returned" });
                #[cfg(target_os = "linux")]
                set_linux_acl_probe_counting(false);
            }
        });
    }
}

/// Nested phases account exclusive time; lock waits are separate from admission.
pub(crate) struct Phase(Option<&'static str>);

impl Phase {
    pub(crate) fn directory_sync_name() -> &'static str {
        PROFILE.with(|slot| {
            if slot
                .borrow()
                .as_ref()
                .is_some_and(|profile| profile.active == "checkpoint_directory_sync_dispatch")
            {
                "checkpoint_directory_sync"
            } else {
                "directory_sync"
            }
        })
    }

    #[cfg(unix)]
    pub(crate) fn checkpoint_detail(name: &'static str) -> Option<Self> {
        let enabled = PROFILE
            .with(|slot| slot.borrow().as_ref().is_some_and(|profile| profile.checkpoint_detail));
        enabled.then(|| Self::enter(name))
    }

    #[cfg(unix)]
    pub(crate) fn checkpoint_prepare_detail(name: &'static str) -> Option<Self> {
        let enabled = PROFILE.with(|slot| {
            slot.borrow().as_ref().is_some_and(|profile| profile.checkpoint_prepare_detail)
        });
        enabled.then(|| Self::enter(name))
    }

    pub(crate) fn segment_sql_detail(name: &'static str) -> Option<Self> {
        let enabled = PROFILE
            .with(|slot| slot.borrow().as_ref().is_some_and(|profile| profile.segment_sql_detail));
        enabled.then(|| Self::enter(name))
    }

    pub(crate) fn enter(name: &'static str) -> Self {
        Self(PROFILE.with(|slot| {
            slot.borrow_mut().as_mut().map(|profile| {
                let previous = profile.active;
                profile.transition(name);
                previous
            })
        }))
    }

    pub(crate) fn switch(&mut self, name: &'static str) {
        PROFILE.with(|slot| {
            if let Some(profile) = slot.borrow_mut().as_mut() {
                if profile.active != name {
                    profile.transition(name);
                }
            }
        });
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        // Keep the failing phase in the artifact while outer guards unwind.
        if !std::thread::panicking() {
            if let Some(previous) = self.0 {
                self.switch(previous);
            }
        }
    }
}
