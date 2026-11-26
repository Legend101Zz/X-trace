//! Optional Linux thread timings at existing cardinality progress boundaries.
//! An interval spans phases and may contain profiler I/O and scheduling noise.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::Instant;

use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};

struct Sample {
    wall: Instant,
    cpu_ns: Option<u128>,
    runqueue_ns: Option<u128>,
}

pub(super) struct ThreadTiming {
    output: File,
    schedstats_enabled: bool,
    previous: Option<Sample>,
}

impl ThreadTiming {
    pub(super) fn open(directory: &Path, name: &str) -> Option<Self> {
        if std::env::var_os("XTRACE_STORE_THREAD_TIMING").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return None;
        }
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(format!("store-{name}-thread.txt")))
            .ok()?;
        let schedstats_enabled =
            proc_text("/proc/sys/kernel/sched_schedstats").is_some_and(|value| value.trim() == "1");
        Some(Self { output, schedstats_enabled, previous: None })
    }

    pub(super) fn sample(&mut self, completed: usize) {
        let current = Sample {
            wall: Instant::now(),
            cpu_ns: thread_cpu_ns(),
            runqueue_ns: self.schedstats_enabled.then(runqueue_ns).flatten(),
        };
        let (wall, cpu, runqueue) = self.previous.as_ref().map_or((None, None, None), |previous| {
            (
                current.wall.checked_duration_since(previous.wall).map(|delta| delta.as_nanos()),
                delta(current.cpu_ns, previous.cpu_ns),
                delta(current.runqueue_ns, previous.runqueue_ns),
            )
        });
        let residual = wall.and_then(|wall| wall.checked_sub(cpu?)?.checked_sub(runqueue?));
        self.previous = Some(current);
        // Evidence is optional. An unavailable measurement must not alter a workload result.
        let _ = writeln!(
            self.output,
            "phase_spanning completed={completed} wall_ns={} thread_cpu_ns={} runqueue_ns={} unclassified_ns={}",
            field(wall),
            field(cpu),
            field(runqueue),
            field(residual),
        );
    }
}

fn delta(current: Option<u128>, previous: Option<u128>) -> Option<u128> {
    current?.checked_sub(previous?)
}

fn field(value: Option<u128>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn thread_cpu_ns() -> Option<u128> {
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u128::try_from(value.tv_sec).ok()?;
    let nanos = u128::try_from(value.tv_nsec).ok().filter(|value| *value < 1_000_000_000)?;
    Some(seconds * 1_000_000_000 + nanos)
}

fn runqueue_ns() -> Option<u128> {
    let text = proc_text("/proc/thread-self/schedstat")?;
    if !text.ends_with('\n') {
        return None;
    }
    let mut fields = text.split_ascii_whitespace();
    let _runtime: u64 = fields.next()?.parse().ok()?;
    let wait: u64 = fields.next()?.parse().ok()?;
    let _timeslices: u64 = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some(u128::from(wait))
}

fn proc_text(path: &str) -> Option<String> {
    let mut text = String::new();
    File::open(path).ok()?.take(128).read_to_string(&mut text).ok()?;
    Some(text)
}
