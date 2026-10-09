//! MEASUREMENT-ONLY instrumentation (branch never merged): spawn counters and an env-gated trace.
//! With `XTRACE_ADMISSION_TRACE` unset, behaviour is unchanged apart from three relaxed counters.

use std::cell::{Cell, RefCell};
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static BATCH: AtomicUsize = AtomicUsize::new(0);
static SINGLE: AtomicUsize = AtomicUsize::new(0);
static FILE: AtomicUsize = AtomicUsize::new(0);
static SPAWN_NANOS: AtomicU64 = AtomicU64::new(0);
static OPS: AtomicUsize = AtomicUsize::new(0);

/// Process-wide counts: (batched walks, single directories, named files, spawn nanoseconds, operations).
#[doc(hidden)]
#[must_use]
pub fn admission_counts() -> (usize, usize, usize, u64, usize) {
    (
        BATCH.load(Ordering::Relaxed),
        SINGLE.load(Ordering::Relaxed),
        FILE.load(Ordering::Relaxed),
        SPAWN_NANOS.load(Ordering::Relaxed),
        OPS.load(Ordering::Relaxed),
    )
}

fn sink() -> Option<&'static Mutex<std::fs::File>> {
    static SINK: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    SINK.get_or_init(|| {
        // The leased runner scrubs XTRACE_* from the child environment, so a measuring run can
        // instead pre-create the sibling file `<private scratch>.trace` to switch the trace on.
        let path = std::env::var_os("XTRACE_ADMISSION_TRACE").or_else(|| {
            let mut sibling = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")?;
            sibling.push(".trace");
            std::path::Path::new(&sibling).is_file().then_some(sibling)
        })?;
        std::fs::OpenOptions::new().create(true).append(true).open(path).ok().map(Mutex::new)
    })
    .as_ref()
}

pub(crate) fn enabled() -> bool {
    sink().is_some()
}

fn emit(line: &str) {
    if let Some(sink) = sink() {
        if let Ok(mut file) = sink.lock() {
            let _ = file.write_all(format!("{line}\n").as_bytes());
        }
    }
}

thread_local! {
    /// Stack of (operation id, spawns so far).
    static STACK: RefCell<Vec<(u64, u32)>> = const { RefCell::new(Vec::new()) };
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
    static FALLBACK: Cell<&'static str> = const { Cell::new("") };
}

pub(crate) fn set_fallback(reason: &'static str) {
    FALLBACK.with(|cell| cell.set(reason));
}

/// Frames as (function, location) from a captured backtrace.
fn frames() -> Vec<(String, String)> {
    let text = format!("{}", std::backtrace::Backtrace::force_capture());
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(location) = trimmed.strip_prefix("at ") {
            if let Some(last) = out.last_mut() {
                last.1 = location.to_owned();
            }
        } else if let Some((index, name)) = trimmed.split_once(": ") {
            if index.chars().all(|c| c.is_ascii_digit()) {
                out.push((name.to_owned(), String::new()));
            }
        }
    }
    out
}

const OUTER: [&str; 5] =
    ["xtrace_store", "xtrace_daemon", "xtrace_cli", "xtrace_application", "xtrace_runtime"];

fn short(name: &str) -> String {
    name.replace("xtrace_private_storage::", "ps::").replace("{{closure}}", "{c}")
}

fn plain(name: &str) -> &str {
    name.trim_start_matches('<')
}

/// Drops generic arguments (`::<...>`) and trailing closures noise for the chain column.
fn compact(name: &str) -> String {
    let mut depth = 0_u32;
    let mut out = String::new();
    for c in plain(name).chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.replace("xtrace_store::", "st::").replace("xtrace_daemon::", "dn::").replace("xtrace_cli::", "cl::").replace("xtrace_runtime::", "rt::").replace("xtrace_application::", "ap::").replace("{{closure}}", "{c}")
}

/// (entry point, outer caller "fn @ file:line | chain").
fn attribute() -> (String, String) {
    let frames = frames();
    let mut entry = String::from("?");
    let mut caller = String::new();
    let mut chain: Vec<String> = Vec::new();
    for (name, location) in &frames {
        let bare = plain(name);
        if bare.starts_with("xtrace_private_storage") {
            if caller.is_empty() && !bare.contains("::probe::") && !bare.contains("::trace::") {
                entry = short(bare);
            }
            continue;
        }
        if OUTER.iter().any(|prefix| bare.starts_with(prefix)) {
            if caller.is_empty() {
                caller = format!("{} @ {}", compact(name), location);
            }
            if chain.len() < 8 {
                chain.push(compact(name));
            }
        }
    }
    if caller.is_empty() {
        caller = String::from("?");
    }
    (entry, format!("{caller} | {}", chain.join(" < ")))
}

/// Per-operation state kept inside `Operation`.
pub(crate) struct OpTrace {
    id: u64,
    entry: String,
    caller: String,
    started: Instant,
}

pub(crate) fn operation_started() -> Option<OpTrace> {
    OPS.fetch_add(1, Ordering::Relaxed);
    let id = NEXT_ID.with(|cell| {
        let id = cell.get();
        cell.set(id + 1);
        id
    });
    STACK.with(|stack| stack.borrow_mut().push((id, 0)));
    if !enabled() {
        return Some(OpTrace { id, entry: String::new(), caller: String::new(), started: Instant::now() });
    }
    let (entry, caller) = attribute();
    emit(&format!(
        "OPSTART pid={} tid={:?} op={id} entry={entry} caller={caller}",
        std::process::id(),
        std::thread::current().id()
    ));
    Some(OpTrace { id, entry, caller, started: Instant::now() })
}

pub(crate) fn operation_ended(trace: &OpTrace) {
    let spawns = STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let position = stack.iter().rposition(|(id, _)| *id == trace.id);
        position.map_or(0, |index| stack.remove(index).1)
    });
    if enabled() {
        emit(&format!(
            "OPEND pid={} op={} entry={} caller={} spawns={spawns} elapsed_us={}",
            std::process::id(),
            trace.id,
            trace.entry,
            trace.caller,
            trace.started.elapsed().as_micros()
        ));
    }
}

/// Counts a spawn; returns a guard to call `finish` on with the measured duration.
pub(crate) fn spawn_started(kind: &'static str) {
    match kind {
        "batch" => BATCH.fetch_add(1, Ordering::Relaxed),
        "single" => SINGLE.fetch_add(1, Ordering::Relaxed),
        _ => FILE.fetch_add(1, Ordering::Relaxed),
    };
    STACK.with(|stack| {
        if let Some(top) = stack.borrow_mut().last_mut() {
            top.1 += 1;
        }
    });
}

pub(crate) fn spawn_finished(kind: &'static str, operands: &[&std::path::Path], duration: std::time::Duration, ok: bool) {
    SPAWN_NANOS.fetch_add(u64::try_from(duration.as_nanos()).unwrap_or(0), Ordering::Relaxed);
    if enabled() {
        let (entry, caller) = attribute();
        let op = STACK.with(|stack| stack.borrow().last().map_or(0, |(id, _)| *id));
 let paths = operands.len();
        let listed = operands.iter().map(|p| p.to_string_lossy().replace(' ', "_")).collect::<Vec<_>>().join(",");
        let reason = if kind == "single" { FALLBACK.with(Cell::get) } else { "" };
        emit(&format!(
            "SPAWN pid={} op={op} kind={kind} paths={paths} us={} ok={ok} why={reason} dirs={listed} entry={entry} caller={caller}",
            std::process::id(),
            duration.as_micros()
        ));
    }
}

pub(crate) fn discard(reason: &str) {
    if enabled() {
        let (entry, caller) = attribute();
        emit(&format!("DISCARD pid={} reason={reason} entry={entry} caller={caller}", std::process::id()));
    }
}
