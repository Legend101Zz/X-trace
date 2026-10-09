//! `xtrace doctor` (lane P).
//!
//! Read-only diagnostics. Each check reports `ok`, `warn`, `fail` or `unavailable`; a check this build
//! cannot perform is `unavailable` with the reason, never `ok`. Nothing here writes to the store, takes
//! the project lock for longer than a probe, or signals a process. `--bundle` (a sanitized support
//! bundle) is not implemented in this build and fails loudly rather than being ignored.

use std::path::PathBuf;

use serde::Serialize;

use crate::error::CliError;

/// Arguments for `xtrace doctor`.
#[derive(Clone, Debug, clap::Args)]
pub struct DoctorArgs {
    /// Path to the repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Write a diagnostic bundle to this path.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,
    /// Confirm without prompting.
    #[arg(long)]
    pub yes: bool,
}

/// Outcome of one check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Ok,
    Warn,
    Fail,
    Unavailable,
}

/// One diagnostic line.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Check {
    pub(crate) id: &'static str,
    pub(crate) status: Status,
    pub(crate) detail: String,
}

impl Check {
    fn new(id: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self { id, status, detail: detail.into() }
    }
}

#[derive(Debug, Serialize)]
struct Summary {
    ok: usize,
    warn: usize,
    fail: usize,
    unavailable: usize,
}

#[derive(Debug, Serialize)]
struct DoctorDocument {
    kind: &'static str,
    version: &'static str,
    schema_version: u32,
    overall: Status,
    summary: Summary,
    checks: Vec<Check>,
}

pub(crate) fn summarize(checks: &[Check]) -> (Status, [usize; 4]) {
    let mut counts = [0_usize; 4];
    for check in checks {
        let index = match check.status {
            Status::Ok => 0,
            Status::Warn => 1,
            Status::Fail => 2,
            Status::Unavailable => 3,
        };
        counts[index] += 1;
    }
    let overall = if counts[2] > 0 {
        Status::Fail
    } else if counts[1] > 0 {
        Status::Warn
    } else {
        Status::Ok
    };
    (overall, counts)
}

/// Runs `xtrace doctor`.
pub async fn run(args: DoctorArgs) -> Result<i32, CliError> {
    if args.bundle.is_some() {
        return Err(CliError::NotImplemented { command: "doctor --bundle" });
    }
    let checks = collect(&args.project_dir);
    let (overall, counts) = summarize(&checks);
    let document = DoctorDocument {
        kind: "doctor_report",
        version: env!("CARGO_PKG_VERSION"),
        schema_version: xtrace_store::CURRENT_SCHEMA_VERSION,
        overall,
        summary: Summary {
            ok: counts[0],
            warn: counts[1],
            fail: counts[2],
            unavailable: counts[3],
        },
        checks,
    };
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    crate::output::write_success(&mut handle, &document)?;
    Ok(if overall == Status::Fail { 1 } else { 0 })
}

fn collect(project_dir: &std::path::Path) -> Vec<Check> {
    let mut checks = vec![Check::new(
        "binary",
        Status::Ok,
        format!(
            "xtrace {} with store schema {}",
            env!("CARGO_PKG_VERSION"),
            xtrace_store::CURRENT_SCHEMA_VERSION
        ),
    )];
    checks.push(packs_check("java"));
    checks.push(packs_check("node"));
    #[cfg(not(unix))]
    checks.push(Check::new(
        "project",
        Status::Unavailable,
        "project diagnostics need the Unix private-storage layer",
    ));
    #[cfg(unix)]
    unix_project_checks(project_dir, &mut checks);
    #[cfg(not(unix))]
    let _ = project_dir;
    checks
}

fn packs_check(language: &'static str) -> Check {
    use xtrace_runtime::pack_discovery::{PackTrustState, locate};
    let id = if language == "java" { "pack_java" } else { "pack_node" };
    let Ok(exe) = std::env::current_exe().and_then(|path| path.canonicalize()) else {
        return Check::new(id, Status::Unavailable, "the executable path cannot be resolved");
    };
    match locate(&exe, language) {
        None => Check::new(
            id,
            Status::Unavailable,
            "no installed pack next to this executable (running from a build tree, or not installed)",
        ),
        Some(pack) => match pack.trust {
            PackTrustState::UnsignedLayout => Check::new(
                id,
                Status::Warn,
                "installed pack has no xtrace-pack.json: unsigned layout, publisher not verified",
            ),
            PackTrustState::Verified => Check::new(
                id,
                Status::Ok,
                "pack manifest verifies against the built-in trust table",
            ),
            PackTrustState::Untrusted(code) => Check::new(
                id,
                Status::Fail,
                format!("pack manifest is not trusted by this build ({code})"),
            ),
        },
    }
}

#[cfg(unix)]
fn unix_project_checks(project_dir: &std::path::Path, checks: &mut Vec<Check>) {
    use xtrace_application::recording_queries::{
        RecordingCompletionEvidence, RecordingReadPort as _, RecordingStatus,
    };
    use xtrace_store::{OpenOptions, SqliteRecordingReader, SqliteStore};

    let env_reader = crate::paths::read_env_path;
    let preflight = match crate::daemon::preflight_project(project_dir, &env_reader) {
        Ok(preflight) => preflight,
        Err(error) => {
            checks.push(Check::new(
                "project",
                Status::Fail,
                format!("the project cannot be opened for diagnostics: {error}"),
            ));
            return;
        }
    };
    checks.push(Check::new(
        "private_storage",
        Status::Ok,
        "project data root passed private-storage admission and the store file is a private regular file",
    ));

    let root = preflight.private_root.path().to_path_buf();
    match crate::daemon_lock::project_lock_is_held(&preflight.private_root) {
        Ok(true) => checks.push(Check::new(
            "daemon_lock",
            Status::Ok,
            "a process holds the project daemon lock (a daemon or run is active)",
        )),
        Ok(false) => {
            checks.push(Check::new("daemon_lock", Status::Ok, "no daemon holds the project lock"))
        }
        Err(error) => checks.push(Check::new(
            "daemon_lock",
            Status::Fail,
            format!("the project lock cannot be probed: {error}"),
        )),
    }

    let database = root.join("metadata.sqlite3");
    let store = SqliteStore::open(
        &database,
        OpenOptions::default().with_must_exist(true).with_read_only(true),
    );
    let store = match store {
        Ok(store) => {
            checks.push(Check::new(
                "store_schema",
                Status::Ok,
                format!(
                    "store opened read-only; schema matches this build ({})",
                    xtrace_store::CURRENT_SCHEMA_VERSION
                ),
            ));
            store
        }
        Err(error) => {
            let mapped = crate::commands::map_store_error(error);
            checks.push(Check::new(
                "store_schema",
                Status::Fail,
                format!("the store cannot be opened read-only: {mapped}"),
            ));
            return;
        }
    };
    checks.push(Check::new(
        "store_integrity",
        Status::Unavailable,
        "a full SQLite integrity and object-hash scan is not available in this build",
    ));

    let reader = SqliteRecordingReader::new(store, root);
    let mut open = 0_usize;
    let mut total = 0_usize;
    let mut after = None;
    loop {
        match reader.list_recordings(preflight.project_id, after, 200) {
            Ok((page, more)) => {
                total += page.len();
                open += page
                    .iter()
                    .filter(|item| {
                        matches!(
                            item.status,
                            RecordingStatus::Recording | RecordingStatus::Finalizing
                        ) && item.completion != RecordingCompletionEvidence::Complete
                    })
                    .count();
                match (more, page.last()) {
                    (true, Some(last)) => after = Some(last.recording_id),
                    _ => break,
                }
            }
            Err(_) => {
                checks.push(Check::new(
                    "recordings",
                    Status::Fail,
                    "recordings cannot be listed from the store",
                ));
                return;
            }
        }
    }
    let lock_held = checks
        .iter()
        .any(|check| check.id == "daemon_lock" && check.detail.starts_with("a process holds"));
    checks.push(if open > 0 && !lock_held {
        Check::new(
            "recordings",
            Status::Warn,
            format!(
                "{total} recordings, {open} left open by a daemon that is no longer running; \
                 `xtrace restart` or `xtrace stop` seals them as partial"
            ),
        )
    } else {
        Check::new("recordings", Status::Ok, format!("{total} recordings, {open} currently open"))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_is_the_worst_actionable_status_and_unavailable_never_counts_as_ok() {
        let checks =
            vec![Check::new("a", Status::Ok, ""), Check::new("b", Status::Unavailable, "")];
        let (overall, counts) = summarize(&checks);
        assert_eq!(overall, Status::Ok);
        assert_eq!(counts, [1, 0, 0, 1]);
        let checks = vec![Check::new("a", Status::Warn, ""), Check::new("b", Status::Fail, "")];
        assert_eq!(summarize(&checks).0, Status::Fail);
    }
}
