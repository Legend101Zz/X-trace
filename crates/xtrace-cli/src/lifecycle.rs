//! `xtrace record`, `stop` and `restart` (lane P).
//!
//! What the commands mean in v0.0.1:
//!
//! * `record` starts the project's recording daemon as a detached process
//!   (`xtrace daemon --project-dir <DIR>`), waits for its readiness document,
//!   and records the daemon's identity (PID, process start time, executable)
//!   in a private state file under the project's `.daemon` directory. The
//!   daemon publishes a one-shot bootstrap artifact; that arms capture for
//!   exactly one next launch (multi-session grants are a later contract).
//!   Before starting it, recordings that a previous daemon left open are
//!   sealed as partial (see `recover_interrupted` below).
//! * `stop` signals the daemon with SIGTERM only after proving that the PID in
//!   the state file still is that daemon (same process start time, same
//!   executable and a `daemon` command line). It waits
//!   for the daemon to release its lock, then seals recordings the daemon left
//!   open as partial.
//! * `restart` is `stop` (a daemon that is not running is not an error) then
//!   `record`, preserving the store.
//!
//! No command ever signals a process found by name or pattern.

use std::path::PathBuf;

use crate::error::CliError;

/// Arguments for `xtrace record`.
#[derive(Clone, Debug, clap::Args)]
pub struct RecordArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Accepted for compatibility; output is always JSON.
    #[arg(long)]
    pub json: bool,
    /// Capture depth, application scope and launcher: the same inputs, with the same validation,
    /// as `xtrace run` (CONTRACTS 11.2).
    #[command(flatten)]
    pub capture: crate::capture_args::CaptureArgs,
}

/// Arguments for `xtrace stop`.
#[derive(Clone, Debug, clap::Args)]
pub struct StopArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Accepted for compatibility; output is always JSON.
    #[arg(long)]
    pub json: bool,
    /// Session to end; must equal the running daemon's runtime session id.
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
}

/// Arguments for `xtrace restart`.
#[derive(Clone, Debug, clap::Args)]
pub struct RestartArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Accepted for compatibility; output is always JSON.
    #[arg(long)]
    pub json: bool,
    /// Capture depth, application scope and launcher: the same inputs, with the same validation,
    /// as `xtrace run` (CONTRACTS 11.2).
    #[command(flatten)]
    pub capture: crate::capture_args::CaptureArgs,
}

/// Runs `xtrace record`.
pub async fn run_record(args: RecordArgs) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        Err(CliError::DaemonUnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let capture = args.capture.validate()?;
        unix::record(args.project_dir, &capture)
    }
}

/// Runs `xtrace stop`.
pub async fn run_stop(args: StopArgs) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        Err(CliError::DaemonUnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        unix::stop(args.project_dir, args.session)
    }
}

/// Runs `xtrace restart`.
pub async fn run_restart(args: RestartArgs) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        Err(CliError::DaemonUnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let capture = args.capture.validate()?;
        unix::restart(args.project_dir, &capture)
    }
}

/// What `daemon.json` says compared with what is actually running (for `xtrace doctor`).
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LifecycleState {
    /// No daemon record exists.
    NoRecord,
    /// The record names the live recorded daemon.
    Verified,
    /// The record names a process that is not the recorded daemon (or no process at all).
    Stale(String),
    /// The record or `ps` could not be read; nothing is inferred.
    Unavailable(String),
}

/// Inspects the daemon record without changing anything.
#[cfg(unix)]
pub(crate) fn lifecycle_state(
    private_root: &xtrace_private_storage::AdmittedPrivateRoot,
) -> LifecycleState {
    unix::lifecycle_state(private_root)
}

#[cfg(unix)]
mod unix {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};
    use xtrace_application::recording::{FinishRecording, RecordingPersistencePort as _};
    use xtrace_application::recording_queries::{
        RecordingCompletionEvidence, RecordingReadPort as _, RecordingStatus,
    };
    use xtrace_domain::{
        AppError, CorrelationId, ErrorCategory, ErrorCode, RecordingId, RetryAdvice,
    };
    use xtrace_private_storage::AdmittedPrivateRoot;
    use xtrace_store::{SqliteRecordingPersistence, SqliteRecordingReader};

    use crate::daemon::{open_validated_project, preflight_project};
    use crate::daemon_lock::{acquire_project_lock, daemon_state_root, project_lock_is_held};
    use crate::error::CliError;
    use crate::output::write_success;

    const STATE_FILE: &str = "daemon.json";
    const STDOUT_FILE: &str = "daemon.out";
    const STDERR_FILE: &str = "daemon.err";
    const STATE_SCHEMA: u32 = 1;
    const MAX_STATE_BYTES: usize = 16 * 1024;
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const STOP_TIMEOUT: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(25);
    const LIST_PAGE: u32 = 200;
    const MAX_RECOVERED: usize = 10_000;

    /// Durable identity of one detached daemon, written 0600 beside the project lock.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct DaemonRecord {
        schema: u32,
        pid: u32,
        /// `ps -o lstart=` of the daemon at spawn; a reused PID has a different value.
        process_started: String,
        /// Executable that was spawned (`current_exe` of the `record` invocation).
        executable: String,
        project_id: String,
        runtime_session_id: String,
        host: String,
        port: u16,
        certificate_sha256_pin: String,
        bootstrap_path: String,
        capture_depth: String,
    }

    #[derive(Debug, Serialize)]
    struct RecoveredRecording {
        recording_id: String,
        persisted_events: String,
        completion: &'static str,
    }

    #[derive(Debug, Serialize)]
    struct RecordDocument {
        kind: &'static str,
        project_id: String,
        pid: u32,
        runtime_session_id: String,
        host: String,
        port: u16,
        certificate_sha256_pin: String,
        bootstrap_path: String,
        bootstrap_armed: bool,
        arming: &'static str,
        capture_depth: String,
        /// True when the daemon, reading the private `capture.json` beside the bootstrap exactly
        /// as it does for every adapter session, arms the recorded depth. A `focused` record whose
        /// file is missing, unreadable, non-private or names another mode reports `false`: the
        /// daemon then serves every recording under the standard policy.
        capture_depth_enforced: bool,
        /// Application scope this invocation wrote to `capture.json`; empty when no
        /// `--app-package` was given, because `record` launches nothing and so has no jar to
        /// derive one from. `null` when a daemon was already running: nothing was rewritten.
        application_packages: Option<Vec<String>>,
        source_roots: Option<Vec<String>>,
        already_running: bool,
        recovered_recordings: Vec<RecoveredRecording>,
    }

    #[derive(Debug, Serialize)]
    struct StopDocument {
        kind: &'static str,
        project_id: String,
        pid: Option<u32>,
        runtime_session_id: Option<String>,
        was_running: bool,
        recovered_recordings: Vec<RecoveredRecording>,
    }

    #[derive(Debug, Serialize)]
    struct RestartDocument {
        kind: &'static str,
        previously_running: bool,
        stopped: StopDocument,
        started: RecordDocument,
    }

    fn lifecycle_error(
        code: &'static str,
        category: ErrorCategory,
        message: &str,
        retry: RetryAdvice,
    ) -> CliError {
        CliError::App(AppError::new(
            ErrorCode::new(code),
            category,
            message.to_string(),
            retry,
            CorrelationId::new(),
        ))
    }

    fn io_unavailable(error: &std::io::Error) -> CliError {
        CliError::StoreUnavailable(format!("daemon lifecycle I/O failed ({:?})", error.kind()))
    }

    // ------------------------------------------------------------------
    // Process identity (PID alone is never trusted).
    // ------------------------------------------------------------------

    /// Answer of the `ps` query: a missing process is distinct from an unusable `ps`.
    #[derive(Debug, PartialEq, Eq)]
    enum Ps {
        Absent,
        Present(String),
        Unavailable,
    }

    /// Needs a procps or BSD `ps` (`-o lstart=`/`command=`); BusyBox `ps` is reported as
    /// unavailable. Runs with `LC_ALL=C` so the start-time text does not depend on the locale.
    fn ps(pid: u32, column: &str) -> Ps {
        ps_with(&["/bin/ps", "/usr/bin/ps"], pid, column)
    }

    fn ps_with(binaries: &[&str], pid: u32, column: &str) -> Ps {
        for binary in binaries {
            let Ok(output) = Command::new(binary)
                .args(["-o", column, "-p", &pid.to_string()])
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .output()
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if output.status.success() && !text.is_empty() {
                return Ps::Present(text);
            }
            // A missing pid exits 1 with no output on procps and BSD; anything that writes to
            // stderr is a `ps` we cannot rely on.
            return if output.stderr.is_empty() && text.is_empty() {
                Ps::Absent
            } else {
                Ps::Unavailable
            };
        }
        Ps::Unavailable
    }

    fn process_started(pid: u32) -> Option<String> {
        match ps(pid, "lstart=") {
            Ps::Present(text) => Some(text),
            Ps::Absent | Ps::Unavailable => None,
        }
    }

    /// Why a recorded PID is or is not the recorded daemon.
    #[derive(Debug, PartialEq, Eq)]
    enum Identity {
        Verified,
        NotRunning,
        Mismatch(&'static str),
        /// `ps` could not answer; nothing may be inferred (and nothing deleted or signalled).
        Unavailable,
    }

    fn verify_identity(record: &DaemonRecord) -> Identity {
        let started = match ps(record.pid, "lstart=") {
            Ps::Present(text) => text,
            Ps::Absent => return Identity::NotRunning,
            Ps::Unavailable => return Identity::Unavailable,
        };
        if started != record.process_started {
            return Identity::Mismatch("process start time differs from the recorded daemon");
        }
        let command = match ps(record.pid, "command=") {
            Ps::Present(text) => text,
            Ps::Absent => return Identity::NotRunning,
            Ps::Unavailable => return Identity::Unavailable,
        };
        if !command.starts_with(&record.executable) {
            return Identity::Mismatch("process executable differs from the recorded daemon");
        }
        let arguments = &command[record.executable.len()..];
        if arguments.split_whitespace().next() != Some("daemon") {
            return Identity::Mismatch("process is not an xtrace daemon");
        }
        Identity::Verified
    }

    pub(super) fn lifecycle_state(private_root: &AdmittedPrivateRoot) -> super::LifecycleState {
        use super::LifecycleState;
        let state = match daemon_state_root(private_root) {
            Ok(state) => state,
            Err(_) => return LifecycleState::NoRecord,
        };
        let record = match read_record(&state) {
            Ok(Some(record)) => record,
            Ok(None) => return LifecycleState::NoRecord,
            Err(error) => return LifecycleState::Unavailable(error.to_string()),
        };
        match verify_identity(&record) {
            Identity::Verified => LifecycleState::Verified,
            Identity::NotRunning => LifecycleState::Stale(format!(
                "daemon.json names pid {}, which is not running",
                record.pid
            )),
            Identity::Mismatch(reason) => LifecycleState::Stale(format!(
                "daemon.json names pid {}, which is not the recorded daemon ({reason})",
                record.pid
            )),
            Identity::Unavailable => {
                LifecycleState::Unavailable("`ps` is missing or unusable".to_string())
            }
        }
    }

    fn identity_unavailable() -> CliError {
        lifecycle_error(
            "XTR-LIFECYCLE-IDENTITY-UNAVAILABLE",
            ErrorCategory::Resource,
            "`ps` is missing or unusable, so the daemon's identity cannot be verified",
            RetryAdvice::None,
        )
    }

    /// Terminates a child this command spawned itself after a failed start, then reaps it
    /// within a bounded wait. A child that already exited (and was reaped) is never signalled.
    fn abort_child(child: &mut std::process::Child) {
        if matches!(child.try_wait(), Ok(None)) {
            let _ = signal_term(child.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if !matches!(child.try_wait(), Ok(None)) {
                    return;
                }
                std::thread::sleep(POLL);
            }
        }
    }

    fn signal_term(pid: u32) -> Result<(), CliError> {
        let raw = i32::try_from(pid).map_err(|_| {
            lifecycle_error(
                "XTR-LIFECYCLE-IDENTITY-MISMATCH",
                ErrorCategory::Conflict,
                "recorded process id is out of range",
                RetryAdvice::None,
            )
        })?;
        let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
            lifecycle_error(
                "XTR-LIFECYCLE-IDENTITY-MISMATCH",
                ErrorCategory::Conflict,
                "recorded process id is invalid",
                RetryAdvice::None,
            )
        })?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(|_| {
            lifecycle_error(
                "XTR-LIFECYCLE-SIGNAL-FAILED",
                ErrorCategory::Resource,
                "the daemon could not be signalled",
                RetryAdvice::None,
            )
        })
    }

    // ------------------------------------------------------------------
    // Mutual exclusion between lifecycle commands.
    // ------------------------------------------------------------------

    const LIFECYCLE_LOCK: &str = "lifecycle.lock";
    const LIFECYCLE_WAIT: Duration = Duration::from_secs(60);

    /// Serializes `record`, `stop` and `restart` for one project (separate from the project
    /// lock the daemon holds), so two concurrent invocations cannot unlink each other's
    /// readiness file. Waits a bounded time; released when dropped.
    struct LifecycleLock {
        _file: std::fs::File,
    }

    fn lifecycle_lock(project_dir: &Path) -> Result<LifecycleLock, CliError> {
        // Two first-ever invocations race to create `.daemon` and the lock file; a lost
        // creation race surfaces as an admission error, so retry the setup briefly.
        let mut attempts = 0_u32;
        let file = loop {
            attempts += 1;
            let opened = (|| {
                let preflight = preflight_project(project_dir, &crate::paths::read_env_path)?;
                let state = daemon_state_root(&preflight.private_root)?;
                state
                    .open_or_create_private_file(LIFECYCLE_LOCK)
                    .map_err(|_| CliError::PrivateStorageUnavailable)
            })();
            match opened {
                Ok(file) => break file,
                Err(CliError::PrivateStorageUnavailable) if attempts < 10 => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        };
        let deadline = Instant::now() + LIFECYCLE_WAIT;
        loop {
            match fs4::FileExt::try_lock(&file) {
                Ok(()) => return Ok(LifecycleLock { _file: file }),
                Err(fs4::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(lifecycle_error(
                            "XTR-LIFECYCLE-BUSY",
                            ErrorCategory::Resource,
                            "another record, stop or restart is still running for this project",
                            RetryAdvice::AfterDelay { millis: 1_000 },
                        ));
                    }
                    std::thread::sleep(POLL);
                }
                Err(fs4::TryLockError::Error(_)) => {
                    return Err(CliError::PrivateStorageUnavailable);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // State file.
    // ------------------------------------------------------------------

    fn read_record(state: &AdmittedPrivateRoot) -> Result<Option<DaemonRecord>, CliError> {
        match state.validate_optional_private_file(STATE_FILE) {
            Ok(false) => return Ok(None),
            Ok(true) => {}
            Err(_) => return Err(CliError::PrivateStorageUnavailable),
        }
        let bytes = state
            .read_bounded_file(STATE_FILE, MAX_STATE_BYTES)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        let record: DaemonRecord = serde_json::from_slice(&bytes).map_err(|_| {
            CliError::StoreCorrupted("daemon state file is not valid JSON".to_string())
        })?;
        if record.schema != STATE_SCHEMA {
            return Err(CliError::StoreCorrupted(
                "daemon state file has an unsupported schema".to_string(),
            ));
        }
        Ok(Some(record))
    }

    fn write_record(state: &AdmittedPrivateRoot, record: &DaemonRecord) -> Result<(), CliError> {
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|_| CliError::StoreUnavailable("encode daemon state failed".to_string()))?;
        let temp = format!("{STATE_FILE}.tmp");
        let _ = state.remove_private_file(&temp);
        let mut file =
            state.create_private_file(&temp).map_err(|_| CliError::PrivateStorageUnavailable)?;
        file.write_all(&bytes).map_err(|error| io_unavailable(&error))?;
        file.sync_all().map_err(|error| io_unavailable(&error))?;
        drop(file);
        state.rename_replace(&temp, STATE_FILE).map_err(|_| CliError::PrivateStorageUnavailable)
    }

    fn remove_record(state: &AdmittedPrivateRoot) {
        let _ = state.remove_private_file(STATE_FILE);
    }

    // ------------------------------------------------------------------
    // Recovery: seal recordings a dead daemon left open.
    // ------------------------------------------------------------------

    /// Seals every recording that is still `recording`/`finalizing` without
    /// terminal evidence as partial. The caller must know no daemon is
    /// running; this function additionally holds the project lock, so a
    /// concurrent daemon start fails closed instead of racing.
    fn recover_interrupted(project_dir: &Path) -> Result<Vec<RecoveredRecording>, CliError> {
        let preflight = preflight_project(project_dir, &crate::paths::read_env_path)?;
        let _lock = acquire_project_lock(&preflight.private_root)?;
        let selected = open_validated_project(preflight)?;
        let reader =
            SqliteRecordingReader::new(selected.store.clone(), selected.project_data_root.clone());
        let persistence = SqliteRecordingPersistence::new(
            selected.store.clone(),
            selected.project_data_root.clone(),
        );
        let mut open = Vec::new();
        let mut after: Option<RecordingId> = None;
        loop {
            let (page, more) =
                reader.list_recordings(selected.project_id, after, LIST_PAGE).map_err(|error| {
                    CliError::StoreUnavailable(format!(
                        "recording store operation failed ({:?})",
                        error.kind()
                    ))
                })?;
            for item in &page {
                let nonterminal =
                    matches!(item.status, RecordingStatus::Recording | RecordingStatus::Finalizing);
                if nonterminal && item.completion != RecordingCompletionEvidence::Complete {
                    let last = item
                        .last_sequence
                        .as_deref()
                        .and_then(|value| value.parse::<u64>().ok())
                        // A begun recording always holds sequence 1 (RecordingStarted).
                        .unwrap_or(1)
                        .max(1);
                    open.push((item.recording_id, last, item.event_count.clone()));
                }
            }
            if open.len() > MAX_RECOVERED {
                return Err(CliError::Partial(
                    "too many open recordings to recover in one pass".to_string(),
                ));
            }
            match (more, page.last()) {
                (true, Some(last)) => after = Some(last.recording_id),
                _ => break,
            }
        }
        // Best effort per recording: one recording that cannot be sealed (for example a segment
        // that fails verification) is reported as `failed` and does not block the others.
        let mut recovered = Vec::new();
        for (recording_id, last, events) in open {
            let completion = match persistence
                .finish_recording(&FinishRecording::without_digest(recording_id, last))
            {
                Ok(xtrace_application::recording::RecordingCompletion::Complete) => "complete",
                Ok(xtrace_application::recording::RecordingCompletion::Partial) => "partial",
                Ok(xtrace_application::recording::RecordingCompletion::Invalid) => "invalid",
                Err(_) => "failed",
            };
            recovered.push(RecoveredRecording {
                recording_id: recording_id.to_string(),
                persisted_events: events,
                completion,
            });
        }
        Ok(recovered)
    }

    // ------------------------------------------------------------------
    // record
    // ------------------------------------------------------------------

    fn record_document(
        record: &DaemonRecord,
        written_scope: Option<&crate::capture_args::ResolvedCapture>,
        recovered: Vec<RecoveredRecording>,
    ) -> RecordDocument {
        let already_running = written_scope.is_none();
        RecordDocument {
            kind: if already_running { "record_already_running" } else { "record_started" },
            project_id: record.project_id.clone(),
            pid: record.pid,
            runtime_session_id: record.runtime_session_id.clone(),
            host: record.host.clone(),
            port: record.port,
            certificate_sha256_pin: record.certificate_sha256_pin.clone(),
            bootstrap_path: record.bootstrap_path.clone(),
            bootstrap_armed: Path::new(&record.bootstrap_path).exists(),
            arming: "single_launch_bootstrap",
            capture_depth: record.capture_depth.clone(),
            // The daemon's own reader decides: `capture_depth_enforced` is what it will arm.
            capture_depth_enforced: crate::capture_args::armed_depth_beside(Path::new(
                &record.bootstrap_path,
            ))
            .as_str()
                == record.capture_depth,
            application_packages: written_scope.map(|scope| scope.application_packages.clone()),
            source_roots: written_scope.map(|scope| scope.source_roots.clone()),
            already_running,
            recovered_recordings: recovered,
        }
    }

    pub(super) fn record(
        project_dir: PathBuf,
        capture: &crate::capture_args::CaptureOptions,
    ) -> Result<i32, CliError> {
        let _guard = lifecycle_lock(&project_dir)?;
        let document = start(project_dir, capture)?;
        write_stdout(&document)?;
        Ok(0)
    }

    fn write_stdout<T: Serialize>(document: &T) -> Result<(), CliError> {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        write_success(&mut handle, document).map_err(|error| io_unavailable(&error))
    }

    fn start(
        project_dir: PathBuf,
        capture: &crate::capture_args::CaptureOptions,
    ) -> Result<RecordDocument, CliError> {
        let depth = capture.depth.as_str();
        let preflight = preflight_project(&project_dir, &crate::paths::read_env_path)?;
        let state = daemon_state_root(&preflight.private_root)?;
        let project_root = preflight.private_root;
        let project_id = preflight.project_id.to_string();

        if let Some(existing) = read_record(&state)? {
            match verify_identity(&existing) {
                Identity::Verified if project_lock_is_held(&project_root)? => {
                    return Ok(record_document(&existing, None, Vec::new()));
                }
                Identity::Unavailable => return Err(identity_unavailable()),
                Identity::Verified | Identity::NotRunning | Identity::Mismatch(_) => {
                    remove_record(&state);
                }
            }
        }
        if project_lock_is_held(&project_root)? {
            // Something we did not start (a foreground `daemon` or a `run`) owns the lock.
            return Err(CliError::DaemonAlreadyRunning);
        }
        drop(state);
        drop(project_root);

        let recovered = recover_interrupted(&project_dir)?;

        // Re-open after recovery so every handle is fresh for the spawn.
        let preflight = preflight_project(&project_dir, &crate::paths::read_env_path)?;
        let state = daemon_state_root(&preflight.private_root)?;
        let _ = state.remove_private_file(STDOUT_FILE);
        let _ = state.remove_private_file(STDERR_FILE);
        let stdout_file = state
            .create_private_file(STDOUT_FILE)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        let stderr_file = state
            .create_private_file(STDERR_FILE)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        let executable = std::env::current_exe().map_err(|error| io_unavailable(&error))?;
        let repo = crate::commands::resolve_repo(&project_dir)?;
        let mut child = Command::new(&executable)
            .arg("daemon")
            .arg("--project-dir")
            .arg(&repo)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            // A new process group keeps the daemon alive when the invoking terminal goes away.
            .process_group(0)
            .spawn()
            .map_err(|error| io_unavailable(&error))?;
        let pid = child.id();

        let ready = match wait_for_ready(&state, &mut child) {
            Ok(ready) => ready,
            Err(error) => {
                abort_child(&mut child);
                return Err(error);
            }
        };
        let record = DaemonRecord {
            schema: STATE_SCHEMA,
            pid,
            process_started: process_started(pid).unwrap_or_default(),
            executable: executable.to_string_lossy().into_owned(),
            project_id,
            runtime_session_id: ready.runtime_session_id,
            host: ready.host,
            port: ready.port,
            certificate_sha256_pin: ready.certificate_sha256_pin,
            bootstrap_path: ready.bootstrap_path,
            capture_depth: depth.to_string(),
        };
        if record.process_started.is_empty() {
            abort_child(&mut child);
            return Err(lifecycle_error(
                "XTR-LIFECYCLE-IDENTITY-UNAVAILABLE",
                ErrorCategory::Resource,
                "the daemon started but its process identity could not be recorded",
                RetryAdvice::None,
            ));
        }
        if let Err(error) = write_record(&state, &record) {
            abort_child(&mut child);
            return Err(error);
        }
        // Arm the session and persist the resolved scope: the daemon reads this file when the
        // first adapter connects, and the Java agent reads the scope from it.
        let resolved = capture.resolve(None);
        if let Err(error) = crate::capture_args::write_beside(
            Path::new(&record.bootstrap_path),
            &resolved.document(),
        ) {
            remove_record(&state);
            abort_child(&mut child);
            return Err(error);
        }
        // `child` is intentionally not waited on: the daemon outlives this command.
        drop(child);
        Ok(record_document(&record, Some(&resolved), recovered))
    }

    #[derive(Deserialize)]
    struct Ready {
        kind: String,
        runtime_session_id: String,
        host: String,
        port: u16,
        certificate_sha256_pin: String,
        bootstrap_path: String,
    }

    fn wait_for_ready(
        state: &AdmittedPrivateRoot,
        child: &mut std::process::Child,
    ) -> Result<Ready, CliError> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Ok(bytes) = state.read_bounded_file(STDOUT_FILE, MAX_STATE_BYTES) {
                if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                    let ready: Ready = serde_json::from_slice(&bytes[..end]).map_err(|_| {
                        CliError::StoreCorrupted("daemon readiness line is not valid JSON".into())
                    })?;
                    if ready.kind != "daemon_bound" {
                        return Err(CliError::StoreCorrupted(
                            "daemon readiness line has an unexpected kind".to_string(),
                        ));
                    }
                    return Ok(ready);
                }
            }
            if let Ok(Some(status)) = child.try_wait() {
                let _ = status;
                // Surface the daemon's own sanitized error document.
                let detail = state
                    .read_bounded_file(STDERR_FILE, MAX_STATE_BYTES)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                if let Some(code) = detail.as_ref().and_then(|value| value["exit_code"].as_i64()) {
                    if code == 5 {
                        return Err(CliError::DaemonAlreadyRunning);
                    }
                }
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-DAEMON-EXITED",
                    ErrorCategory::Resource,
                    "the daemon exited before it became ready",
                    RetryAdvice::None,
                ));
            }
            if Instant::now() >= deadline {
                // We started this child and recorded its PID at spawn; it is ours to stop.
                abort_child(child);
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-START-TIMEOUT",
                    ErrorCategory::Transport,
                    "the daemon did not become ready in time",
                    RetryAdvice::AfterDelay { millis: 1_000 },
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    // ------------------------------------------------------------------
    // stop / restart
    // ------------------------------------------------------------------

    pub(super) fn stop(project_dir: PathBuf, session: Option<String>) -> Result<i32, CliError> {
        let _guard = lifecycle_lock(&project_dir)?;
        let document = stop_inner(&project_dir, session.as_deref(), true)?;
        write_stdout(&document)?;
        if !document.was_running && !document.recovered_recordings.is_empty() {
            // Nothing was running, but store rows changed: the document says which, exit 3.
            return Ok(3);
        }
        Ok(exit_for(&document.recovered_recordings))
    }

    fn stop_inner(
        project_dir: &Path,
        session: Option<&str>,
        not_running_is_error: bool,
    ) -> Result<StopDocument, CliError> {
        let preflight = preflight_project(project_dir, &crate::paths::read_env_path)?;
        let state = daemon_state_root(&preflight.private_root)?;
        let project_root = preflight.private_root;
        let project_id = preflight.project_id.to_string();
        let record = read_record(&state)?;

        let Some(record) = record else {
            if project_lock_is_held(&project_root)? {
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-NOT-OURS",
                    ErrorCategory::Conflict,
                    "a daemon holds the project lock but was not started by `xtrace record`; \
                     it is not signalled",
                    RetryAdvice::None,
                ));
            }
            drop(state);
            drop(project_root);
            let recovered = recover_interrupted(project_dir)?;
            if not_running_is_error && recovered.is_empty() {
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-NOT-RUNNING",
                    ErrorCategory::NotFound,
                    "no recording daemon is running for this project",
                    RetryAdvice::None,
                ));
            }
            return Ok(StopDocument {
                kind: "stop_not_running",
                project_id,
                pid: None,
                runtime_session_id: None,
                was_running: false,
                recovered_recordings: recovered,
            });
        };

        if let Some(wanted) = session {
            if wanted != record.runtime_session_id {
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-SESSION-UNKNOWN",
                    ErrorCategory::NotFound,
                    "the requested session is not the running daemon's session",
                    RetryAdvice::None,
                ));
            }
        }

        match verify_identity(&record) {
            Identity::Mismatch(_) if !project_lock_is_held(&project_root)? => {
                // Stale record (reboot, crash, recycled PID, zombie) and no daemon holds the
                // project lock: nothing to stop. Never signal the bystander; drop the record.
                remove_record(&state);
                drop(state);
                drop(project_root);
                let recovered = recover_interrupted(project_dir)?;
                if not_running_is_error && recovered.is_empty() {
                    return Err(lifecycle_error(
                        "XTR-LIFECYCLE-NOT-RUNNING",
                        ErrorCategory::NotFound,
                        "the recorded daemon is no longer running; its stale state was cleaned up",
                        RetryAdvice::None,
                    ));
                }
                return Ok(StopDocument {
                    kind: "stop_not_running",
                    project_id,
                    pid: Some(record.pid),
                    runtime_session_id: Some(record.runtime_session_id),
                    was_running: false,
                    recovered_recordings: recovered,
                });
            }
            Identity::Mismatch(reason) => {
                // A daemon holds the lock but the record names another process: never signal it.
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-IDENTITY-MISMATCH",
                    ErrorCategory::Conflict,
                    &format!("refusing to signal the recorded process: {reason}"),
                    RetryAdvice::None,
                ));
            }
            Identity::NotRunning => {
                remove_record(&state);
                drop(state);
                drop(project_root);
                let recovered = recover_interrupted(project_dir)?;
                if not_running_is_error && recovered.is_empty() {
                    return Err(lifecycle_error(
                        "XTR-LIFECYCLE-NOT-RUNNING",
                        ErrorCategory::NotFound,
                        "the recorded daemon is no longer running; its state was cleaned up",
                        RetryAdvice::None,
                    ));
                }
                return Ok(StopDocument {
                    kind: "stop_not_running",
                    project_id,
                    pid: Some(record.pid),
                    runtime_session_id: Some(record.runtime_session_id),
                    was_running: false,
                    recovered_recordings: recovered,
                });
            }
            Identity::Unavailable => return Err(identity_unavailable()),
            Identity::Verified => {}
        }

        signal_term(record.pid)?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            let identity = verify_identity(&record);
            if identity == Identity::Unavailable {
                return Err(identity_unavailable());
            }
            // Gone = the lock is released and the process is no longer the verified daemon
            // (absent, or a zombie whose command line no longer matches).
            let gone = identity != Identity::Verified && !project_lock_is_held(&project_root)?;
            if gone {
                break;
            }
            if Instant::now() >= deadline {
                return Err(lifecycle_error(
                    "XTR-LIFECYCLE-STOP-TIMEOUT",
                    ErrorCategory::Transport,
                    "the daemon did not stop within the deadline; it was not forcibly killed",
                    RetryAdvice::AfterDelay { millis: 1_000 },
                ));
            }
            std::thread::sleep(POLL);
        }
        remove_record(&state);
        drop(state);
        drop(project_root);
        let recovered = recover_interrupted(project_dir)?;
        Ok(StopDocument {
            kind: "stopped",
            project_id,
            pid: Some(record.pid),
            runtime_session_id: Some(record.runtime_session_id),
            was_running: true,
            recovered_recordings: recovered,
        })
    }

    pub(super) fn restart(
        project_dir: PathBuf,
        capture: &crate::capture_args::CaptureOptions,
    ) -> Result<i32, CliError> {
        let _guard = lifecycle_lock(&project_dir)?;
        let stopped = stop_inner(&project_dir, None, false)?;
        let started = start(project_dir, capture)?;
        let document = RestartDocument {
            kind: "restarted",
            previously_running: stopped.was_running,
            stopped,
            started,
        };
        write_stdout(&document)?;
        Ok(exit_for(&document.stopped.recovered_recordings))
    }

    /// Exit 10 (partial) when any open recording could not be sealed; the document names which.
    fn exit_for(recovered: &[RecoveredRecording]) -> i32 {
        if recovered.iter().any(|item| item.completion == "failed") { 10 } else { 0 }
    }

    #[cfg(test)]
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "unit fixtures assert on controlled local values"
    )]
    mod tests {
        use super::*;

        fn record_for(pid: u32, started: &str, executable: &str) -> DaemonRecord {
            DaemonRecord {
                schema: STATE_SCHEMA,
                pid,
                process_started: started.to_string(),
                executable: executable.to_string(),
                project_id: String::new(),
                runtime_session_id: String::new(),
                host: String::new(),
                port: 0,
                certificate_sha256_pin: String::new(),
                bootstrap_path: String::new(),
                capture_depth: "standard".to_string(),
            }
        }

        #[test]
        fn identity_of_a_live_unrelated_process_is_a_mismatch_never_verified() {
            // This test process is alive, but is not an `xtrace daemon`; the recorded
            // executable is an explicit non-matching path so the verdict does not depend on
            // this test binary's own arguments.
            let pid = std::process::id();
            let started = process_started(pid).expect("own start time");
            let exe = "/nonexistent/xtrace-test-executable".to_string();
            assert!(matches!(
                verify_identity(&record_for(pid, &started, &exe)),
                Identity::Mismatch(_)
            ));
            // A different recorded start time (PID reuse) is also a mismatch.
            assert!(matches!(
                verify_identity(&record_for(pid, "Mon Jan  1 00:00:00 1990", &exe)),
                Identity::Mismatch(_)
            ));
        }

        #[test]
        fn identity_of_a_dead_process_is_not_running() {
            let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("spawn sleep");
            let pid = child.id();
            child.kill().expect("kill own child");
            child.wait().expect("reap own child");
            assert_eq!(
                verify_identity(&record_for(pid, "Mon Jan  1 00:00:00 1990", "/bin/sleep")),
                Identity::NotRunning
            );
        }

        #[test]
        fn abort_child_terminates_a_live_child_and_leaves_a_reaped_one_alone() {
            let mut live = Command::new("/bin/sleep").arg("30").spawn().expect("spawn sleep");
            abort_child(&mut live);
            assert!(live.try_wait().expect("try_wait").is_some(), "child must be reaped");

            let mut done =
                Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().expect("spawn sh");
            done.wait().expect("reap");
            abort_child(&mut done); // must not signal a reaped pid, must return promptly
        }

        #[test]
        fn a_zombie_is_a_mismatch_not_verified() {
            let mut zombie =
                Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().expect("spawn sh");
            let pid = zombie.id();
            // Wait until the child has exited but has NOT been reaped.
            let deadline = Instant::now() + Duration::from_secs(5);
            let started = loop {
                if let Some(started) = process_started(pid) {
                    if ps(pid, "command=") != Ps::Present("/bin/sh -c exit 0".into()) {
                        break started;
                    }
                }
                assert!(Instant::now() < deadline, "child never became a zombie");
                std::thread::sleep(Duration::from_millis(20));
            };
            let verdict = verify_identity(&record_for(pid, &started, "/nonexistent/xtrace"));
            assert!(matches!(verdict, Identity::Mismatch(_)), "{verdict:?}");
            zombie.wait().expect("reap");
        }

        #[test]
        fn unusable_ps_is_unavailable_not_absent() {
            assert_eq!(
                ps_with(&["/nonexistent/ps-binary"], std::process::id(), "lstart="),
                Ps::Unavailable
            );
            // A `ps` that exits 1 with no output is the "no such pid" answer.
            assert_eq!(ps_with(&["/usr/bin/false"], std::process::id(), "lstart="), Ps::Absent);
        }

        #[test]
        fn exit_code_is_ten_only_when_a_recording_failed_to_seal() {
            let item = |completion: &'static str| RecoveredRecording {
                recording_id: String::new(),
                persisted_events: String::new(),
                completion,
            };
            assert_eq!(exit_for(&[]), 0);
            assert_eq!(exit_for(&[item("partial")]), 0);
            assert_eq!(exit_for(&[item("partial"), item("failed")]), 10);
        }
    }
}
