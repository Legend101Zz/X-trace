//! Foreground composition for one explicitly selected, already-running JVM.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use xtrace_runtime::java_attach::{
    AttachError, JavaAttachPack, admit_private_container_directory, admit_private_directory,
    prepare_helper_cache,
};

use crate::commands::{resolve_data_home, resolve_repo};
use crate::error::CliError;
use crate::output::write_success_line;
use crate::paths::{RepositoryPointer, UserDataPaths};

const MAX_HELPER_OUTPUT: usize = 256 * 1024;
const MAX_HELPER_SECONDS: u64 = 40;

/// Runs one attach session and keeps its owned recording daemon in the foreground.
pub(crate) async fn run(
    project_dir: PathBuf,
    requested_pid: Option<u32>,
    explicit_pack: PathBuf,
    json: bool,
) -> Result<(), CliError> {
    match requested_pid {
        Some(pid) if pid > 0 => {}
        Some(_) => {
            return Err(attach_error(
                "XTR-ATTACH-PID-INVALID",
                "validation",
                "PID must be a positive process identifier.",
                "Pass --pid <positive PID> for the intended JVM.",
                2,
            ));
        }
        None => require_interactive_terminal(
            std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        )?,
    }
    let supplied_pack = JavaAttachPack::resolve(&explicit_pack).map_err(map_runtime_error)?;
    let helper_java = resolve_java().map_err(|error| {
        attach_error(
            "XTR-ATTACH-JDK-UNAVAILABLE",
            "compatibility",
            error,
            "Install a full JDK with jdk.attach and retry.",
            6,
        )
    })?;

    let repo = resolve_repo(&project_dir)?;
    let pointer = RepositoryPointer::read(&repo)?;
    let data_home = resolve_data_home(Some(&pointer), &crate::paths::read_env_path)?;
    let project_data_root = UserDataPaths::project_dir_with_home(&data_home, pointer.project_id)?;
    if project_data_root.to_str().is_none() || data_home.to_str().is_none() {
        return Err(attach_error(
            "XTR-ATTACH-PRIVATE-STORAGE",
            "validation",
            "The project data path is not valid UTF-8.",
            "Choose an owner-enforced local data directory with a UTF-8 path and retry.",
            2,
        ));
    }
    validate_project_private_roots(&data_home, &project_data_root)?;
    let helper_cache = prepare_helper_cache(&data_home).map_err(map_runtime_error)?;
    // The helper executes only the independently revalidated private snapshot,
    // so later changes to the supplied distribution cannot swap in new bytes.
    let pack = supplied_pack.snapshot_into(&helper_cache).map_err(map_runtime_error)?;

    let selected = match requested_pid {
        Some(pid) => inspect(&helper_java, &pack, &helper_cache, pid).await?,
        None => {
            let listed =
                helper_command(&helper_java, &pack, &helper_cache, &["list", "--json"]).await?;
            if !listed.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(helper_failure(&listed, "list"));
            }
            let rows = listed.get("processes").and_then(Value::as_array).ok_or_else(|| {
                attach_error("XTR-ATTACH-HELPER-FAILED", "process", "The Java helper returned an invalid process list.", "Retry once; if inspection remains unavailable, relaunch the application through X-trace.", 7)
            })?;
            if listed.get("truncated").and_then(Value::as_bool).unwrap_or(true) {
                return Err(attach_error(
                    "XTR-ATTACH-PROCESS-LIST-TRUNCATED",
                    "resource",
                    "The JVM list exceeded its safe selection limit.",
                    "Pass --pid for the intended JVM, or close unrelated JVMs and retry.",
                    5,
                ));
            }
            select_interactively(rows)?
        }
    };
    let pid = selected.pid;
    let first_inspection = inspect(&helper_java, &pack, &helper_cache, pid).await?;
    verify_identity(&selected, &first_inspection)?;
    verify_os_identity(&selected).await?;

    let agent_path = pack.agent_dir().join("xtrace-java-agent.jar");
    let agent_path = agent_path
        .to_str()
        .ok_or_else(|| {
            attach_error(
                "XTR-ATTACH-PACK-INVALID",
                "validation",
                "The verified Java pack path is invalid.",
                "Use a Java pack installed at a UTF-8 path and retry.",
                2,
            )
        })?
        .to_string();

    let daemon_path = project_data_root.join(".daemon");
    match std::fs::symlink_metadata(&daemon_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(attach_error(
                "XTR-ATTACH-PRIVATE-STORAGE",
                "validation",
                "The project daemon directory is not a real directory.",
                "Use a project data directory on an owner-enforced local filesystem and retry.",
                2,
            ));
        }
        Ok(_) => admit_private_directory(&daemon_path).map_err(map_runtime_error)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(attach_error(
                "XTR-ATTACH-PRIVATE-STORAGE",
                "validation",
                "The project daemon directory could not be inspected.",
                "Use a project data directory on an owner-enforced local filesystem and retry.",
                2,
            ));
        }
    }

    let prepared = crate::daemon::prepare(repo, &crate::paths::read_env_path).await.map_err(|error| {
        if matches!(error, CliError::DaemonAlreadyRunning) {
            attach_error("XTR-ATTACH-PROJECT-LOCKED", "conflict", "This project already has a foreground X-trace owner.", "Close the current foreground X-trace owner for this project, then retry xtrace attach.", 4)
        } else {
            error
        }
    })?;
    let crate::daemon::PreparedDaemon { bound, bootstrap_path, runtime_dir, lock } = prepared;
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        bound
            .serve(async move {
                match shutdown_rx.await {
                    Ok(()) => (),
                    Err(_) => tracing::debug!(
                        code = "XTR-ATTACH-SHUTDOWN-SENDER-CLOSED",
                        "owned server shutdown sender closed"
                    ),
                }
            })
            .await
    });
    let mut shutdown_signals = match ShutdownSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
        }
    };

    let Some(bootstrap_path_text) = bootstrap_path.to_str() else {
        let error = attach_error(
            "XTR-ATTACH-PRIVATE-STORAGE",
            "validation",
            "The private bootstrap path is invalid.",
            "Use an owner-enforced local data directory and retry.",
            2,
        );
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    };
    // Daemon preparation can take time. Revalidate immediately before the
    // helper invocation; the helper independently checks again before loadAgent.
    let final_inspection = inspect(&helper_java, &pack, &helper_cache, pid).await;
    let identity_check =
        final_inspection.and_then(|observed| verify_identity(&selected, &observed));
    if let Err(error) = identity_check {
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    }
    if let Err(error) = verify_os_identity(&selected).await {
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    }
    let attach_result = helper_command(
        &helper_java,
        &pack,
        &helper_cache,
        &[
            "attach",
            "--pid",
            &pid.to_string(),
            "--agent",
            &agent_path,
            "--options-file",
            bootstrap_path_text,
            "--json",
        ],
    )
    .await;

    let attach_result = match attach_result {
        Ok(result) => result,
        Err(error) => {
            return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
        }
    };
    if !attach_result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        let error = helper_failure(&attach_result, "attach");
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    }
    let attached_identity = process_document(attach_result.get("process").unwrap_or(&Value::Null));
    let Some(process) = attached_identity else {
        let error = attach_error(
            "XTR-ATTACH-RESULT-UNCERTAIN",
            "process",
            "The helper did not return the validated target identity.",
            "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.",
            7,
        );
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    };

    let document = AttachResultDocument {
        kind: "java_attach_result",
        pid,
        process,
        pack_authenticity: "unsigned_development_pack",
        agent_load_status: "agent_load_requested",
        capture_status: "unknown_pending_daemon_observation",
        supported_adapter_scope: "current_java_fixture_only",
        focused_capture: "unavailable",
        line_evidence: "unavailable",
        value_capture: "unavailable",
        lifecycle: "foreground_until_interrupt",
        target_lifecycle: "not_owned_by_xtrace",
        recording_ingress: "durable_segments",
    };
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let output_result = if json {
        write_success_line(&mut output, &document)
    } else {
        writeln!(
            output,
            "WARNING: unsigned development Java pack; publisher authenticity is not verified. Agent load requested for JVM {} ({}); capture status is unknown pending daemon observation. Adapter scope is the current Java fixture; focused capture, active-line evidence, and value capture are unavailable. Press Ctrl-C to stop this X-trace session; the JVM stays running.",
            document.pid,
            document.process.owner
        )
    }
    .and_then(|()| output.flush());
    if output_result.is_err() {
        drop(output);
        let error = attach_error(
            "XTR-ATTACH-OUTPUT-FAILED",
            "process",
            "The attach result could not be written.",
            "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
            7,
        );
        return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
    }
    drop(output);

    enum ForegroundEnd {
        Signal,
        SignalSetupFailed(CliError),
        ServerFinished(Result<Result<(), xtrace_daemon::DaemonError>, tokio::task::JoinError>),
    }
    let end = tokio::select! {
        signal_result = shutdown_signals.wait() => match signal_result {
            Ok(()) => ForegroundEnd::Signal,
            Err(error) => ForegroundEnd::SignalSetupFailed(error),
        },
        result = &mut server => ForegroundEnd::ServerFinished(result),
    };
    let server_result = match end {
        ForegroundEnd::Signal => {
            if shutdown.send(()).is_err() {
                tracing::debug!(
                    code = "XTR-ATTACH-SERVER-ALREADY-STOPPED",
                    "owned server stopped before shutdown signal"
                );
            }
            await_owned_server(&mut server).await
        }
        ForegroundEnd::SignalSetupFailed(error) => {
            return cleanup_after_primary(shutdown, server, runtime_dir, lock, error).await;
        }
        ForegroundEnd::ServerFinished(result) => {
            if shutdown.send(()).is_err() {
                tracing::debug!(
                    code = "XTR-ATTACH-SERVER-ALREADY-STOPPED",
                    "owned server had already stopped"
                );
            }
            match result {
                Ok(result) => OwnedServerResult::Finished(result),
                Err(_) => OwnedServerResult::Unconfirmed,
            }
        }
    };
    let cleanup_result = match &server_result {
        OwnedServerResult::Finished(_) => {
            finish_confirmed_runtime(runtime_dir, lock, |runtime| runtime.cleanup())
        }
        OwnedServerResult::Unconfirmed => {
            retain_unconfirmed_runtime(runtime_dir, lock);
            return Err(attach_error(
                "XTR-ATTACH-DAEMON-FAILED",
                "process",
                "The owned recording session could not be confirmed stopped.",
                "Leave this project closed until the X-trace process exits; the selected JVM remains running.",
                7,
            ));
        }
    };
    if !matches!(&server_result, OwnedServerResult::Finished(Ok(()))) {
        if cleanup_result.is_err() {
            tracing::warn!(
                code = "XTR-ATTACH-CLEANUP-UNCONFIRMED",
                "owned attach cleanup did not complete"
            );
        }
        return Err(attach_error(
            "XTR-ATTACH-DAEMON-FAILED",
            "process",
            "The owned recording session stopped unexpectedly.",
            "Relaunch the application through X-trace if standard capture is required.",
            7,
        ));
    }
    cleanup_result
}

async fn cleanup_after_primary(
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<(), xtrace_daemon::DaemonError>>,
    runtime_dir: crate::daemon_lock::RuntimeDirectory,
    lock: crate::daemon_lock::ProjectDaemonLock,
    primary: CliError,
) -> Result<(), CliError> {
    let mut server = server;
    if shutdown.send(()).is_err() {
        tracing::debug!(
            code = "XTR-ATTACH-SERVER-ALREADY-STOPPED",
            "owned server stopped before cleanup"
        );
    }
    let server_result = await_owned_server(&mut server).await;
    let cleanup_result = match &server_result {
        OwnedServerResult::Finished(_) => {
            finish_confirmed_runtime(runtime_dir, lock, |runtime| runtime.cleanup())
        }
        OwnedServerResult::Unconfirmed => {
            retain_unconfirmed_runtime(runtime_dir, lock);
            Err(attach_error(
                "XTR-ATTACH-DAEMON-FAILED",
                "process",
                "The owned recording session could not be confirmed stopped.",
                "Leave this project closed until the X-trace process exits; the selected JVM remains running.",
                7,
            ))
        }
    };
    if cleanup_result.is_err() || !matches!(&server_result, OwnedServerResult::Finished(Ok(()))) {
        tracing::warn!(
            code = "XTR-ATTACH-CLEANUP-UNCONFIRMED",
            "owned attach cleanup did not complete"
        );
    }
    Err(primary)
}

fn finish_confirmed_runtime<R, L, C>(runtime_dir: R, lock: L, cleanup: C) -> Result<(), CliError>
where
    C: FnOnce(&mut R) -> Result<(), CliError>,
{
    let mut runtime_dir = runtime_dir;
    let cleanup_result = cleanup(&mut runtime_dir);
    // RuntimeDirectory::drop may retry cleanup, so it must finish while the
    // project lock still prevents a new owner from entering this directory.
    drop(runtime_dir);
    drop(lock);
    cleanup_result
}

fn retain_unconfirmed_runtime(
    mut runtime_dir: crate::daemon_lock::RuntimeDirectory,
    lock: crate::daemon_lock::ProjectDaemonLock,
) {
    // No in-process custodian can prove a timed-out task has drained. Keep its
    // artifacts and lock until this CLI process exits; never let Drop clean
    // them while the daemon may still be using the session directory.
    runtime_dir.defer_drop_cleanup();
    std::mem::forget(runtime_dir);
    std::mem::forget(lock);
}

enum OwnedServerResult {
    Finished(Result<(), xtrace_daemon::DaemonError>),
    Unconfirmed,
}

async fn await_owned_server(
    server: &mut tokio::task::JoinHandle<Result<(), xtrace_daemon::DaemonError>>,
) -> OwnedServerResult {
    await_owned_server_with_timeout(server, Duration::from_secs(5)).await
}

async fn await_owned_server_with_timeout(
    server: &mut tokio::task::JoinHandle<Result<(), xtrace_daemon::DaemonError>>,
    timeout: Duration,
) -> OwnedServerResult {
    match tokio::time::timeout(timeout, &mut *server).await {
        Ok(Ok(result)) => OwnedServerResult::Finished(result),
        // A JoinError only proves the async wrapper ended. A panic or cancel
        // cannot certify that started blocking storage work has drained.
        Ok(Err(_)) => OwnedServerResult::Unconfirmed,
        // Cancellation cannot preempt work already running in spawn_blocking.
        // Do not abort and mistake a cancelled serve future for drained storage.
        Err(_) => OwnedServerResult::Unconfirmed,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    start_time: String,
    owner: String,
}

#[derive(Debug, Serialize)]
struct SafeProcess {
    command_summary: String,
    jdk_version: Option<String>,
    owner: String,
}

#[derive(Debug, Serialize)]
struct AttachResultDocument {
    kind: &'static str,
    pid: u32,
    process: SafeProcess,
    pack_authenticity: &'static str,
    agent_load_status: &'static str,
    capture_status: &'static str,
    supported_adapter_scope: &'static str,
    focused_capture: &'static str,
    line_evidence: &'static str,
    value_capture: &'static str,
    lifecycle: &'static str,
    target_lifecycle: &'static str,
    recording_ingress: &'static str,
}

fn validate_project_private_roots(
    data_home: &Path,
    project_data_root: &Path,
) -> Result<(), CliError> {
    admit_private_container_directory(data_home).map_err(map_runtime_error)?;
    admit_private_directory(project_data_root).map_err(map_runtime_error)?;
    Ok(())
}

fn map_runtime_error(error: AttachError) -> CliError {
    let code = error.code();
    let (category, message, remediation, exit_code) = match &error {
        AttachError::Validation(_) => (
            "validation",
            "The verified Java attach pack failed validation.",
            "Use a complete Java pack produced by the X-trace javaPackDist task, then retry.",
            2,
        ),
        AttachError::PrivateStorage(_) => (
            "permission",
            "The selected project or helper storage does not meet the private-storage policy.",
            "Select an owner-enforced local data directory with no granting ACL entries, then retry.",
            7,
        ),
        AttachError::Unsupported => (
            "compatibility",
            "Java attach is unsupported on this host.",
            "Use a supported full JDK on macOS or Linux and relaunch through X-trace if attach remains unavailable.",
            6,
        ),
        AttachError::Process => (
            "process",
            "The bounded Java attach helper failed.",
            "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
            9,
        ),
    };
    attach_error(code, category, message, remediation, exit_code)
}

fn attach_error(
    code: &'static str,
    category: &'static str,
    message: &str,
    remediation: &str,
    exit_code: i32,
) -> CliError {
    CliError::Attach {
        code,
        category,
        message: message.to_string(),
        remediation: remediation.to_string(),
        exit_code,
    }
}

async fn helper_command(
    java: &Path,
    pack: &JavaAttachPack,
    cache: &Path,
    arguments: &[&str],
) -> Result<Value, CliError> {
    let command = arguments.first().copied().unwrap_or("unknown");
    let mut child = Command::new(java);
    child
        .arg(format!("-Djava.io.tmpdir={}", cache.display()))
        .arg("-jar")
        .arg(pack.helper_jar())
        .args(arguments)
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS")
        .env_remove("_JAVA_OPTIONS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    use std::os::unix::process::CommandExt as _;
    child.as_std_mut().process_group(0);
    let mut child = child.spawn().map_err(|_| {
        attach_error(
            "XTR-ATTACH-HELPER-FAILED",
            "process",
            "The bounded Java helper could not start.",
            "Install a full JDK with jdk.attach and retry.",
            9,
        )
    })?;
    let process_group = child.id().ok_or_else(|| attach_error("XTR-ATTACH-HELPER-FAILED", "process", "The bounded Java helper identity is unavailable.", "Retry once; if inspection remains unavailable, relaunch the application through X-trace.", 7))?;
    let Some(mut stdout) = child.stdout.take() else {
        stop_helper_group(&mut child, process_group).await;
        return Err(attach_error(
            "XTR-ATTACH-WORKER-UNCONFIRMED",
            "process",
            "The bounded Java helper output is unavailable.",
            "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
            7,
        ));
    };
    let mut output_task = tokio::spawn(async move {
        let mut bytes = Vec::with_capacity(MAX_HELPER_OUTPUT);
        let mut limited = (&mut stdout).take((MAX_HELPER_OUTPUT + 1) as u64);
        limited.read_to_end(&mut bytes).await.map_err(|_| ())?;
        Ok::<_, ()>(bytes)
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAX_HELPER_SECONDS);
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        _ => {
            stop_helper_group(&mut child, process_group).await;
            output_task.abort();
            if let Err(join_error) = output_task.await {
                if !join_error.is_cancelled() {
                    tracing::warn!(
                        code = "XTR-ATTACH-HELPER-OUTPUT-CLEANUP",
                        "bounded helper output task did not stop cleanly"
                    );
                }
            }
            let (code, message) = if command == "attach" {
                (
                    "XTR-ATTACH-WORKER-UNCONFIRMED",
                    "The attach helper timed out and its owned worker could not be confirmed stopped; target state is uncertain.",
                )
            } else {
                (
                    "XTR-ATTACH-WORKER-UNCONFIRMED",
                    "The bounded Java helper timed out and its owned worker could not be confirmed stopped.",
                )
            };
            return Err(attach_error(
                code,
                "process",
                message,
                "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
                7,
            ));
        }
    };
    let bytes = match tokio::time::timeout_at(deadline, &mut output_task).await {
        Ok(result) => result,
        Err(_) => {
            // The leader has already exited. Its PID/PGID may now be reused, so
            // never signal the numeric group; an inherited pipe means a worker
            // is still unconfirmed.
            output_task.abort();
            if let Err(join_error) = output_task.await {
                if !join_error.is_cancelled() {
                    tracing::warn!(code = "XTR-ATTACH-HELPER-OUTPUT-CLEANUP", "bounded helper output task did not stop cleanly");
                }
            }
            let message = if command == "attach" {
                "The attach helper exited without closing its result pipe; a worker remains unconfirmed and target state is uncertain."
            } else {
                "The Java helper exited while an owned worker still held its result pipe."
            };
            let code = "XTR-ATTACH-WORKER-UNCONFIRMED";
            return Err(attach_error(code, "process", message, "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.", 7));
        }
    }
        .map_err(|_| helper_protocol_error(command, "The Java helper output was incomplete."))?
        .map_err(|_| helper_protocol_error(command, "The Java helper output could not be read."))?;
    if bytes.len() > MAX_HELPER_OUTPUT {
        return Err(helper_protocol_error(
            command,
            "The Java helper result exceeded its size bound.",
        ));
    }
    decode_helper_result(&bytes, status.success(), command)
}

fn decode_helper_result(
    bytes: &[u8],
    process_succeeded: bool,
    command: &str,
) -> Result<Value, CliError> {
    let record = match bytes.strip_suffix(b"\r\n") {
        Some(record) => record,
        None => bytes.strip_suffix(b"\n").unwrap_or(bytes),
    };
    if record.contains(&b'\n') || record.contains(&b'\r') {
        return Err(helper_protocol_error(
            command,
            "The Java helper returned more than one result record.",
        ));
    }
    let value: Value = serde_json::from_slice(record)
        .map_err(|_| helper_protocol_error(command, "The Java helper returned malformed JSON."))?;
    let ok = value.get("ok").and_then(Value::as_bool);
    let success_payload_valid = match command {
        "list" => {
            value.get("processes").and_then(Value::as_array).is_some()
                && value.get("truncated").and_then(Value::as_bool).is_some()
        }
        "inspect" | "attach" => value.get("process").and_then(Value::as_object).is_some(),
        _ => false,
    };
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || value.get("command").and_then(Value::as_str) != Some(command)
        || ok != Some(process_succeeded)
        || (ok == Some(true) && value.get("code").and_then(Value::as_str) != Some("XTR-ATTACH-OK"))
        || value.get("code").and_then(Value::as_str).is_none_or(|code| {
            code.len() > 80
                || !code.starts_with("XTR-ATTACH-")
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || value.get("message").and_then(Value::as_str).is_none_or(|message| message.len() > 512)
        || value.get("remediation").and_then(Value::as_str).is_some_and(|text| text.len() > 2048)
        || (ok == Some(true) && !success_payload_valid)
    {
        return Err(helper_protocol_error(
            command,
            "The Java helper returned an inconsistent result.",
        ));
    }
    if ok == Some(false)
        && (value.get("code").and_then(Value::as_str).is_none()
            || value.get("message").and_then(Value::as_str).is_none()
            || value.get("remediation").and_then(Value::as_str).is_none())
    {
        return Err(helper_protocol_error(
            command,
            "The Java helper returned an incomplete failure result.",
        ));
    }
    Ok(value)
}

fn helper_protocol_error(command: &str, message: &str) -> CliError {
    let code = if command == "attach" {
        "XTR-ATTACH-RESULT-UNCERTAIN"
    } else {
        "XTR-ATTACH-HELPER-FAILED"
    };
    attach_error(
        code,
        "process",
        message,
        "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
        7,
    )
}

async fn stop_helper_group(child: &mut tokio::process::Child, raw_pid: u32) {
    use rustix::process::{Pid, Signal, kill_process_group};
    use tokio::time::timeout;
    let Some(owned_pid) = child.id() else { return };
    if owned_pid != raw_pid {
        return;
    }
    let Ok(raw_pid) = i32::try_from(raw_pid) else { return };
    let Some(group) = Pid::from_raw(raw_pid) else { return };
    if let Err(error) = kill_process_group(group, Signal::TERM) {
        tracing::warn!(code = "XTR-ATTACH-WORKER-UNCONFIRMED", errno = %error, "owned helper group termination was not confirmed");
    }
    // Child::id pins the original group leader identity until it is reaped.
    // Signal the group only while that identity is still owned, then reap the
    // leader. Descendants may have escaped or retained pipes, so callers still
    // report WORKER_UNCONFIRMED rather than inferring tree shutdown.
    if child.id() == Some(owned_pid) {
        if let Err(error) = kill_process_group(group, Signal::KILL) {
            tracing::warn!(code = "XTR-ATTACH-WORKER-UNCONFIRMED", errno = %error, "owned helper group kill was not confirmed");
        }
        if let Err(error) = child.start_kill() {
            tracing::warn!(code = "XTR-ATTACH-WORKER-UNCONFIRMED", error_kind = ?error.kind(), "owned helper process kill was not confirmed");
        }
    }
    if !matches!(timeout(Duration::from_secs(2), child.wait()).await, Ok(Ok(_))) {
        tracing::warn!(
            code = "XTR-ATTACH-WORKER-UNCONFIRMED",
            "owned helper leader did not reap within its cleanup bound"
        );
    }
}

fn helper_failure(value: &Value, command: &str) -> CliError {
    let code = value.get("code").and_then(Value::as_str).unwrap_or("XTR-ATTACH-HELPER-FAILED");
    let (stable_code, category, message, remediation, exit) = match code {
        "XTR-ATTACH-DYNAMIC-DISABLED" => (
            "XTR-ATTACH-DYNAMIC-DISABLED",
            "compatibility",
            "The target JVM has disabled dynamic agent loading.",
            "Relaunch with `xtrace run --project-dir <DIR> --java-agent <AGENT> -- java <application arguments>`, or enable dynamic agent loading for this JVM.",
            6,
        ),
        "XTR-ATTACH-OWNER-MISMATCH" => (
            "XTR-ATTACH-OWNER-MISMATCH",
            "permission",
            "The selected JVM belongs to a different operating-system user.",
            "Run X-trace as the JVM owner, or relaunch the application through X-trace.",
            7,
        ),
        "XTR-ATTACH-PROCESS-CHANGED" => (
            "XTR-ATTACH-PROCESS-CHANGED",
            "conflict",
            "The selected PID or its start time changed during attach.",
            "Refresh the process list and inspect the current JVM before attaching again.",
            5,
        ),
        "XTR-ATTACH-UNSUPPORTED-RUNTIME" => (
            "XTR-ATTACH-UNSUPPORTED-RUNTIME",
            "compatibility",
            "The selected process is not a JVM that accepts Java agents.",
            "Use a JVM build of the application and launch it through X-trace.",
            6,
        ),
        "XTR-ATTACH-AGENT-REJECTED" | "XTR-ATTACH-RESULT-UNCERTAIN" => (
            "XTR-ATTACH-RESULT-UNCERTAIN",
            "process",
            "The target may have received the agent, but the helper could not confirm its final state.",
            "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.",
            7,
        ),
        "XTR-ATTACH-WORKER-UNCONFIRMED" => (
            "XTR-ATTACH-WORKER-UNCONFIRMED",
            "process",
            "The helper could not confirm that its owned worker stopped; target attach state is uncertain.",
            "Inspect the helper and target before retrying; relaunch the application through X-trace if attach state remains uncertain.",
            7,
        ),
        "XTR-ATTACH-TIMEOUT" => (
            "XTR-ATTACH-TIMEOUT",
            "process",
            "The bounded JVM attach operation exceeded its time limit.",
            "Inspect the target before retrying; if attach state is uncertain, relaunch through X-trace.",
            7,
        ),
        "XTR-ATTACH-HELPER-TIMEOUT" => (
            "XTR-ATTACH-HELPER-TIMEOUT",
            "process",
            "The bounded Java helper exceeded its time limit.",
            "Retry once; if inspection remains unavailable, relaunch the application through X-trace.",
            7,
        ),
        "XTR-ATTACH-PROCESS-NOT-FOUND" => (
            "XTR-ATTACH-PROCESS-NOT-FOUND",
            "not_found",
            "The selected JVM exited before attach.",
            "Refresh the process list and select a currently running JVM.",
            3,
        ),
        "XTR-ATTACH-UNAVAILABLE"
        | "XTR-ATTACH-JDK-UNAVAILABLE"
        | "XTR-ATTACH-IDENTITY-UNAVAILABLE" => (
            "XTR-ATTACH-UNAVAILABLE",
            "compatibility",
            "The local attach provider could not inspect this JVM.",
            "Use a compatible full JDK in the same user and process namespace, or relaunch the application through X-trace.",
            6,
        ),
        _ if command == "attach" => (
            "XTR-ATTACH-RESULT-UNCERTAIN",
            "process",
            "The helper did not confirm the attach result; target state is uncertain.",
            "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.",
            7,
        ),
        _ => (
            "XTR-ATTACH-FAILED",
            "process",
            "The JVM helper could not attach safely.",
            "Inspect the target before retrying; if attachment remains unavailable, relaunch through X-trace.",
            7,
        ),
    };
    attach_error(stable_code, category, message, remediation, exit)
}

async fn inspect(
    java: &Path,
    pack: &JavaAttachPack,
    cache: &Path,
    pid: u32,
) -> Result<ProcessIdentity, CliError> {
    let pid_text = pid.to_string();
    let value =
        helper_command(java, pack, cache, &["inspect", "--pid", &pid_text, "--json"]).await?;
    if !value.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(helper_failure(&value, "inspect"));
    }
    parse_identity(value.get("process").unwrap_or(&Value::Null)).ok_or_else(|| {
        attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The JVM did not provide a stable PID, start time, and owner.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        )
    })
}

fn select_interactively(rows: &[Value]) -> Result<ProcessIdentity, CliError> {
    require_interactive_terminal(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
    )?;
    if rows.is_empty() {
        return Err(attach_error(
            "XTR-ATTACH-NO-JVMS",
            "not_found",
            "The local attach provider found no selectable JVMs.",
            "Start a compatible JVM under the current user, then retry with --pid <PID>.",
            3,
        ));
    }
    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "Select one listed JVM:")
        .map_err(|_| CliError::StoreUnavailable("write terminal selection failed".to_string()))?;
    for (index, row) in rows.iter().enumerate() {
        let identity = parse_identity(row).ok_or_else(|| {
            attach_error(
                "XTR-ATTACH-IDENTITY-UNAVAILABLE",
                "process",
                "A listed JVM has incomplete identity facts.",
                "Refresh the process list and select a JVM with a stable start time and owner.",
                5,
            )
        })?;
        let command =
            safe_short(row.get("commandSummary").and_then(Value::as_str).unwrap_or("process"));
        let jdk = safe_short(row.get("jdkVersion").and_then(Value::as_str).unwrap_or("unknown"));
        writeln!(
            stderr,
            "  {}  PID {}  {}  JDK {}  owner {}",
            index + 1,
            identity.pid,
            command,
            jdk,
            safe_short(&identity.owner)
        )
        .map_err(|_| CliError::StoreUnavailable("write terminal selection failed".to_string()))?;
    }
    write!(stderr, "Choice (1-{}): ", rows.len())
        .map_err(|_| CliError::StoreUnavailable("write terminal selection failed".to_string()))?;
    stderr
        .flush()
        .map_err(|_| CliError::StoreUnavailable("flush terminal selection failed".to_string()))?;
    drop(stderr);
    let mut choice = Vec::with_capacity(32);
    use std::io::BufRead as _;
    use std::io::Read as _;
    let read = std::io::stdin().lock().take(33).read_until(b'\n', &mut choice);
    if read.is_err() || choice.len() > 32 || choice.last() != Some(&b'\n') {
        return Err(attach_error(
            "XTR-ATTACH-SELECTION-INVALID",
            "validation",
            "The JVM selection was too long or incomplete.",
            "Run xtrace attach again and choose one listed row, or pass --pid <PID>.",
            2,
        ));
    }
    let choice = std::str::from_utf8(&choice).map_err(|_| {
        attach_error(
            "XTR-ATTACH-SELECTION-INVALID",
            "validation",
            "The JVM selection was invalid.",
            "Run xtrace attach again and choose one listed row, or pass --pid <PID>.",
            2,
        )
    })?;
    let selected = choice
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| rows.get(index))
        .and_then(parse_identity)
        .ok_or_else(|| {
            attach_error(
                "XTR-ATTACH-SELECTION-INVALID",
                "validation",
                "The JVM selection was invalid.",
                "Run xtrace attach again and choose one listed row, or pass --pid <PID>.",
                2,
            )
        })?;
    Ok(selected)
}

fn require_interactive_terminal(is_tty: bool) -> Result<(), CliError> {
    if is_tty {
        return Ok(());
    }
    Err(attach_error(
        "XTR-ATTACH-PID-REQUIRED",
        "validation",
        "A PID is required when no interactive terminal is available.",
        "Run xtrace attach --pid <PID> --project-dir <DIR> --java-pack <DIR>.",
        2,
    ))
}

fn parse_identity(value: &Value) -> Option<ProcessIdentity> {
    let pid = u32::try_from(value.get("pid")?.as_u64()?).ok()?;
    let start_time = value.get("startTime")?.as_str()?.to_string();
    let owner = value.get("owner")?.as_str()?.to_string();
    if start_time.is_empty()
        || start_time.len() > 64
        || owner.is_empty()
        || owner == "unknown"
        || owner.len() > 128
    {
        return None;
    }
    Some(ProcessIdentity { pid, start_time, owner })
}

fn verify_identity(expected: &ProcessIdentity, observed: &ProcessIdentity) -> Result<(), CliError> {
    if expected != observed {
        return Err(attach_error(
            "XTR-ATTACH-PROCESS-CHANGED",
            "conflict",
            "The selected PID, start time, or owner changed during inspection.",
            "Refresh the process list and inspect the current JVM before attaching again.",
            5,
        ));
    }
    Ok(())
}

async fn verify_os_identity(identity: &ProcessIdentity) -> Result<(), CliError> {
    use tokio::time::{timeout, timeout_at};
    let pid = identity.pid.to_string();
    // `ps` samples the elapsed time at some instant after this point and before its output is
    // read, so the wall clock is bracketed rather than read once afterwards: a stalled runner
    // that delays this task must not look like a changed process.
    let probe_started = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut command = Command::new("/bin/ps");
    command
        .args(["-p", &pid, "-o", "etime=", "-o", "uid="])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let mut child = command.spawn().map_err(|_| {
        attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The operating system could not verify the selected PID.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        )
    })?;
    let Some(mut stdout) = child.stdout.take() else {
        let kill_result = child.start_kill();
        let reaped = matches!(timeout(Duration::from_secs(1), child.wait()).await, Ok(Ok(_)));
        return Err(attach_error(
            if reaped && kill_result.is_ok() {
                "XTR-ATTACH-IDENTITY-UNAVAILABLE"
            } else {
                "XTR-ATTACH-WORKER-UNCONFIRMED"
            },
            "process",
            "The operating system probe output could not be collected and its process state is uncertain.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        ));
    };
    let mut output_task = tokio::spawn(async move {
        let mut bytes = Vec::with_capacity(128);
        (&mut stdout).take(129).read_to_end(&mut bytes).await.map_err(|_| ())?;
        Ok::<_, ()>(bytes)
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let status = match timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        _ => {
            let kill_result = child.start_kill();
            let wait_result = timeout(Duration::from_secs(1), child.wait()).await;
            if !matches!(wait_result, Ok(Ok(_))) {
                output_task.abort();
                if let Err(join_error) = output_task.await {
                    if !join_error.is_cancelled() {
                        tracing::warn!(
                            code = "XTR-ATTACH-IDENTITY-CLEANUP",
                            "bounded operating-system probe did not stop cleanly"
                        );
                    }
                }
                let code = if kill_result.is_err() {
                    "XTR-ATTACH-WORKER-UNCONFIRMED"
                } else {
                    "XTR-ATTACH-IDENTITY-UNAVAILABLE"
                };
                return Err(attach_error(
                    code,
                    "process",
                    "The operating system identity probe could not be confirmed stopped.",
                    "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
                    5,
                ));
            }
            output_task.abort();
            if let Err(join_error) = output_task.await {
                if !join_error.is_cancelled() {
                    tracing::warn!(
                        code = "XTR-ATTACH-IDENTITY-CLEANUP",
                        "bounded operating-system probe output did not stop cleanly"
                    );
                }
            }
            return Err(attach_error(
                "XTR-ATTACH-IDENTITY-UNAVAILABLE",
                "process",
                "The operating system identity check exceeded its time limit.",
                "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
                5,
            ));
        }
    };
    let output = match timeout_at(deadline, &mut output_task).await {
        Ok(Ok(Ok(output))) => output,
        _ => {
            output_task.abort();
            if let Err(join_error) = output_task.await {
                if !join_error.is_cancelled() {
                    tracing::warn!(
                        code = "XTR-ATTACH-IDENTITY-CLEANUP",
                        "bounded operating-system probe output did not stop cleanly"
                    );
                }
            }
            return Err(attach_error(
                "XTR-ATTACH-WORKER-UNCONFIRMED",
                "process",
                "The operating system probe exited without closing its result pipe; process state is uncertain.",
                "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
                5,
            ));
        }
    };
    if !status.success() || output.len() > 128 {
        return Err(attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The operating system could not verify the selected PID.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        ));
    }
    let fields = std::str::from_utf8(&output)
        .ok()
        .map(str::split_ascii_whitespace)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let [elapsed, uid] = fields.as_slice() else {
        return Err(attach_error(
            "XTR-ATTACH-PROCESS-CHANGED",
            "conflict",
            "The selected JVM is no longer visible to the operating system.",
            "Refresh the process list and inspect the current JVM before attaching again.",
            5,
        ));
    };
    let elapsed = parse_elapsed(elapsed).ok_or_else(|| {
        attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The operating system returned incomplete process identity facts.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        )
    })?;
    let uid = uid.parse::<u32>().map_err(|_| {
        attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The operating system returned incomplete process identity facts.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        )
    })?;
    let observed_start = time::OffsetDateTime::parse(
        &identity.start_time,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| {
        attach_error(
            "XTR-ATTACH-IDENTITY-UNAVAILABLE",
            "process",
            "The JVM start time is not parseable.",
            "Refresh the process list; if identity remains unavailable, relaunch through X-trace.",
            5,
        )
    })?
    .unix_timestamp();
    let probe_finished = time::OffsetDateTime::now_utc().unix_timestamp().max(probe_started);
    if uid != rustix::process::getuid().as_raw() {
        return Err(attach_error(
            "XTR-ATTACH-OWNER-MISMATCH",
            "permission",
            "The selected JVM is not owned by the current operating-system user.",
            "Run X-trace as the JVM owner, or relaunch the application through X-trace.",
            7,
        ));
    }
    if !elapsed_is_consistent(observed_start, probe_started, probe_finished, elapsed) {
        return Err(attach_error(
            "XTR-ATTACH-PROCESS-CHANGED",
            "conflict",
            "The selected PID start time changed during attach preflight.",
            "Refresh the process list and inspect the current JVM before attaching again.",
            5,
        ));
    }
    Ok(())
}

/// True when `ps`'s whole-second elapsed time fits a process that started at `start_unix`, given
/// that `ps` sampled it at an unknown instant in `[probe_started, probe_finished]` (whole unix
/// seconds). The two-second slack covers whole-second truncation on both sides; a start time that
/// is genuinely different still falls outside it.
fn elapsed_is_consistent(
    start_unix: i64,
    probe_started: i64,
    probe_finished: i64,
    ps_elapsed: u64,
) -> bool {
    let low = probe_started.saturating_sub(start_unix);
    let high = probe_finished.saturating_sub(start_unix);
    if high < 0 {
        return false;
    }
    let Ok(ps) = i64::try_from(ps_elapsed) else {
        return false;
    };
    ps >= low.saturating_sub(2) && ps <= high.saturating_add(2)
}

fn parse_elapsed(value: &str) -> Option<u64> {
    let (days, clock) = value
        .split_once('-')
        .map_or((0_u64, value), |(days, clock)| (days.parse().unwrap_or(u64::MAX), clock));
    if days == u64::MAX {
        return None;
    }
    let components = clock.split(':').map(str::parse::<u64>).collect::<Result<Vec<_>, _>>().ok()?;
    let (hours, minutes, seconds) = match components.as_slice() {
        [minutes, seconds] if *minutes < 60 => (0, *minutes, *seconds),
        [hours, minutes, seconds] if *minutes < 60 => (*hours, *minutes, *seconds),
        _ => return None,
    };
    if seconds >= 60 || hours >= 24 || (days > 0 && components.len() != 3) {
        return None;
    }
    days.checked_mul(86_400)?
        .checked_add(hours.checked_mul(3_600)?)?
        .checked_add(minutes.checked_mul(60)?)?
        .checked_add(seconds)
}

fn process_document(value: &Value) -> Option<SafeProcess> {
    parse_identity(value)?;
    let command_summary =
        value.get("commandSummary").and_then(Value::as_str).map(safe_short)?.to_string();
    let jdk_version =
        value.get("jdkVersion").and_then(Value::as_str).map(safe_short).map(str::to_string);
    let owner = value.get("owner").and_then(Value::as_str).map(safe_short)?.to_string();
    Some(SafeProcess { command_summary, jdk_version, owner })
}

fn safe_short(input: &str) -> &str {
    if input.len() <= 64
        && input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'@'))
    {
        input
    } else {
        "unknown"
    }
}

fn resolve_java() -> Result<PathBuf, &'static str> {
    let path = std::env::var_os("PATH").ok_or("PATH does not contain a Java launcher")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("java");
        if let Ok(metadata) = std::fs::metadata(&candidate) {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                return candidate
                    .canonicalize()
                    .map_err(|_| "the Java launcher path is unavailable");
            }
        }
    }
    Err("PATH does not contain a Java launcher")
}

struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    fn install() -> Result<Self, CliError> {
        use tokio::signal::unix::{SignalKind, signal};
        let interrupt = signal(SignalKind::interrupt()).map_err(|_| {
            attach_error("XTR-ATTACH-SIGNAL-UNAVAILABLE", "process", "The CLI could not install its shutdown handlers.", "Retry from an interactive terminal; if signal setup remains unavailable, use `xtrace daemon` for the documented foreground lifecycle.", 7)
        })?;
        let terminate = signal(SignalKind::terminate()).map_err(|_| {
            attach_error("XTR-ATTACH-SIGNAL-UNAVAILABLE", "process", "The CLI could not install its shutdown handlers.", "Retry from an interactive terminal; if signal setup remains unavailable, use `xtrace daemon` for the documented foreground lifecycle.", 7)
        })?;
        Ok(Self { interrupt, terminate })
    }

    async fn wait(&mut self) -> Result<(), CliError> {
        let received = tokio::select! {
            result = self.interrupt.recv() => result,
            result = self.terminate.recv() => result,
        };
        if received.is_some() {
            Ok(())
        } else {
            Err(attach_error(
                "XTR-ATTACH-SIGNAL-UNAVAILABLE",
                "process",
                "The CLI shutdown signal stream ended unexpectedly.",
                "Retry from an interactive terminal; if signal setup remains unavailable, use `xtrace daemon` for the documented foreground lifecycle.",
                7,
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests use fixed identity and JSON facts")]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::cell::RefCell;
    use xtrace_domain::RuntimeSessionId;

    fn private_tempdir() -> tempfile::TempDir {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        xtrace_private_storage::AdmittedPrivateRoot::open(&scratch)
            .expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix("xtrace-attach-test-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("private attach test directory")
    }

    #[test]
    fn non_tty_attach_requires_explicit_pid_even_for_one_listed_process() {
        let rows = [serde_json::json!({
            "pid": 41,
            "startTime": "2026-10-04T00:00:00Z",
            "owner": "xtrace-test"
        })];
        assert_eq!(rows.len(), 1);
        let error = require_interactive_terminal(false).expect_err("PID must be explicit");
        assert!(matches!(&error, CliError::Attach { code: "XTR-ATTACH-PID-REQUIRED", .. }));
        if let CliError::Attach { remediation, .. } = error {
            assert!(remediation.contains("--java-pack <DIR>"));
        }
    }

    #[test]
    fn attach_requires_explicit_development_pack() {
        let error = crate::Cli::try_parse_from([
            "xtrace",
            "attach",
            "--project-dir",
            "/tmp/project",
            "--pid",
            "41",
        ])
        .expect_err("unsigned development pack must be explicit");
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn elapsed_check_brackets_the_probe_window_and_still_rejects_a_different_start() {
        // Same instant: exactly the old two-second tolerance.
        assert!(elapsed_is_consistent(1_000, 1_100, 1_100, 100));
        assert!(elapsed_is_consistent(1_000, 1_100, 1_100, 102));
        assert!(elapsed_is_consistent(1_000, 1_100, 1_100, 98));
        assert!(!elapsed_is_consistent(1_000, 1_100, 1_100, 103));
        assert!(!elapsed_is_consistent(1_000, 1_100, 1_100, 97));
        // A probe that took five seconds (stalled runner): ps sampled anywhere inside it.
        assert!(elapsed_is_consistent(1_000, 1_100, 1_105, 104));
        assert!(elapsed_is_consistent(1_000, 1_100, 1_105, 107));
        assert!(!elapsed_is_consistent(1_000, 1_100, 1_105, 108));
        // A process that started ten seconds earlier or later is a different process.
        assert!(!elapsed_is_consistent(990, 1_100, 1_101, 100));
        assert!(!elapsed_is_consistent(1_010, 1_100, 1_101, 100));
        // A start time in the future is never consistent.
        assert!(!elapsed_is_consistent(2_000, 1_100, 1_101, 0));
    }

    #[test]
    fn identity_binding_requires_same_pid_start_time_and_owner() {
        let selected = ProcessIdentity {
            pid: 204,
            start_time: "2026-10-04T01:02:03Z".to_string(),
            owner: "xtrace-test".to_string(),
        };
        assert!(verify_identity(&selected, &selected).is_ok());
        let changed =
            ProcessIdentity { start_time: "2026-10-04T01:02:04Z".to_string(), ..selected.clone() };
        assert!(verify_identity(&selected, &changed).is_err());
        let changed_owner = ProcessIdentity { owner: "other-user".to_string(), ..selected.clone() };
        assert!(verify_identity(&selected, &changed_owner).is_err());
    }

    #[test]
    fn process_elapsed_parser_handles_platform_formats() {
        assert_eq!(parse_elapsed("00:07"), Some(7));
        assert_eq!(parse_elapsed("01:02:03"), Some(3_723));
        assert_eq!(parse_elapsed("2-01:02:03"), Some(176_523));
        assert_eq!(parse_elapsed("1-25:00:00"), None);
        assert_eq!(parse_elapsed("bad"), None);
    }

    #[test]
    fn helper_failure_codes_are_allowlisted_before_public_output() {
        let value = serde_json::json!({
            "code": "XTR-ATTACH-BOGUS-PRIVATE-PATH",
            "message": "/private/source/path",
            "remediation": "secret"
        });
        let error = helper_failure(&value, "list");
        assert!(matches!(error, CliError::Attach { code: "XTR-ATTACH-FAILED", .. }));
        assert!(!error.to_string().contains("/private/source/path"));

        let attach_error = helper_failure(&value, "attach");
        assert!(matches!(
            attach_error,
            CliError::Attach { code: "XTR-ATTACH-RESULT-UNCERTAIN", .. }
        ));
    }

    #[test]
    fn helper_envelope_accepts_main_newline_and_rejects_extra_or_contradictory_records() {
        let record = br#"{"schemaVersion":1,"ok":true,"command":"inspect","code":"XTR-ATTACH-OK","message":"JVM operation completed.","process":{}}"#;
        let mut line = record.to_vec();
        line.push(b'\n');
        assert!(decode_helper_result(&line, true, "inspect").is_ok());

        let mut crlf = record.to_vec();
        crlf.extend_from_slice(b"\r\n");
        assert!(decode_helper_result(&crlf, true, "inspect").is_ok());

        let mut extra_line = line.clone();
        extra_line.push(b'\n');
        assert!(decode_helper_result(&extra_line, true, "inspect").is_err());
        assert!(decode_helper_result(&line, false, "inspect").is_err());
        assert!(decode_helper_result(&line, true, "attach").is_err());
        assert!(decode_helper_result(b"not-json\n", true, "inspect").is_err());
    }

    #[tokio::test]
    async fn helper_cleanup_never_signals_numeric_group_after_leader_reap() {
        use std::os::unix::process::CommandExt as _;
        use tokio::io::AsyncBufReadExt as _;

        let mut leader_command = Command::new("/bin/sh");
        leader_command
            .args(["-c", "sleep 10 & echo $!; wait"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        leader_command.as_std_mut().process_group(0);
        let mut leader = leader_command.spawn().expect("owned helper-group leader");
        let leader_pid = leader.id().expect("leader PID");
        let mut stdout = tokio::io::BufReader::new(leader.stdout.take().expect("worker pid pipe"));
        let mut worker_line = String::new();
        stdout.read_line(&mut worker_line).await.expect("worker PID");
        let worker_pid = worker_line.trim().parse::<u32>().expect("numeric worker PID");
        leader.start_kill().expect("stop group leader only");
        leader.wait().await.expect("reap group leader");
        assert!(leader.id().is_none());

        stop_helper_group(&mut leader, leader_pid).await;

        let alive = std::process::Command::new("/bin/ps")
            .args(["-p", &worker_pid.to_string(), "-o", "pid="])
            .output()
            .expect("inspect owned test worker");
        assert!(
            alive.status.success(),
            "reaped leader cleanup signaled a reused or still-owned group"
        );
        let terminated = std::process::Command::new("/bin/kill")
            .args(["-TERM", &worker_pid.to_string()])
            .status()
            .expect("stop test-owned worker by its reported PID");
        assert!(terminated.success());
    }

    #[tokio::test]
    async fn unconfirmed_blocking_server_work_retains_lock_and_runtime_artifacts() {
        let project = private_tempdir();
        let admitted = xtrace_private_storage::AdmittedPrivateRoot::open(project.path())
            .expect("admitted project root");
        let lock = crate::daemon_lock::acquire_project_lock(&admitted).expect("project lock");
        let runtime =
            crate::daemon_lock::RuntimeDirectory::create(&admitted, RuntimeSessionId::new())
                .expect("session directory");
        let session_path = runtime.path().to_path_buf();
        let marker_path = session_path.join(".in-flight-marker");
        std::fs::write(&marker_path, b"still in use").expect("marker");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocking = tokio::task::spawn_blocking(move || {
            started_tx.send(()).expect("signal work started");
            release_rx.recv().expect("release blocking storage work");
        });
        let mut server = tokio::spawn(async move {
            let _ = blocking.await;
            Ok::<(), xtrace_daemon::DaemonError>(())
        });
        started_rx.await.expect("blocking work started");

        let drain = await_owned_server_with_timeout(&mut server, Duration::from_millis(10)).await;
        assert!(matches!(drain, OwnedServerResult::Unconfirmed));
        retain_unconfirmed_runtime(runtime, lock);
        assert!(marker_path.exists(), "unconfirmed work must retain its session artifacts");
        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));

        release_tx.send(()).expect("release work after retention assertion");
        server.await.expect("server completes when blocking work is released").expect("server ok");
        assert!(marker_path.exists(), "retained artifacts are left for process-exit cleanup");
        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));
    }

    #[tokio::test]
    async fn cancelled_server_with_started_blocking_work_retains_lock_and_artifacts() {
        let project = private_tempdir();
        let admitted = xtrace_private_storage::AdmittedPrivateRoot::open(project.path())
            .expect("admitted project root");
        let lock = crate::daemon_lock::acquire_project_lock(&admitted).expect("project lock");
        let runtime =
            crate::daemon_lock::RuntimeDirectory::create(&admitted, RuntimeSessionId::new())
                .expect("session directory");
        let marker_path = runtime.path().join(".blocking-work-marker");
        std::fs::write(&marker_path, b"storage closure is active").expect("marker");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocking = tokio::task::spawn_blocking(move || {
            started_tx.send(()).expect("signal blocking closure started");
            release_rx.recv().expect("release blocking closure");
            finished_tx.send(()).expect("signal blocking closure finished");
        });
        let mut server = tokio::spawn(async move {
            let _ = blocking.await;
            Ok::<(), xtrace_daemon::DaemonError>(())
        });
        started_rx.await.expect("blocking storage closure started");
        server.abort();

        let drain = await_owned_server_with_timeout(&mut server, Duration::from_secs(1)).await;
        assert!(matches!(drain, OwnedServerResult::Unconfirmed));
        retain_unconfirmed_runtime(runtime, lock);
        assert!(marker_path.exists(), "cancelled wrapper must not clean live-work artifacts");
        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));

        release_tx.send(()).expect("release blocking closure after assertions");
        finished_rx.await.expect("blocking closure completed");
        assert!(marker_path.exists(), "artifacts remain until process exit");
        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));
    }

    #[test]
    fn confirmed_cleanup_failure_drops_runtime_before_releasing_lock() {
        struct DropEvent<'a> {
            name: &'static str,
            events: &'a RefCell<Vec<&'static str>>,
        }

        impl Drop for DropEvent<'_> {
            fn drop(&mut self) {
                self.events.borrow_mut().push(self.name);
            }
        }

        let events = RefCell::new(Vec::new());
        let runtime = DropEvent { name: "runtime-drop", events: &events };
        let lock = DropEvent { name: "lock-drop", events: &events };
        let result = finish_confirmed_runtime(runtime, lock, |_| {
            events.borrow_mut().push("cleanup");
            Err(attach_error(
                "XTR-ATTACH-CLEANUP-FAILED",
                "process",
                "cleanup failed",
                "retry cleanup",
                7,
            ))
        });

        assert!(result.is_err(), "cleanup failure must remain observable");
        assert_eq!(events.borrow().as_slice(), &["cleanup", "runtime-drop", "lock-drop"]);
    }
}
