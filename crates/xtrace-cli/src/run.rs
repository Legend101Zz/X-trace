//! Project-scoped composition for the experimental direct-Java launch path.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::CliError;

#[cfg(unix)]
const DAEMON_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Launches a validated direct Java executable under the project daemon.
pub(crate) async fn run(
    project_dir: PathBuf,
    java_agent: PathBuf,
    observed_endpoint_policy: Option<String>,
    application_component: Option<String>,
    binding_key: Option<String>,
    capture: crate::capture_args::CaptureOptions,
    command: Vec<OsString>,
) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = (
            project_dir,
            java_agent,
            observed_endpoint_policy,
            application_component,
            binding_key,
            capture,
            command,
        );
        Err(CliError::DaemonUnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        run_unix(
            project_dir,
            java_agent,
            observed_endpoint_policy,
            application_component,
            binding_key,
            capture,
            command,
        )
        .await
    }
}

/// Launches a validated direct Node process under the project daemon.
pub(crate) async fn run_node(
    project_dir: PathBuf,
    adapter_dist: PathBuf,
    mode: String,
    command: Vec<OsString>,
) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = (project_dir, adapter_dist, mode, command);
        Err(CliError::DaemonUnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let mode = xtrace_runtime::node::NodeMode::parse(&mode).map_err(CliError::NodeRun)?;
        run_node_unix(project_dir, adapter_dist, mode, command).await
    }
}

#[cfg(unix)]
async fn run_node_unix(
    project_dir: PathBuf,
    adapter_dist: PathBuf,
    mode: xtrace_runtime::node::NodeMode,
    command: Vec<OsString>,
) -> Result<i32, CliError> {
    use tokio::sync::oneshot;
    use xtrace_runtime::node::{NodeLaunch, NodeSignals};

    // Runtime, lock, and daemon side effects wait until both Node and its
    // explicit adapter distribution have passed preflight.
    let launch = NodeLaunch::validate(&adapter_dist, mode, &command).map_err(CliError::NodeRun)?;
    let mut signals = NodeSignals::install().map_err(CliError::NodeRun)?;
    let prepared = crate::daemon::prepare(project_dir, &crate::paths::read_env_path).await?;
    let crate::daemon::PreparedDaemon { bound, bootstrap_path, mut runtime_dir, lock } = prepared;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut daemon_task = tokio::spawn(async move {
        bound
            .serve(async move {
                if shutdown_rx.await.is_err() {
                    // A dropped sender also ends this one-shot daemon lifetime.
                }
            })
            .await
    });

    let spawn_result = launch.spawn(&bootstrap_path);
    let (mut child, mut launch_error) = match spawn_result {
        Ok(child) => (Some(child), None),
        Err(error) => (None, Some(error)),
    };
    let child_started = child.is_some();
    let mut capture_notice_written = false;
    let mut daemon_outcome = None;
    let mut child_status = None;
    if let Some(node_child) = child.as_mut() {
        let (status, observed_daemon) =
            observe_child_and_daemon(node_child.wait(&mut signals), &mut daemon_task, || {
                write_capture_incomplete();
                capture_notice_written = true;
            })
            .await;
        match status {
            Ok(status) => child_status = Some(status),
            Err(error) => launch_error = Some(error),
        }
        daemon_outcome = observed_daemon;
    }

    let mut capture_incomplete = child_started && launch_error.is_some();
    if child_status.is_some_and(|status| {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal().is_some()
    }) {
        capture_incomplete = true;
    }
    if shutdown_tx.send(()).is_err() {
        capture_incomplete = true;
    }
    if let Some(outcome) = daemon_outcome {
        if !matches!(outcome, Ok(Ok(()))) {
            capture_incomplete = true;
        }
        let bootstrap_remains = bootstrap_path.exists();
        let cleanup_failed = runtime_dir.cleanup().is_err();
        if bootstrap_remains || cleanup_failed {
            capture_incomplete = true;
        }
        drop(runtime_dir);
        drop(lock);
    } else {
        let finalization =
            finalize_daemon(daemon_task, runtime_dir, lock, DAEMON_DRAIN_BUDGET).await;
        if finalization.cleanup_failed || finalization.deferred {
            capture_incomplete = true;
        }
        if finalization.outcome.is_some_and(|outcome| !matches!(outcome, Ok(Ok(())))) {
            capture_incomplete = true;
        }
    }
    drop(child);
    if capture_incomplete && child_started && !capture_notice_written {
        write_capture_incomplete();
    }
    if let Some(error) = launch_error {
        return Err(CliError::NodeRun(error));
    }
    child_status
        .map(child_exit_code)
        .ok_or(CliError::NodeRun(xtrace_runtime::node::LaunchError::Process))
}

#[cfg(unix)]
async fn run_unix(
    project_dir: PathBuf,
    java_agent: PathBuf,
    observed_endpoint_policy: Option<String>,
    application_component: Option<String>,
    binding_key: Option<String>,
    capture: crate::capture_args::CaptureOptions,
    command: Vec<OsString>,
) -> Result<i32, CliError> {
    use tokio::sync::oneshot;
    use xtrace_runtime::java::{JavaLaunch, JavaSignals};

    // No project lock, runtime directory, or daemon is created until both the
    // direct JDK and private agent distribution have passed runtime preflight.
    let launch = JavaLaunch::validate(&java_agent, &command).map_err(CliError::Run)?;
    let mut signals = JavaSignals::install().map_err(CliError::Run)?;

    // Scope is resolved before any side effect so the observation policy can be derived from it.
    let jar = xtrace_runtime::java_scope::jar_from_java_args(&command);
    let scope = xtrace_runtime::java_scope::resolve_scope(&capture.app_packages, jar.as_deref());
    // An operator-selected endpoint observation policy attributes routes to application-owned
    // handlers, so it is only meaningful when application scope is known. `spring-orders-v1` is
    // itself a fixture literal: the store confines it to the fixture component/binding tuple.
    if observed_endpoint_policy.is_some() && scope.application_packages.is_empty() {
        return Err(CliError::InvalidArgument(
            "--observed-endpoint-policy needs a resolved application scope: pass --app-package \
             or launch a Spring Boot fat jar whose BOOT-INF/classes names the application packages"
                .to_string(),
        ));
    }
    let run_observation = xtrace_application::recording::EndpointObservationInput {
        policy_id: observed_endpoint_policy,
        application_component,
        binding_key,
        ..xtrace_application::recording::EndpointObservationInput::default()
    };
    // The JVM may be started from any directory, so the repository the operator named is passed
    // to the agent in the private capture file; source roots resolve against it.
    let source_base = std::fs::canonicalize(&project_dir)
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned));
    let prepared = crate::daemon::prepare_with_observation(
        project_dir,
        &crate::paths::read_env_path,
        run_observation,
    )
    .await?;
    let crate::daemon::PreparedDaemon { bound, bootstrap_path, mut runtime_dir, lock } = prepared;

    // CONTRACTS 10.3: scope and capture options reach the agent and the daemon through the
    // private capture.json beside the bootstrap. Scope is resolved from the explicit prefixes,
    // else from a Spring Boot fat jar's BOOT-INF/classes, else it is honestly empty.
    let mut capture_document = crate::capture_args::document(
        capture.depth,
        &scope.application_packages,
        &capture.source_roots,
    );
    if let (Some(base), Some(object)) = (source_base, capture_document.as_object_mut()) {
        object.insert("project_dir".to_owned(), serde_json::Value::String(base));
    }
    if let Err(error) = crate::capture_args::write_beside(&bootstrap_path, &capture_document) {
        let _ = runtime_dir.cleanup();
        drop(runtime_dir);
        drop(lock);
        return Err(error);
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut daemon_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    // From this point every result is collected before entering the shared
    // finalizer. JavaChild's drop guard also kills the process group on unwind.
    let spawn_result = launch.spawn(&bootstrap_path);
    let (mut child, mut launch_error) = match spawn_result {
        Ok(child) => (Some(child), None),
        Err(error) => (None, Some(error)),
    };
    let child_started = child.is_some();
    let mut capture_notice_written = false;
    let mut daemon_outcome = None;
    let mut child_status = None;
    if let Some(java_child) = child.as_mut() {
        let (status, observed_daemon) =
            observe_child_and_daemon(java_child.wait(&mut signals), &mut daemon_task, || {
                write_capture_incomplete();
                capture_notice_written = true;
            })
            .await;
        match status {
            Ok(status) => child_status = Some(status),
            Err(error) => launch_error = Some(error),
        }
        daemon_outcome = observed_daemon;
    }

    let mut capture_incomplete = child_started && launch_error.is_some();
    if child_status.is_some_and(|status| {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal().is_some()
    }) {
        capture_incomplete = true;
    }
    let _ = shutdown_tx.send(());
    if let Some(outcome) = daemon_outcome {
        if !matches!(outcome, Ok(Ok(()))) {
            capture_incomplete = true;
        }
        let bootstrap_remains = bootstrap_path.exists();
        let cleanup_failed = runtime_dir.cleanup().is_err();
        if bootstrap_remains || cleanup_failed {
            capture_incomplete = true;
        }
        // Keep the advisory lock through RuntimeDirectory's final Drop retry.
        drop(runtime_dir);
        drop(lock);
    } else {
        let finalization =
            finalize_daemon(daemon_task, runtime_dir, lock, DAEMON_DRAIN_BUDGET).await;
        if finalization.cleanup_failed || finalization.deferred {
            capture_incomplete = true;
        }
        if finalization.outcome.is_some_and(|outcome| !matches!(outcome, Ok(Ok(())))) {
            capture_incomplete = true;
        }
    }
    drop(child);

    if capture_incomplete && child_started && !capture_notice_written {
        write_capture_incomplete();
    }
    if let Some(error) = launch_error {
        return Err(CliError::Run(error));
    }
    child_status
        .map(child_exit_code)
        .ok_or(CliError::Run(xtrace_runtime::java::LaunchError::Process))
}

#[cfg(unix)]
async fn observe_child_and_daemon<C, R, T, F>(
    child_wait: C,
    daemon_task: &mut tokio::task::JoinHandle<T>,
    mut on_early_daemon_exit: F,
) -> (R, Option<Result<T, tokio::task::JoinError>>)
where
    C: std::future::Future<Output = R>,
    T: Send + 'static,
    F: FnMut(),
{
    tokio::pin!(child_wait);
    tokio::select! {
        child = &mut child_wait => (child, None),
        daemon = daemon_task => {
            on_early_daemon_exit();
            // Do not cancel an in-flight Java wait after daemon failure: the
            // user's process remains supervised until it exits or is signalled.
            (child_wait.await, Some(daemon))
        }
    }
}

#[cfg(unix)]
struct DaemonFinalization<T> {
    outcome: Option<Result<T, tokio::task::JoinError>>,
    cleanup_failed: bool,
    deferred: bool,
}

#[cfg(unix)]
async fn finalize_daemon<T: Send + 'static>(
    daemon_task: tokio::task::JoinHandle<T>,
    mut runtime_dir: crate::daemon_lock::RuntimeDirectory,
    lock: crate::daemon_lock::ProjectDaemonLock,
    drain_budget: std::time::Duration,
) -> DaemonFinalization<T> {
    let mut daemon_task = daemon_task;
    match tokio::time::timeout(drain_budget, &mut daemon_task).await {
        Ok(outcome) => {
            let cleanup_failed = runtime_dir.cleanup().is_err();
            // Ensure Drop's best-effort retry also runs before unlocking.
            drop(runtime_dir);
            drop(lock);
            DaemonFinalization { outcome: Some(outcome), cleanup_failed, deferred: false }
        }
        Err(_) => {
            runtime_dir.defer_drop_cleanup();
            // The CLI must return the application's status within its drain
            // budget. There is no same-process custodian: main exits after
            // this call, so preserve artifacts and the advisory lock until
            // process termination. Embedders intentionally retain both too;
            // they must not allow another capture to overlap unfinished work.
            std::mem::forget(runtime_dir);
            std::mem::forget(lock);
            // Dropping JoinHandle detaches but does not cancel unsafe started
            // daemon work. It can continue only until the CLI process exits.
            drop(daemon_task);
            DaemonFinalization { outcome: None, cleanup_failed: false, deferred: true }
        }
    }
}

#[cfg(unix)]
fn child_exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

#[cfg(unix)]
fn write_capture_incomplete() {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Incomplete {
        kind: &'static str,
        code: &'static str,
        message: &'static str,
    }
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let document = Incomplete {
        kind: "capture_incomplete",
        code: "XTR-RUN-CAPTURE-INCOMPLETE",
        message: "the application ran, but X-trace could not confirm complete capture",
    };
    let _ = crate::output::write_success_line(&mut handle, &document);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "exit mapping uses fixed test values")]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn private_tempdir() -> tempfile::TempDir {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        xtrace_private_storage::AdmittedPrivateRoot::open(&scratch)
            .expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix("xtrace-run-test-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("private run test directory")
    }

    #[test]
    fn signaled_java_status_maps_to_shell_conventional_exit_code() {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(child_exit_code(std::process::ExitStatus::from_raw(9)), 137);
    }

    #[tokio::test]
    async fn early_daemon_failure_notifies_once_and_does_not_cancel_child_wait() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let daemon_task = tokio::spawn(async { Err::<(), _>("injected early failure") });
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<usize>();
        let notices = Arc::new(AtomicUsize::new(0));
        let task_notices = Arc::clone(&notices);
        let worker = tokio::spawn(async move {
            let mut daemon_task = daemon_task;
            observe_child_and_daemon(
                async move { release_rx.await.expect("release child wait") },
                &mut daemon_task,
                || {
                    task_notices.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while notices.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("early daemon failure was observed");
        assert!(!worker.is_finished(), "daemon completion cancelled the child wait");
        release_tx.send(23).expect("release child wait");
        let (child_result, daemon_result) = worker.await.expect("join observer");
        assert_eq!(child_result, 23);
        assert!(matches!(daemon_result, Some(Ok(Err("injected early failure")))));
        assert_eq!(notices.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drain_timeout_returns_and_intentionally_retains_lock_and_artifacts() {
        use std::time::{Duration, Instant};
        use xtrace_domain::RuntimeSessionId;

        let root = private_tempdir();
        let admitted = xtrace_private_storage::AdmittedPrivateRoot::open(root.path())
            .expect("admitted project root");
        let lock = crate::daemon_lock::acquire_project_lock(&admitted).expect("project lock");
        let runtime_dir =
            crate::daemon_lock::RuntimeDirectory::create(&admitted, RuntimeSessionId::new())
                .expect("runtime directory");
        let session_path = runtime_dir.path().to_path_buf();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let daemon_task = tokio::spawn(async move {
            let _ = release_rx.await;
            Ok::<(), ()>(())
        });

        let started = Instant::now();
        let result =
            finalize_daemon(daemon_task, runtime_dir, lock, Duration::from_millis(20)).await;
        assert!(result.deferred);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(session_path.exists(), "runtime artifact was removed before drain completed");
        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));

        assert!(matches!(
            crate::daemon_lock::acquire_project_lock(&admitted),
            Err(CliError::DaemonAlreadyRunning)
        ));
    }
}
