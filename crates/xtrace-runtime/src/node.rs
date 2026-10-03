//! Validated direct-Node launch and Unix process-group supervision.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Coarse class for a Node launch failure.
pub enum LaunchErrorKind {
    /// User input or a selected adapter artifact is invalid.
    Validation,
    /// The host cannot provide the requested runtime operation.
    Unsupported,
    /// A process could not be started, signalled, waited for, or reaped.
    Process,
}

/// A sanitized Node launch or process-supervision failure.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// Launch input failed pre-side-effect validation.
    #[error("{0}")]
    Validation(&'static str),
    /// The host does not support direct Node supervision.
    #[error("direct Node supervision is unsupported on this platform")]
    Unsupported,
    /// Process creation or supervision failed.
    #[error("could not start or supervise the Node launcher")]
    Process,
}

impl LaunchError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "XTR-NODE-INVALID-LAUNCH",
            Self::Unsupported => "XTR-NODE-UNSUPPORTED",
            Self::Process => "XTR-NODE-PROCESS",
        }
    }
    /// Returns the stable coarse error category.
    #[must_use]
    pub const fn kind(&self) -> LaunchErrorKind {
        match self {
            Self::Validation(_) => LaunchErrorKind::Validation,
            Self::Unsupported => LaunchErrorKind::Unsupported,
            Self::Process => LaunchErrorKind::Process,
        }
    }
    /// Returns the CLI status associated with this category.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.kind() {
            LaunchErrorKind::Validation => 2,
            LaunchErrorKind::Unsupported => 6,
            LaunchErrorKind::Process => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Explicit Node module mode used to select the adapter preload.
pub enum NodeMode {
    /// CommonJS application launched with `--require`.
    CommonJs,
    /// ES module application launched with `--import`.
    EsModule,
}

impl NodeMode {
    /// Parses only the documented short mode names.
    pub fn parse(value: &str) -> Result<Self, LaunchError> {
        match value {
            "cjs" => Ok(Self::CommonJs),
            "esm" => Ok(Self::EsModule),
            _ => Err(LaunchError::Validation("Node mode must be cjs or esm")),
        }
    }
}

/// A preflighted Node command and adapter distribution.
#[derive(Clone, Debug)]
pub struct NodeLaunch {
    executable: PathBuf,
    adapter: PathBuf,
    preload: PathBuf,
    mode: NodeMode,
    arguments: Vec<OsString>,
    original_options: Option<OsString>,
}

impl NodeLaunch {
    /// Validates a direct native Node 22/24 executable and a hashed adapter dist.
    pub fn validate(
        adapter_dist: &Path,
        mode: NodeMode,
        command: &[OsString],
    ) -> Result<Self, LaunchError> {
        Self::validate_with_environment(
            adapter_dist,
            mode,
            command,
            std::env::var_os("PATH").as_deref(),
            |name| std::env::var_os(name),
        )
    }

    /// Deterministic validation entry point for callers and tests.
    pub fn validate_with_environment<F>(
        adapter_dist: &Path,
        mode: NodeMode,
        command: &[OsString],
        path: Option<&OsStr>,
        env: F,
    ) -> Result<Self, LaunchError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let (program, arguments) = command
            .split_first()
            .ok_or(LaunchError::Validation("a direct node executable is required after --"))?;
        let program_path = Path::new(program);
        if program_path.file_name().is_none_or(|name| name != "node") {
            return Err(LaunchError::Validation(
                "xtrace run accepts only a direct executable named node",
            ));
        }
        if command.iter().any(|argument| argument.as_os_str().as_bytes().contains(&0)) {
            return Err(LaunchError::Validation("Node launch arguments cannot contain NUL bytes"));
        }
        validate_node_options_arguments(arguments)?;
        let executable = resolve_executable(program_path, path)?;
        let metadata = std::fs::metadata(&executable)
            .map_err(|_| LaunchError::Validation("the Node launcher is unavailable"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(LaunchError::Validation(
                "the Node launcher is not an executable regular file",
            ));
        }
        verify_node_version(&executable)?;
        let adapter_metadata = std::fs::symlink_metadata(adapter_dist)
            .map_err(|_| LaunchError::Validation("the Node adapter distribution is unavailable"))?;
        if adapter_metadata.file_type().is_symlink() || !adapter_metadata.is_dir() {
            return Err(LaunchError::Validation("the Node adapter dist must be a real directory"));
        }
        let adapter = adapter_dist
            .canonicalize()
            .map_err(|_| LaunchError::Validation("the Node adapter distribution is unavailable"))?;
        validate_distribution(&adapter)?;
        let preload = adapter.join(match mode {
            NodeMode::CommonJs => "register.cjs",
            NodeMode::EsModule => "register.mjs",
        });
        let original_options = env("NODE_OPTIONS");
        if let Some(options) = original_options.as_ref() {
            let text = options
                .to_str()
                .ok_or(LaunchError::Validation("NODE_OPTIONS must be valid UTF-8"))?;
            if text.as_bytes().contains(&0) {
                return Err(LaunchError::Validation("NODE_OPTIONS cannot contain NUL bytes"));
            }
            validate_node_options(text)?;
        }
        for reserved in
            ["XTRACE_BOOTSTRAP_PATH", "XTRACE_NODE_ORIGINAL_OPTIONS", "XTRACE_NODE_OPTIONS_WAS_SET"]
        {
            if env(reserved).is_some() {
                return Err(LaunchError::Validation(
                    "reserved XTRACE launch environment is already set",
                ));
            }
        }
        Ok(Self {
            executable,
            adapter,
            preload,
            mode,
            arguments: arguments.to_vec(),
            original_options,
        })
    }

    /// Returns the canonical executable selected during preflight.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    /// Returns the canonical, integrity-checked adapter dist.
    #[must_use]
    pub fn adapter(&self) -> &Path {
        &self.adapter
    }
    /// Returns the explicit module mode.
    #[must_use]
    pub fn mode(&self) -> NodeMode {
        self.mode
    }

    /// Spawns the direct Node child with one private preloader and bootstrap.
    pub fn spawn(&self, bootstrap: &Path) -> Result<NodeChild, LaunchError> {
        use std::os::unix::process::CommandExt as _;
        use tokio::process::Command;
        let preload_value = match self.mode {
            NodeMode::CommonJs => quote_node_option(&self.preload)?,
            NodeMode::EsModule => file_url(&self.preload)?,
        };
        let mut options =
            self.original_options.as_ref().and_then(|v| v.to_str()).unwrap_or("").to_owned();
        if !options.is_empty() {
            options.push(' ');
        }
        match self.mode {
            NodeMode::CommonJs => options.push_str(&format!("--require={preload_value}")),
            NodeMode::EsModule => options.push_str(&format!("--import={preload_value}")),
        }
        let mut command = Command::new(&self.executable);
        command
            .args(&self.arguments)
            .env("NODE_OPTIONS", options)
            .env("XTRACE_BOOTSTRAP_PATH", bootstrap)
            .env(
                "XTRACE_NODE_ORIGINAL_OPTIONS",
                self.original_options.as_deref().unwrap_or(OsStr::new("")),
            )
            .env(
                "XTRACE_NODE_OPTIONS_WAS_SET",
                if self.original_options.is_some() { "1" } else { "0" },
            );
        command.as_std_mut().process_group(0);
        command.kill_on_drop(true);
        let child = command.spawn().map_err(|_| LaunchError::Process)?;
        let Some(pid) = child.id() else {
            let mut child = child;
            if child.start_kill().is_err() {
                // Tokio's kill_on_drop guard remains enabled for the direct child.
            }
            return Err(LaunchError::Process);
        };
        Ok(NodeChild { child, process_group: pid as i32, reaped: false })
    }
}

/// A spawned Node process protected by its Unix process-group guard.
pub struct NodeChild {
    child: tokio::process::Child,
    process_group: i32,
    reaped: bool,
}
impl NodeChild {
    /// Waits for normal exit or forwards SIGINT/SIGTERM with bounded escalation.
    pub async fn wait(
        &mut self,
        signals: &mut NodeSignals,
    ) -> Result<std::process::ExitStatus, LaunchError> {
        use rustix::process::{Pid, Signal, kill_process_group};
        use tokio::time::{Duration, timeout};
        let result = tokio::select! { result = self.child.wait() => result.map_err(|_| LaunchError::Process), _ = signals.interrupt.recv() => self.forward_and_reap(Signal::INT).await, _ = signals.terminate.recv() => self.forward_and_reap(Signal::TERM).await };
        match result {
            Ok(status) => {
                self.reaped = true;
                if let Some(group) = Pid::from_raw(self.process_group) {
                    if kill_process_group(group, Signal::KILL)
                        .is_err_and(|error| error != rustix::io::Errno::SRCH)
                    {
                        return Err(LaunchError::Process);
                    }
                }
                Ok(status)
            }
            Err(_) => {
                if let Some(group) = Pid::from_raw(self.process_group) {
                    if kill_process_group(group, Signal::KILL)
                        .is_err_and(|error| error != rustix::io::Errno::SRCH)
                    {
                        // Direct-child kill below is the fallback when group signalling fails.
                    }
                }
                if self.child.start_kill().is_err() {
                    // The bounded wait below still reaps an already-exited child.
                }
                match timeout(Duration::from_secs(10), self.child.wait()).await {
                    Ok(Ok(_)) => {
                        self.reaped = true;
                        Err(LaunchError::Process)
                    }
                    _ => Err(LaunchError::Process),
                }
            }
        }
    }
    async fn forward_and_reap(
        &mut self,
        signal: rustix::process::Signal,
    ) -> Result<std::process::ExitStatus, LaunchError> {
        use rustix::process::{Pid, Signal, kill_process_group};
        use tokio::time::{Duration, timeout};
        let mut forwarding_failed = false;
        if let Some(group) = Pid::from_raw(self.process_group) {
            if kill_process_group(group, signal)
                .is_err_and(|error| error != rustix::io::Errno::SRCH)
            {
                forwarding_failed = self.child.start_kill().is_err();
            }
        }
        match timeout(Duration::from_secs(10), self.child.wait()).await {
            Ok(Ok(status)) => {
                self.reaped = true;
                let cleanup_failed = Pid::from_raw(self.process_group).is_some_and(|group| {
                    kill_process_group(group, Signal::KILL)
                        .is_err_and(|error| error != rustix::io::Errno::SRCH)
                });
                if forwarding_failed || cleanup_failed {
                    Err(LaunchError::Process)
                } else {
                    Ok(status)
                }
            }
            _ => {
                let cleanup_failed = Pid::from_raw(self.process_group).is_some_and(|group| {
                    kill_process_group(group, Signal::KILL)
                        .is_err_and(|error| error != rustix::io::Errno::SRCH)
                });
                let child_kill_failed = self.child.start_kill().is_err();
                let result = timeout(Duration::from_secs(10), self.child.wait())
                    .await
                    .map_err(|_| LaunchError::Process)?
                    .map_err(|_| LaunchError::Process)?;
                self.reaped = true;
                if cleanup_failed || child_kill_failed {
                    Err(LaunchError::Process)
                } else {
                    Ok(result)
                }
            }
        }
    }
}
impl Drop for NodeChild {
    fn drop(&mut self) {
        use rustix::process::{Pid, Signal, kill_process_group};
        if !self.reaped {
            if let Some(group) = Pid::from_raw(self.process_group) {
                match kill_process_group(group, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(_) => { /* Child::kill_on_drop remains the direct-child fallback. */ }
                }
            }
            if self.child.start_kill().is_err() {
                // Tokio's kill_on_drop guard remains enabled for the direct child.
            }
        }
    }
}

/// Installed SIGINT/SIGTERM streams for a supervised Node child.
pub struct NodeSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}
impl NodeSignals {
    /// Installs Unix termination handlers before project side effects begin.
    pub fn install() -> Result<Self, LaunchError> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(|_| LaunchError::Process)?,
            terminate: signal(SignalKind::terminate()).map_err(|_| LaunchError::Process)?,
        })
    }
}

fn validate_node_options_arguments(arguments: &[OsString]) -> Result<(), LaunchError> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let value = argument.to_string_lossy();
        if value == "--" {
            if arguments.get(index + 1).is_none() {
                return Err(node_script_required());
            }
            break;
        }
        if !value.starts_with('-') {
            break;
        }
        let option = value.split_once('=').map_or(value.as_ref(), |(name, _)| name);
        if is_preload_flag(option) {
            return Err(LaunchError::Validation(
                "Node preload and loader flags conflict with X-trace injection",
            ));
        }
        if matches!(option, "--env-file" | "--env-file-if-exists") {
            // Node parses NODE_OPTIONS from these files after argv validation.
            return Err(LaunchError::Validation(
                "Node env-file options are unsupported; pass validated environment values to xtrace run",
            ));
        }
        if matches!(option, "--watch" | "--watch-preserve-output") {
            // The direct-script supervisor has no tested restarted-child lifecycle.
            return Err(LaunchError::Validation(
                "Node watch flags are unsupported by xtrace run; launch the script directly",
            ));
        }
        if matches!(option, "-e" | "--eval" | "-p" | "--print") {
            return Err(LaunchError::Validation(
                "Node eval and print entrypoints are unsupported; use a script file",
            ));
        }
        let has_inline_value = value.contains('=');
        if node_option_takes_value(option) && !has_inline_value {
            if arguments.get(index + 1).is_none() {
                return Err(node_script_required());
            }
            index = index.saturating_add(1);
        } else if !node_option_takes_value(option)
            && !node_option_is_boolean(option)
            && option != "--"
        {
            return Err(LaunchError::Validation(
                "xtrace run supports a limited set of Node options; use a script file and put app arguments after its path",
            ));
        }
        index = index.saturating_add(1);
    }
    if index >= arguments.len() {
        return Err(node_script_required());
    }
    Ok(())
}
fn node_script_required() -> LaunchError {
    LaunchError::Validation("a Node script path is required after supported Node options")
}
fn node_option_takes_value(value: &str) -> bool {
    [
        "--conditions",
        "--cpu-prof-dir",
        "--diagnostic-dir",
        "--disable-warning",
        "--env-file",
        "--env-file-if-exists",
        "--experimental-policy",
        "--heapsnapshot-near-heap-limit",
        "--icu-data-dir",
        "--input-type",
        "--inspect-port",
        "--inspect-publish-uid",
        "--max-http-header-size",
        "--max-old-space-size",
        "--openssl-config",
        "--redirect-warnings",
        "--test-name-pattern",
        "--test-reporter",
        "--title",
        "--tls-cipher-list",
        "--trace-event-categories",
        "--trace-event-file-pattern",
        "--experimental-default-type",
        "--experimental-specifier-resolution",
        "--secure-heap",
        "--secure-heap-min",
        "--unhandled-rejections",
    ]
    .contains(&value)
}
fn node_option_is_boolean(value: &str) -> bool {
    [
        "--abort-on-uncaught-exception",
        "--completion-bash",
        "--enable-source-maps",
        "--experimental-network-inspection",
        "--experimental-strip-types",
        "--experimental-transform-types",
        "--force-fips",
        "--frozen-intrinsics",
        "--no-deprecation",
        "--no-experimental-fetch",
        "--no-warnings",
        "--preserve-symlinks",
        "--preserve-symlinks-main",
        "--report-compact",
        "--report-on-fatalerror",
        "--report-on-signal",
        "--report-uncaught-exception",
        "--throw-deprecation",
        "--trace-deprecation",
        "--trace-uncaught",
        "--trace-warnings",
        "--track-heap-objects",
        "--zero-fill-buffers",
        "--watch",
        "--watch-preserve-output",
        "--no-addons",
        "--experimental-wasm-modules",
        "--experimental-vm-modules",
    ]
    .contains(&value)
}
fn is_preload_flag(value: &str) -> bool {
    value == "-r"
        || value.starts_with("-r") && value != "-"
        || ["--require", "--import", "--loader", "--experimental-loader"]
            .iter()
            .any(|flag| value == *flag || value.starts_with(&format!("{flag}=")))
}
fn validate_node_options(options: &str) -> Result<(), LaunchError> {
    let tokens = parse_node_options(options)?;
    if tokens.iter().any(|token| is_preload_flag(token)) {
        return Err(LaunchError::Validation(
            "NODE_OPTIONS preload and loader flags conflict with X-trace injection",
        ));
    }
    Ok(())
}
fn parse_node_options(options: &str) -> Result<Vec<String>, LaunchError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut active = false;
    for character in options.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            active = true;
            continue;
        }
        match character {
            '\\' => {
                escaped = true;
                active = true;
            }
            '"' => {
                quoted = !quoted;
                active = true;
            }
            c if c.is_whitespace() && !quoted => {
                if active {
                    tokens.push(std::mem::take(&mut current));
                    active = false;
                }
            }
            c => {
                current.push(c);
                active = true;
            }
        }
    }
    if escaped || quoted {
        return Err(LaunchError::Validation("NODE_OPTIONS quoting is malformed"));
    }
    if active {
        tokens.push(current);
    }
    Ok(tokens)
}
fn quote_node_option(path: &Path) -> Result<String, LaunchError> {
    let value =
        path.to_str().ok_or(LaunchError::Validation("Node adapter paths must be valid UTF-8"))?;
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}
fn file_url(path: &Path) -> Result<String, LaunchError> {
    let value =
        path.to_str().ok_or(LaunchError::Validation("Node adapter paths must be valid UTF-8"))?;
    let mut encoded = String::from("file://");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~' | b':') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(encoded)
}
fn resolve_executable(program: &Path, path: Option<&OsStr>) -> Result<PathBuf, LaunchError> {
    use std::path::Component;
    if program.components().any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        || program.components().count() > 1
    {
        return program
            .canonicalize()
            .map_err(|_| LaunchError::Validation("the Node launcher is unavailable"));
    }
    let path = path.ok_or(LaunchError::Validation("PATH does not contain a Node launcher"))?;
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        if std::fs::metadata(&candidate).is_ok_and(|m| m.is_file()) {
            return candidate
                .canonicalize()
                .map_err(|_| LaunchError::Validation("the Node launcher path is invalid"));
        }
    }
    Err(LaunchError::Validation("PATH does not contain a Node launcher"))
}
fn verify_node_version(executable: &Path) -> Result<(), LaunchError> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut file = std::fs::File::open(executable)
        .map_err(|_| LaunchError::Validation("the Node launcher is unavailable"))?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic)
        .map_err(|_| LaunchError::Validation("the Node launcher is not a native executable"))?;
    let native = magic == *b"\x7fELF"
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        );
    if !native {
        return Err(LaunchError::Validation("the Node launcher is not a native executable"));
    }
    let mut probe = Command::new(executable);
    probe.arg("--version").env_remove("NODE_OPTIONS");
    for name in
        ["XTRACE_BOOTSTRAP_PATH", "XTRACE_NODE_ORIGINAL_OPTIONS", "XTRACE_NODE_OPTIONS_WAS_SET"]
    {
        probe.env_remove(name);
    }
    probe.stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let mut child = probe
        .spawn()
        .map_err(|_| LaunchError::Validation("the selected executable is not Node.js"))?;
    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        terminate_probe(&mut child, pid)?;
        return Err(LaunchError::Process);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_probe(&mut child, pid)?;
        return Err(LaunchError::Process);
    };
    let stdout_flags = fcntl_getfl(&stdout).map_err(|_| LaunchError::Process);
    let stderr_flags = fcntl_getfl(&stderr).map_err(|_| LaunchError::Process);
    if let (Ok(stdout_flags), Ok(stderr_flags)) = (stdout_flags, stderr_flags) {
        let nonblocking = fcntl_setfl(&stdout, stdout_flags | OFlags::NONBLOCK)
            .and_then(|()| fcntl_setfl(&stderr, stderr_flags | OFlags::NONBLOCK));
        if nonblocking.is_err() {
            terminate_probe(&mut child, pid)?;
            return Err(LaunchError::Process);
        }
    } else {
        terminate_probe(&mut child, pid)?;
        return Err(LaunchError::Process);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stdout_output = ProbeOutput::default();
    let mut stderr_output = ProbeOutput::default();
    let status = loop {
        if let Err(error) = drain_probe_pipes(
            &stdout,
            &stderr,
            &mut stdout_output,
            &mut stderr_output,
            Duration::from_millis(10),
        ) {
            terminate_probe(&mut child, pid)?;
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {}
            Ok(None) | Err(_) => {
                terminate_probe(&mut child, pid)?;
                return Err(LaunchError::Validation(
                    "the Node version probe exceeded its time limit",
                ));
            }
        }
    };
    let drain_deadline = Instant::now() + Duration::from_secs(1);
    while !stdout_output.closed || !stderr_output.closed {
        if Instant::now() >= drain_deadline {
            terminate_probe(&mut child, pid)?;
            return Err(LaunchError::Validation(
                "the Node version probe output did not close within its time limit",
            ));
        }
        if drain_probe_pipes(
            &stdout,
            &stderr,
            &mut stdout_output,
            &mut stderr_output,
            Duration::from_millis(10),
        )
        .is_err()
        {
            terminate_probe(&mut child, pid)?;
            return Err(LaunchError::Process);
        }
    }
    if stdout_output.exceeded || stderr_output.exceeded {
        terminate_probe(&mut child, pid)?;
        return Err(LaunchError::Validation(
            "the Node version probe output exceeded its size limit",
        ));
    }
    let version = [stdout_output.bytes, stderr_output.bytes].concat();
    let version = String::from_utf8_lossy(&version);
    let major = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    if !status.success() || !matches!(major, Some(22 | 24)) {
        return Err(LaunchError::Validation("xtrace run supports native Node.js 22 and 24 only"));
    }
    Ok(())
}

#[derive(Default)]
struct ProbeOutput {
    bytes: Vec<u8>,
    closed: bool,
    exceeded: bool,
}

fn drain_probe_pipes(
    stdout: &std::process::ChildStdout,
    stderr: &std::process::ChildStderr,
    stdout_output: &mut ProbeOutput,
    stderr_output: &mut ProbeOutput,
    timeout: std::time::Duration,
) -> Result<(), LaunchError> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let timeout_duration = timeout;
    let timeout =
        Timespec { tv_sec: 0, tv_nsec: timeout_duration.as_nanos().min(999_999_999) as i64 };
    let mut fds = Vec::with_capacity(2);
    let mut streams = Vec::with_capacity(2);
    if !stdout_output.closed {
        fds.push(PollFd::new(stdout, PollFlags::IN | PollFlags::HUP | PollFlags::ERR));
        streams.push(true);
    }
    if !stderr_output.closed {
        fds.push(PollFd::new(stderr, PollFlags::IN | PollFlags::HUP | PollFlags::ERR));
        streams.push(false);
    }
    if fds.is_empty() {
        std::thread::sleep(timeout_duration);
        return Ok(());
    }
    poll(&mut fds, Some(&timeout)).map_err(|_| LaunchError::Process)?;
    for (fd, is_stdout) in fds.iter().zip(streams) {
        if !fd.revents().intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            continue;
        }
        let output = if is_stdout { &mut *stdout_output } else { &mut *stderr_output };
        let mut buffer = [0; 1_024];
        let mut remaining = 4;
        while remaining > 0 {
            remaining -= 1;
            let read = if is_stdout {
                rustix::io::read(stdout, &mut buffer)
            } else {
                rustix::io::read(stderr, &mut buffer)
            };
            match read {
                Ok(0) => {
                    output.closed = true;
                    break;
                }
                Ok(count) => {
                    let available = 4_096usize.saturating_sub(output.bytes.len());
                    let retained = count.min(available);
                    output.bytes.extend_from_slice(&buffer[..retained]);
                    output.exceeded |= retained < count;
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(_) => return Err(LaunchError::Process),
            }
        }
    }
    Ok(())
}

fn terminate_probe(child: &mut std::process::Child, pid: u32) -> Result<(), LaunchError> {
    use rustix::process::{Pid, Signal, kill_process_group};
    use std::thread;
    use std::time::{Duration, Instant};
    let group_cleanup_failed = Pid::from_raw(pid as i32).is_some_and(|group| {
        kill_process_group(group, Signal::KILL).is_err_and(|error| error != rustix::io::Errno::SRCH)
    });
    match child.kill() {
        Ok(()) => {}
        Err(_) => { /* The bounded wait below distinguishes an exit race from a surviving child. */
        }
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let reaped = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => break false,
        }
    };
    // An already-exited child can make `kill` report an error; that is safe
    // only when the bounded reap confirms its exit. Group cleanup failures
    // and an unreaped child become sanitized process failures.
    if group_cleanup_failed || !reaped { Err(LaunchError::Process) } else { Ok(()) }
}

fn validate_distribution(root: &Path) -> Result<(), LaunchError> {
    use std::collections::{BTreeMap, BTreeSet};
    let owner = rustix::process::getuid().as_raw();
    let root_meta = owned_directory(root, owner)?;
    let manifest = root.join("manifest.sha256");
    let manifest_meta = owned_file(&manifest, owner)?;
    if manifest_meta.size > 1_048_576 {
        return Err(LaunchError::Validation("the Node adapter manifest exceeds its size limit"));
    }
    let before = std::fs::read_to_string(&manifest)
        .map_err(|_| LaunchError::Validation("the Node adapter manifest cannot be read"))?;
    let mut declared = BTreeMap::new();
    for line in before.lines() {
        let (digest, relative) = line
            .split_once("  ")
            .ok_or(LaunchError::Validation("the Node adapter manifest is malformed"))?;
        if digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || relative.is_empty()
            || relative.starts_with('/')
            || relative.split('/').any(|p| p.is_empty() || p == "." || p == "..")
            || declared.insert(relative.to_string(), digest.to_string()).is_some()
        {
            return Err(LaunchError::Validation("the Node adapter manifest is malformed"));
        }
    }
    let mut actual = BTreeSet::new();
    collect_files(root, root, owner, &mut actual)?;
    if declared.len() != actual.len()
        || declared.keys().any(|name| !actual.contains(name))
        || !declared.contains_key("register.cjs")
        || !declared.contains_key("register.mjs")
        || !declared.contains_key("node-http-manifest.json")
    {
        return Err(LaunchError::Validation("the Node adapter manifest membership does not match"));
    }
    for (relative, digest) in declared {
        let path = root.join(&relative);
        let metadata = owned_file(&path, owner)?;
        let actual = sha256(&path, metadata)?;
        if actual != digest {
            return Err(LaunchError::Validation(
                "the Node adapter distribution digest does not match",
            ));
        }
    }
    let after_meta = owned_file(&manifest, owner)?;
    let after = std::fs::read_to_string(&manifest)
        .map_err(|_| LaunchError::Validation("the Node adapter manifest cannot be read"))?;
    if manifest_meta != after_meta
        || before != after
        || root_meta
            != FileStamp::of(&std::fs::symlink_metadata(root).map_err(|_| {
                LaunchError::Validation("the Node adapter distribution changed during validation")
            })?)
    {
        return Err(LaunchError::Validation(
            "the Node adapter distribution changed during validation",
        ));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    nlink: u64,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl FileStamp {
    fn of(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            nlink: m.nlink(),
            mode: m.mode(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
fn owned_directory(path: &Path, owner: u32) -> Result<FileStamp, LaunchError> {
    let m = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchError::Validation("the Node adapter directory is unavailable"))?;
    let s = FileStamp::of(&m);
    if m.file_type().is_symlink() || !m.is_dir() || s.uid != owner || s.mode & 0o022 != 0 {
        return Err(LaunchError::Validation(
            "Node adapter directories must be owned and not group/other writable",
        ));
    }
    Ok(s)
}
fn owned_file(path: &Path, owner: u32) -> Result<FileStamp, LaunchError> {
    let m = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchError::Validation("a Node adapter file is unavailable"))?;
    let s = FileStamp::of(&m);
    if m.file_type().is_symlink()
        || !m.is_file()
        || s.uid != owner
        || s.nlink != 1
        || s.mode & 0o022 != 0
    {
        return Err(LaunchError::Validation(
            "Node adapter files must be owned, unlinked, and not group/other writable",
        ));
    }
    Ok(s)
}
fn collect_files(
    root: &Path,
    dir: &Path,
    owner: u32,
    files: &mut std::collections::BTreeSet<String>,
) -> Result<(), LaunchError> {
    for item in std::fs::read_dir(dir)
        .map_err(|_| LaunchError::Validation("the Node adapter directory cannot be read"))?
    {
        let item =
            item.map_err(|_| LaunchError::Validation("the Node adapter directory is invalid"))?;
        let path = item.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| LaunchError::Validation("a Node adapter entry is unavailable"))?;
        if meta.file_type().is_symlink() {
            return Err(LaunchError::Validation(
                "Node adapter distributions cannot contain symlinks",
            ));
        }
        if meta.is_dir() {
            owned_directory(&path, owner)?;
            collect_files(root, &path, owner, files)?;
        } else {
            owned_file(&path, owner)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| LaunchError::Validation("the Node adapter path is invalid"))?
                .to_str()
                .ok_or(LaunchError::Validation("Node adapter paths must be valid UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative != "manifest.sha256" && !files.insert(relative) {
                return Err(LaunchError::Validation(
                    "the Node adapter distribution contains duplicate files",
                ));
            }
        }
    }
    Ok(())
}
fn sha256(path: &Path, expected: FileStamp) -> Result<String, LaunchError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)
        .map_err(|_| LaunchError::Validation("a Node adapter file cannot be read"))?;
    if FileStamp::of(
        &f.metadata().map_err(|_| LaunchError::Validation("a Node adapter file cannot be read"))?,
    ) != expected
    {
        return Err(LaunchError::Validation(
            "the Node adapter distribution changed during validation",
        ));
    }
    let mut h = Sha256::new();
    let mut b = [0; 32768];
    loop {
        let n = f
            .read(&mut b)
            .map_err(|_| LaunchError::Validation("a Node adapter file cannot be read"))?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    if FileStamp::of(&std::fs::symlink_metadata(path).map_err(|_| {
        LaunchError::Validation("the Node adapter distribution changed during validation")
    })?) != expected
    {
        return Err(LaunchError::Validation(
            "the Node adapter distribution changed during validation",
        ));
    }
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "runtime tests use fixed launch inputs")]
mod tests {
    use super::*;

    #[test]
    fn module_mode_is_explicit_and_closed() {
        assert_eq!(NodeMode::parse("cjs").unwrap(), NodeMode::CommonJs);
        assert_eq!(NodeMode::parse("esm").unwrap(), NodeMode::EsModule);
        assert_eq!(NodeMode::parse("guess").unwrap_err().code(), "XTR-NODE-INVALID-LAUNCH");
    }

    #[test]
    fn node_options_reject_preexisting_capture_and_loader_hooks() {
        for value in [
            "--require /tmp/loader.cjs",
            "--require=/tmp/loader.cjs",
            "-r/tmp/loader.cjs",
            "--import=file:///tmp/loader.mjs",
            "--loader=custom",
        ] {
            assert!(validate_node_options(value).is_err(), "{value}");
        }
        assert!(validate_node_options("--trace-warnings --max-old-space-size=4096").is_ok());
        assert!(validate_node_options("--trace-warnings \"unterminated").is_err());
    }

    #[test]
    fn user_preload_flags_stop_at_script_boundary_and_eval_entrypoints_are_rejected() {
        assert!(
            validate_node_options_arguments(&["--require=other.cjs".into(), "app.cjs".into()])
                .is_err()
        );
        assert!(
            validate_node_options_arguments(&["--".into(), "--require=ordinary-app-arg".into()])
                .is_ok()
        );
        assert!(
            validate_node_options_arguments(&[
                "app.cjs".into(),
                "--require=ordinary-app-arg".into()
            ])
            .is_ok()
        );
        assert!(
            validate_node_options_arguments(&[
                "--max-old-space-size".into(),
                "4096".into(),
                "app.cjs".into(),
                "--import=ordinary-app-arg".into()
            ])
            .is_ok()
        );
        assert!(
            validate_node_options_arguments(&[
                "--icu-data-dir".into(),
                "/tmp/icu-data".into(),
                "--require=/xtrace-nonexistent-preload.cjs".into(),
                "app.cjs".into()
            ])
            .is_err()
        );
        assert!(
            validate_node_options_arguments(&["--future-unknown-option".into(), "app.cjs".into()])
                .is_err()
        );
        assert!(validate_node_options_arguments(&["--future-unknown-option".into()]).is_err());
        assert!(
            validate_node_options_arguments(&[
                "--eval".into(),
                "console.log(JSON.stringify(process.execArgv))".into(),
                "--require=/xtrace-nonexistent-preload.cjs".into()
            ])
            .is_err()
        );
        assert!(validate_node_options_arguments(&["--eval=1".into()]).is_err());
        assert!(validate_node_options_arguments(&["-p".into(), "1 + 1".into()]).is_err());
        assert!(validate_node_options_arguments(&["--".into()]).is_err());
    }

    #[test]
    fn node_env_files_are_rejected_before_script_but_preserved_as_script_arguments() {
        for arguments in [
            vec!["--env-file".into(), "/tmp/app.env".into(), "app.cjs".into()],
            vec!["--env-file-if-exists".into(), "/tmp/app.env".into(), "app.cjs".into()],
            vec!["--env-file=/tmp/app.env".into(), "app.cjs".into()],
            vec!["--env-file-if-exists=/tmp/app.env".into(), "app.cjs".into()],
        ] {
            assert_eq!(
                validate_node_options_arguments(&arguments).unwrap_err().to_string(),
                "Node env-file options are unsupported; pass validated environment values to xtrace run",
            );
        }
        assert!(
            validate_node_options_arguments(&[
                "app.cjs".into(),
                "--env-file=/ordinary-app-argument".into(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn node_watch_flags_are_rejected_before_script_but_preserved_as_script_arguments() {
        for arguments in [
            vec!["--watch".into(), "app.cjs".into()],
            vec!["--watch-preserve-output".into(), "app.cjs".into()],
            vec!["--watch=true".into(), "app.cjs".into()],
            vec!["--watch-preserve-output=true".into(), "app.cjs".into()],
        ] {
            assert_eq!(
                validate_node_options_arguments(&arguments).unwrap_err().to_string(),
                "Node watch flags are unsupported by xtrace run; launch the script directly",
            );
        }
        assert!(
            validate_node_options_arguments(&[
                "app.cjs".into(),
                "--watch-preserve-output=ordinary-app-argument".into(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn native_version_probe_accepts_bounded_node_version_output() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let helper = compile_native_probe(directory.path(), None);
        verify_node_version(&helper).expect("native Node version probe");
    }

    #[test]
    fn native_version_probe_bounds_pipe_drain_when_detached_descendant_holds_pipes() {
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().expect("fixture directory");
        let pid_file = directory.path().join("detached-descendant.pid");
        let helper = compile_native_probe(directory.path(), Some(&pid_file));
        let started = Instant::now();
        let result = verify_node_version(&helper);
        let exceeded_time_limit = matches!(
            result,
            Err(LaunchError::Validation(
                "the Node version probe output did not close within its time limit"
            ))
        );
        let descendant = std::fs::read_to_string(pid_file)
            .expect("helper recorded detached descendant")
            .trim()
            .parse::<i32>()
            .expect("detached descendant PID");
        let cleanup = ProbeFixtureCleanup(descendant);
        let cleanup_result = cleanup.terminate();
        assert!(
            exceeded_time_limit,
            "a detached inherited pipe must fail with a fixed bounded diagnostic"
        );
        assert!(cleanup_result, "could not clean detached probe fixture");
        assert!(started.elapsed() < Duration::from_secs(3), "version probe exceeded its bound");
    }

    struct ProbeFixtureCleanup(i32);

    impl ProbeFixtureCleanup {
        fn terminate(&self) -> bool {
            use rustix::process::{Pid, Signal, kill_process_group};
            Pid::from_raw(self.0).is_none_or(|group| {
                matches!(
                    kill_process_group(group, Signal::KILL),
                    Ok(()) | Err(rustix::io::Errno::SRCH)
                )
            })
        }
    }

    impl Drop for ProbeFixtureCleanup {
        fn drop(&mut self) {
            let _cleanup_succeeded = self.terminate();
        }
    }

    fn compile_native_probe(
        directory: &std::path::Path,
        descendant_pid_file: Option<&std::path::Path>,
    ) -> std::path::PathBuf {
        use std::process::Command;

        let source = match descendant_pid_file {
            Some(pid_file) => format!(
                r#"use std::os::unix::process::CommandExt as _;
fn main() {{
    let mut descendant = std::process::Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .expect("spawn detached pipe holder");
    std::fs::write({:?}, descendant.id().to_string()).expect("write fixture PID");
    drop(descendant);
    println!("v24.21.0");
}}
"#,
                pid_file.to_string_lossy()
            ),
            None => "fn main() { println!(\"v24.21.0\"); }\n".to_owned(),
        };
        let source_path = directory.join("node_probe.rs");
        let binary_path = directory.join("node");
        std::fs::write(&source_path, source).expect("write native Node fixture source");
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let output = Command::new(compiler)
            .arg("--edition=2024")
            .arg("--crate-name=xtrace_node_probe")
            .arg(&source_path)
            .arg("-o")
            .arg(&binary_path)
            .output()
            .expect("compile native Node fixture");
        assert!(output.status.success(), "native fixture compilation failed");
        binary_path
    }

    #[test]
    fn preload_paths_are_quoted_or_percent_encoded_for_node_options() {
        assert_eq!(
            quote_node_option(Path::new("/adapter with space/register.cjs")).unwrap(),
            "\"/adapter with space/register.cjs\""
        );
        assert_eq!(
            file_url(Path::new("/adapter with space/register #1.mjs")).unwrap(),
            "file:///adapter%20with%20space/register%20%231.mjs"
        );
    }

    #[tokio::test]
    async fn termination_reaps_the_direct_process_and_its_group() {
        use std::os::unix::process::CommandExt as _;
        use std::os::unix::process::ExitStatusExt as _;
        use std::time::{Duration, Instant};
        use tokio::process::Command;

        let directory = tempfile::tempdir().expect("temporary process directory");
        let pid_path = directory.path().join("helper.pid");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", "node::tests::group_leader_fixture", "--nocapture"])
            .env("XTRACE_NODE_TEST_GROUP_FIXTURE", "1")
            .env("XTRACE_NODE_TEST_GROUP_PIDFILE", &pid_path);
        command.as_std_mut().process_group(0);
        command.kill_on_drop(true);
        let child = command.spawn().expect("spawn process-group fixture");
        let leader = child.id().expect("fixture leader PID");
        let deadline = Instant::now() + Duration::from_secs(2);
        let helper = loop {
            if let Ok(value) = std::fs::read_to_string(&pid_path) {
                if let Ok(pid) = value.trim().parse::<i32>() {
                    break pid;
                }
            }
            assert!(Instant::now() < deadline, "helper PID was not written");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let mut supervised = NodeChild { child, process_group: leader as i32, reaped: false };
        let status = supervised
            .forward_and_reap(rustix::process::Signal::TERM)
            .await
            .expect("forward and reap");
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::TERM.as_raw()),
            "termination preserved signal exit status"
        );
        let helper_pid = rustix::process::Pid::from_raw(helper).expect("helper PID");
        let gone_by = Instant::now() + Duration::from_secs(2);
        loop {
            let exists = !matches!(
                rustix::process::kill_process(helper_pid, rustix::process::Signal::CONT),
                Err(rustix::io::Errno::SRCH)
            );
            assert!(
                !exists || Instant::now() < gone_by,
                "process-group helper survived supervised termination"
            );
            if !exists {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn group_leader_fixture() {
        if std::env::var_os("XTRACE_NODE_TEST_GROUP_FIXTURE").is_none() {
            return;
        }
        let pid_path = std::env::var_os("XTRACE_NODE_TEST_GROUP_PIDFILE").expect("test PID path");
        let mut helper =
            std::process::Command::new("sleep").arg("30").spawn().expect("spawn helper child");
        std::fs::write(pid_path, helper.id().to_string()).expect("write helper PID");
        let _status = helper.wait().expect("wait helper child");
    }
}
