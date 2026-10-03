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
            break;
        }
        if !value.starts_with('-') || value == "-" {
            break;
        }
        if is_preload_flag(&value) {
            return Err(LaunchError::Validation(
                "Node preload and loader flags conflict with X-trace injection",
            ));
        }
        if matches!(value.as_ref(), "-e" | "--eval" | "-p" | "--print")
            || ["--eval=", "--print="].iter().any(|flag| value.starts_with(flag))
        {
            return Err(LaunchError::Validation(
                "Node eval and print entrypoints are unsupported; use a script file",
            ));
        }
        if node_option_takes_value(&value) && !value.contains('=') {
            index = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    Ok(())
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
        "--unhandled-rejections",
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
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
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
    let (output_sender, output_receiver) = mpsc::sync_channel(2);
    let stdout_sender = output_sender.clone();
    thread::spawn(move || {
        let output = read_probe_output(stdout);
        if stdout_sender.send((true, output)).is_err() {
            // The caller already exhausted the fixed pipe-drain budget.
        }
    });
    thread::spawn(move || {
        let output = read_probe_output(stderr);
        if output_sender.send((false, output)).is_err() {
            // The caller already exhausted the fixed pipe-drain budget.
        }
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                terminate_probe(&mut child, pid)?;
                return Err(LaunchError::Validation(
                    "the Node version probe exceeded its time limit",
                ));
            }
        }
    };
    let drain_deadline = Instant::now() + Duration::from_secs(1);
    let mut stdout = None;
    let mut stderr = None;
    while stdout.is_none() || stderr.is_none() {
        let remaining = drain_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match output_receiver.recv_timeout(remaining) {
            Ok((true, output)) => stdout = Some(output),
            Ok((false, output)) => stderr = Some(output),
            Err(_) => break,
        }
    }
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        terminate_probe(&mut child, pid)?;
        return Err(LaunchError::Validation(
            "the Node version probe output did not close within its time limit",
        ));
    };
    let version = [stdout.as_slice(), stderr.as_slice()].concat();
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

fn read_probe_output(mut reader: impl std::io::Read) -> Vec<u8> {
    const MAX_PROBE_OUTPUT: usize = 4_096;
    let mut retained = Vec::new();
    let mut buffer = [0; 1_024];
    while retained.len() < MAX_PROBE_OUTPUT {
        let available = MAX_PROBE_OUTPUT - retained.len();
        let read_size = available.min(buffer.len());
        match reader.read(&mut buffer[..read_size]) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                retained.extend_from_slice(&buffer[..count]);
            }
        }
    }
    retained
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
                "--eval".into(),
                "console.log(JSON.stringify(process.execArgv))".into(),
                "--require=/xtrace-nonexistent-preload.cjs".into()
            ])
            .is_err()
        );
        assert!(validate_node_options_arguments(&["--eval=1".into()]).is_err());
        assert!(validate_node_options_arguments(&["-p".into(), "1 + 1".into()]).is_err());
    }

    #[test]
    fn native_version_probe_accepts_bounded_node_version_output() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let helper = compile_native_probe(directory.path(), None);
        verify_node_version(&helper).expect("native Node version probe");
    }

    #[test]
    fn native_version_probe_bounds_pipe_drain_when_detached_descendant_holds_pipes() {
        use rustix::process::{Pid, Signal, kill_process_group};
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().expect("fixture directory");
        let pid_file = directory.path().join("detached-descendant.pid");
        let helper = compile_native_probe(directory.path(), Some(&pid_file));
        let started = Instant::now();
        let result = verify_node_version(&helper);
        assert!(
            matches!(
                result,
                Err(LaunchError::Validation(
                    "the Node version probe output did not close within its time limit"
                ))
            ),
            "a detached inherited pipe must fail with a fixed bounded diagnostic"
        );
        assert!(started.elapsed() < Duration::from_secs(3), "version probe exceeded its bound");

        let descendant = std::fs::read_to_string(pid_file)
            .expect("helper recorded detached descendant")
            .trim()
            .parse::<i32>()
            .expect("detached descendant PID");
        if let Some(group) = Pid::from_raw(descendant) {
            match kill_process_group(group, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(_) => panic!("could not clean detached probe fixture"),
            }
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
            match rustix::process::kill_process(helper_pid, rustix::process::Signal::CONT) {
                Err(rustix::io::Errno::SRCH) => break,
                Ok(()) if Instant::now() < gone_by => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                _ => panic!("process-group helper survived supervised termination"),
            }
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
