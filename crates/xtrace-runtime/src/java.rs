//! Validated direct-JDK launch and Unix process-group supervision.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Stable failure categories for direct Java launch and supervision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchErrorKind {
    /// User input or a selected launcher/agent artifact is invalid.
    Validation,
    /// The host cannot provide the requested runtime operation.
    Unsupported,
    /// A process could not be started, signalled, waited for, or reaped.
    Process,
}

/// A sanitized Java launch or process-supervision failure.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// Launch input failed a pre-side-effect validation.
    #[error("{0}")]
    Validation(&'static str),
    /// The requested launch operation is unavailable on this platform.
    #[error("direct Java supervision is unsupported on this platform")]
    Unsupported,
    /// Process creation or signal registration failed.
    #[error("could not start or supervise the Java launcher")]
    Process,
}

impl LaunchError {
    /// Returns the stable machine-readable code for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "XTR-RUN-INVALID-LAUNCH",
            Self::Unsupported => "XTR-RUN-UNSUPPORTED",
            Self::Process => "XTR-RUN-PROCESS",
        }
    }

    /// Returns the stable coarse category for this error.
    #[must_use]
    pub const fn kind(&self) -> LaunchErrorKind {
        match self {
            Self::Validation(_) => LaunchErrorKind::Validation,
            Self::Unsupported => LaunchErrorKind::Unsupported,
            Self::Process => LaunchErrorKind::Process,
        }
    }

    /// Returns the stable CLI status associated with this error category.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.kind() {
            LaunchErrorKind::Validation => 2,
            LaunchErrorKind::Unsupported => 6,
            LaunchErrorKind::Process => 9,
        }
    }
}

/// A validated direct Java launch and its original application arguments.
#[derive(Clone, Debug)]
pub struct JavaLaunch {
    executable: PathBuf,
    agent: PathBuf,
    arguments: Vec<OsString>,
}

impl JavaLaunch {
    /// Validates a direct `java` command, JDK identity, agent JAR, and runtime sibling.
    ///
    /// Every validation is completed before callers create project or daemon
    /// side effects. Arguments remain native OS strings and are never shell parsed.
    ///
    /// # Errors
    ///
    /// Returns a sanitized validation error when the launch is ambiguous,
    /// unsupported, or its selected artifacts are invalid.
    pub fn validate(agent: &Path, command: &[OsString]) -> Result<Self, LaunchError> {
        Self::validate_with_path(agent, command, std::env::var_os("PATH").as_deref())
    }

    /// Validates a direct `java` command using an explicit search path.
    ///
    /// This variant makes PATH resolution deterministic for tests and callers
    /// that already own a process environment snapshot.
    pub fn validate_with_path(
        agent: &Path,
        command: &[OsString],
        path: Option<&OsStr>,
    ) -> Result<Self, LaunchError> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let (program, arguments) = command
            .split_first()
            .ok_or(LaunchError::Validation("a direct java executable is required after --"))?;
        let program_path = Path::new(program);
        if program_path.file_name().is_none_or(|name| name != "java") {
            return Err(LaunchError::Validation(
                "xtrace run accepts only a direct executable named java; build-tool and wrapper launches \
                 (gradle bootRun, mvn spring-boot:run, gradlew, scripts) are refused: run the built \
                 application with java -jar",
            ));
        }
        if arguments.iter().any(|argument| {
            argument == "-javaagent" || argument.to_string_lossy().starts_with("-javaagent:")
        }) {
            return Err(LaunchError::Validation("provide the X-trace agent with --java-agent"));
        }
        if arguments.iter().any(|argument| argument.as_os_str().as_bytes().starts_with(b"@")) {
            return Err(LaunchError::Validation(
                "Java @argfiles are unsupported because they can hide JVM options",
            ));
        }

        let executable = resolve_executable(program_path, path)?;
        let metadata = std::fs::metadata(&executable)
            .map_err(|_| LaunchError::Validation("the Java launcher is unavailable"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(LaunchError::Validation(
                "the Java launcher is not an executable regular file",
            ));
        }
        if command.iter().any(|argument| argument.as_os_str().as_bytes().contains(&0)) {
            return Err(LaunchError::Validation("Java launch arguments cannot contain NUL bytes"));
        }
        verify_native_jdk(&executable)?;

        let agent_metadata = std::fs::symlink_metadata(agent)
            .map_err(|_| LaunchError::Validation("the Java agent JAR is unavailable"))?;
        if agent_metadata.file_type().is_symlink() || !agent_metadata.is_file() {
            return Err(LaunchError::Validation("the Java agent must be a regular JAR file"));
        }
        let agent = agent
            .canonicalize()
            .map_err(|_| LaunchError::Validation("the Java agent path is invalid"))?;
        if agent.as_os_str().as_bytes().contains(&b'=') {
            return Err(LaunchError::Validation(
                "the canonical Java agent path cannot contain '='",
            ));
        }
        validate_distribution(&agent)?;

        Ok(Self { executable, agent, arguments: arguments.to_vec() })
    }

    /// Returns the canonical, preflighted Java executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Builds the one supported agent injection argument.
    ///
    /// The bootstrap path is intentionally returned only as an OS argument;
    /// callers must never place it in environment variables or diagnostics.
    #[must_use]
    pub fn agent_argument(&self, bootstrap: &Path) -> OsString {
        let mut argument = OsString::from("-javaagent:");
        argument.push(self.agent.as_os_str());
        argument.push("=");
        argument.push(bootstrap.as_os_str());
        argument
    }

    /// Spawns the direct Java process in its own Unix process group.
    ///
    /// # Errors
    ///
    /// Returns a sanitized process error; the underlying OS diagnostic is not
    /// included because it may contain user-controlled paths or arguments.
    pub fn spawn(&self, bootstrap: &Path) -> Result<JavaChild, LaunchError> {
        use std::os::unix::process::CommandExt as _;
        use tokio::process::Command;

        let mut command = Command::new(&self.executable);
        command.arg(self.agent_argument(bootstrap)).args(&self.arguments);
        clear_jvm_option_environment(&mut command);
        command.as_std_mut().process_group(0);
        command.kill_on_drop(true);
        let child = command.spawn().map_err(|_| LaunchError::Process)?;
        let Some(pid) = child.id() else {
            let mut child = child;
            let _ = child.start_kill();
            return Err(LaunchError::Process);
        };
        // Unix pid_t is a signed 32-bit value and the kernel never returns a
        // process identifier outside that range through Child::id().
        let process_group = pid as i32;
        Ok(JavaChild { child, process_group, reaped: false })
    }
}

/// A spawned Java child protected by a process-group kill-on-drop guard.
pub struct JavaChild {
    child: tokio::process::Child,
    process_group: i32,
    reaped: bool,
}

impl JavaChild {
    /// Waits for normal exit or forwards SIGINT/SIGTERM with bounded escalation.
    ///
    /// If waiting itself fails, the process group is killed and the direct
    /// child is still reaped before the sanitized process error is returned.
    pub async fn wait(
        &mut self,
        signals: &mut JavaSignals,
    ) -> Result<std::process::ExitStatus, LaunchError> {
        use rustix::process::{Pid, Signal, kill_process_group};
        use tokio::time::{Duration, timeout};

        let wait_result = tokio::select! {
            result = self.child.wait() => result.map_err(|_| LaunchError::Process),
            _ = signals.interrupt.recv() => self.forward_and_reap(Signal::INT).await,
            _ = signals.terminate.recv() => self.forward_and_reap(Signal::TERM).await,
        };
        match wait_result {
            Ok(status) => {
                self.reaped = true;
                // The group is owned by this launch. A leader may exit while
                // same-group helpers remain, so reap the leader then remove
                // any residue on every exit path.
                if let Some(group) = Pid::from_raw(self.process_group) {
                    let _ = kill_process_group(group, Signal::KILL);
                }
                Ok(status)
            }
            Err(error) => {
                if let Some(group) = Pid::from_raw(self.process_group) {
                    let _ = kill_process_group(group, Signal::KILL);
                }
                let _ = self.child.start_kill();
                match timeout(Duration::from_secs(10), self.child.wait()).await {
                    Ok(Ok(_)) => {
                        self.reaped = true;
                        Err(error)
                    }
                    Ok(Err(_)) | Err(_) => Err(LaunchError::Process),
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

        if let Some(group) = Pid::from_raw(self.process_group) {
            if kill_process_group(group, signal).is_err() {
                let _ = self.child.start_kill();
            }
        }
        match timeout(Duration::from_secs(10), self.child.wait()).await {
            Ok(Ok(status)) => {
                self.reaped = true;
                // The direct launcher can exit before a same-group helper that
                // ignored the forwarded signal. Remove any such owned residue.
                if let Some(group) = Pid::from_raw(self.process_group) {
                    let _ = kill_process_group(group, Signal::KILL);
                }
                Ok(status)
            }
            Ok(Err(_)) | Err(_) => {
                if let Some(group) = Pid::from_raw(self.process_group) {
                    let _ = kill_process_group(group, Signal::KILL);
                }
                let _ = self.child.start_kill();
                let result = timeout(Duration::from_secs(10), self.child.wait())
                    .await
                    .map_err(|_| LaunchError::Process)?
                    .map_err(|_| LaunchError::Process)?;
                self.reaped = true;
                Ok(result)
            }
        }
    }
}

impl Drop for JavaChild {
    fn drop(&mut self) {
        use rustix::process::{Pid, Signal, kill_process_group};
        if !self.reaped {
            if let Some(group) = Pid::from_raw(self.process_group) {
                let _ = kill_process_group(group, Signal::KILL);
            }
            let _ = self.child.start_kill();
        }
    }
}

/// Installed SIGINT/SIGTERM streams for a supervised Java child.
pub struct JavaSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl JavaSignals {
    /// Installs the Unix termination handlers before project side effects begin.
    ///
    /// # Errors
    ///
    /// Returns a sanitized process error if a handler cannot be installed.
    pub fn install() -> Result<Self, LaunchError> {
        use tokio::signal::unix::{SignalKind, signal};
        let interrupt = signal(SignalKind::interrupt()).map_err(|_| LaunchError::Process)?;
        let terminate = signal(SignalKind::terminate()).map_err(|_| LaunchError::Process)?;
        Ok(Self { interrupt, terminate })
    }
}

fn resolve_executable(program: &Path, path: Option<&OsStr>) -> Result<PathBuf, LaunchError> {
    use std::path::Component;

    if program
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        || program.components().count() > 1
    {
        return program
            .canonicalize()
            .map_err(|_| LaunchError::Validation("the Java launcher is unavailable"));
    }
    let path = path.ok_or(LaunchError::Validation("PATH does not contain a Java launcher"))?;
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        if std::fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file()) {
            return candidate
                .canonicalize()
                .map_err(|_| LaunchError::Validation("the Java launcher path is invalid"));
        }
    }
    Err(LaunchError::Validation("PATH does not contain a Java launcher"))
}

fn verify_native_jdk(executable: &Path) -> Result<(), LaunchError> {
    use std::io::Read as _;
    use std::process::Command;

    let mut file = std::fs::File::open(executable)
        .map_err(|_| LaunchError::Validation("the Java launcher is unavailable"))?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|_| LaunchError::Validation("the Java launcher is not a native JDK binary"))?;
    let is_native = magic == *b"\x7fELF"
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        );
    if !is_native {
        return Err(LaunchError::Validation("the Java launcher is not a native JDK binary"));
    }

    // Probe the resolved executable without the agent, bootstrap, or user args.
    // Output is inspected in memory and never written to CLI output.
    let output = Command::new(executable)
        .arg("-version")
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS")
        .env_remove("_JAVA_OPTIONS")
        .output()
        .map_err(|_| LaunchError::Validation("the selected executable is not a Java launcher"))?;
    let version_text = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    let java_version = has_java_version_marker(&version_text);
    if !output.status.success() || !java_version {
        return Err(LaunchError::Validation("the selected executable is not a Java launcher"));
    }
    Ok(())
}

fn has_java_version_marker(version_text: &[u8]) -> bool {
    [b"java version ".as_slice(), b"openjdk version ".as_slice()]
        .into_iter()
        .any(|marker| version_text.windows(marker.len()).any(|window| window == marker))
}

fn clear_jvm_option_environment(command: &mut tokio::process::Command) {
    command
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS")
        .env_remove("_JAVA_OPTIONS");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
}

fn validate_distribution(agent: &Path) -> Result<(), LaunchError> {
    use std::collections::{BTreeMap, BTreeSet};

    let root = agent.parent().ok_or(LaunchError::Validation("the Java agent path is invalid"))?;
    if agent.file_name().is_none_or(|name| name != "xtrace-java-agent.jar") {
        return Err(LaunchError::Validation(
            "the agent distribution has an unexpected bootstrap JAR",
        ));
    }
    let expected_owner = rustix::process::getuid().as_raw();
    let root_metadata = validate_owned_directory(root, expected_owner)?;
    let runtime = root.join("runtime");
    let runtime_metadata = validate_owned_directory(&runtime, expected_owner)?;
    let manifest = root.join("manifest.sha256");
    let manifest_before = validate_owned_file(&manifest, expected_owner)?;
    if manifest_before.size > 1_048_576 {
        return Err(LaunchError::Validation("the agent manifest exceeds its size limit"));
    }

    let mut allowed_root = BTreeSet::new();
    allowed_root.insert("manifest.sha256".to_string());
    allowed_root.insert("runtime".to_string());
    allowed_root.insert("xtrace-java-agent.jar".to_string());
    for entry in std::fs::read_dir(root)
        .map_err(|_| LaunchError::Validation("the agent distribution cannot be read"))?
    {
        let entry =
            entry.map_err(|_| LaunchError::Validation("the agent distribution is invalid"))?;
        let name = entry.file_name().into_string().map_err(|_| {
            LaunchError::Validation("the agent distribution contains a non-UTF-8 name")
        })?;
        if !allowed_root.remove(&name) {
            return Err(LaunchError::Validation("the agent distribution has unexpected contents"));
        }
        if name == "runtime" {
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
                LaunchError::Validation("the agent runtime directory is unavailable")
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LaunchError::Validation("the agent runtime directory is invalid"));
            }
        } else {
            validate_owned_file(&entry.path(), expected_owner)?;
        }
    }
    if !allowed_root.is_empty() {
        return Err(LaunchError::Validation("the agent distribution is incomplete"));
    }

    let mut jars = BTreeMap::<String, PathBuf>::new();
    jars.insert("xtrace-java-agent.jar".to_string(), agent.to_path_buf());
    for entry in std::fs::read_dir(&runtime)
        .map_err(|_| LaunchError::Validation("the Java agent runtime directory cannot be read"))?
    {
        let entry = entry
            .map_err(|_| LaunchError::Validation("the Java agent runtime directory is invalid"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LaunchError::Validation("the runtime contains a non-UTF-8 name"))?;
        let relative = format!("runtime/{name}");
        let path = entry.path();
        if Path::new(&name).extension().is_none_or(|extension| extension != "jar")
            || validate_owned_file(&path, expected_owner).is_err()
            || jars.insert(relative, path).is_some()
        {
            return Err(LaunchError::Validation(
                "the Java agent runtime must contain only owned, unlinked regular JAR files",
            ));
        }
    }
    if jars.len() < 2 {
        return Err(LaunchError::Validation("the Java agent runtime has no JAR files"));
    }

    let manifest_text = std::fs::read_to_string(&manifest)
        .map_err(|_| LaunchError::Validation("the agent manifest cannot be read"))?;
    let mut declared = BTreeMap::new();
    for line in manifest_text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or(LaunchError::Validation("the agent manifest is malformed"))?;
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || declared.insert(path.to_string(), digest.to_string()).is_some()
        {
            return Err(LaunchError::Validation("the agent manifest is malformed"));
        }
    }
    if declared.len() != jars.len() || jars.keys().any(|path| !declared.contains_key(path)) {
        return Err(LaunchError::Validation("the agent manifest membership does not match"));
    }
    for (relative, path) in jars {
        let before = validate_owned_file(&path, expected_owner)?;
        let digest = sha256_file(&path, before)?;
        if declared.get(&relative) != Some(&digest) {
            return Err(LaunchError::Validation("the agent distribution digest does not match"));
        }
    }
    if manifest_before != validate_owned_file(&manifest, expected_owner)?
        || root_metadata
            != FileIdentity::from_metadata(&std::fs::symlink_metadata(root).map_err(|_| {
                LaunchError::Validation("the agent distribution changed during validation")
            })?)
        || runtime_metadata
            != FileIdentity::from_metadata(&std::fs::symlink_metadata(&runtime).map_err(|_| {
                LaunchError::Validation("the agent runtime changed during validation")
            })?)
    {
        return Err(LaunchError::Validation("the agent distribution changed during validation"));
    }
    let manifest_after = std::fs::read_to_string(&manifest)
        .map_err(|_| LaunchError::Validation("the agent manifest cannot be read"))?;
    if manifest_text != manifest_after {
        return Err(LaunchError::Validation("the agent manifest changed during validation"));
    }
    Ok(())
}

fn validate_owned_directory(path: &Path, owner: u32) -> Result<FileIdentity, LaunchError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchError::Validation("an agent distribution directory is unavailable"))?;
    let identity = FileIdentity::from_metadata(&metadata);
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || identity.owner != owner
        || identity.mode & 0o022 != 0
    {
        return Err(LaunchError::Validation(
            "agent distribution directories must be owned and not group/other writable",
        ));
    }
    Ok(identity)
}

fn validate_owned_file(path: &Path, owner: u32) -> Result<FileIdentity, LaunchError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchError::Validation("an agent distribution file is unavailable"))?;
    let identity = FileIdentity::from_metadata(&metadata);
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || identity.owner != owner
        || identity.links != 1
        || identity.mode & 0o022 != 0
    {
        return Err(LaunchError::Validation(
            "agent distribution files must be owned, unlinked, and not group/other writable",
        ));
    }
    Ok(identity)
}

fn sha256_file(path: &Path, expected: FileIdentity) -> Result<String, LaunchError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)
        .map_err(|_| LaunchError::Validation("an agent distribution JAR cannot be read"))?;
    if FileIdentity::from_metadata(
        &file
            .metadata()
            .map_err(|_| LaunchError::Validation("an agent distribution JAR cannot be read"))?,
    ) != expected
    {
        return Err(LaunchError::Validation("the agent distribution changed during validation"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LaunchError::Validation("an agent distribution JAR cannot be read"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let path_after = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchError::Validation("the agent distribution changed during validation"))?;
    if FileIdentity::from_metadata(&path_after) != expected
        || FileIdentity::from_metadata(
            &file
                .metadata()
                .map_err(|_| LaunchError::Validation("an agent distribution JAR cannot be read"))?,
        ) != expected
    {
        return Err(LaunchError::Validation("the agent distribution changed during validation"));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests use constructed launch inputs")]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn distribution(root: &Path) -> PathBuf {
        let agent_dir = root.join("agent space");
        std::fs::create_dir_all(agent_dir.join("runtime")).expect("runtime directory");
        let agent = agent_dir.join("xtrace-java-agent.jar");
        std::fs::write(&agent, b"PK\x03\x04agent").expect("agent jar");
        let runtime = agent_dir.join("runtime/runtime.jar");
        std::fs::write(&runtime, b"PK\x03\x04runtime").expect("runtime jar");
        use sha2::{Digest, Sha256};
        let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
        let manifest = format!(
            "{}  runtime/runtime.jar\n{}  xtrace-java-agent.jar\n",
            digest(b"PK\x03\x04runtime"),
            digest(b"PK\x03\x04agent"),
        );
        std::fs::write(agent_dir.join("manifest.sha256"), manifest).expect("manifest");
        std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o755))
            .expect("private distribution directory mode");
        std::fs::set_permissions(agent_dir.join("runtime"), std::fs::Permissions::from_mode(0o755))
            .expect("private runtime directory mode");
        let files = [agent.clone(), runtime, agent_dir.join("manifest.sha256")];
        for file in files {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644))
                .expect("private distribution file mode");
        }
        agent
    }

    fn real_java() -> Option<PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|directory| directory.join("java"))
            .find(|path| path.exists())
    }

    fn validation(agent: &Path) -> Result<JavaLaunch, LaunchError> {
        let java = real_java().expect("runtime tests require a JDK");
        JavaLaunch::validate(agent, &[java.into_os_string()])
    }

    #[test]
    fn recognizes_java_and_openjdk_version_markers_at_their_literal_lengths() {
        assert!(has_java_version_marker(b"java version \"17.0.10\" 2024-01-16"));
        assert!(has_java_version_marker(b"openjdk version \"21.0.12\" 2025-07-15"));
        assert!(!has_java_version_marker(b"OpenJDK version \"21\""));
        assert!(!has_java_version_marker(b"not a Java launcher"));
    }

    #[test]
    fn rejects_agent_delimiter_after_canonicalization() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let with_delimiter = root.path().join("agent=private");
        std::fs::rename(agent.parent().expect("agent parent"), &with_delimiter)
            .expect("rename agent directory");
        let agent = with_delimiter.join("xtrace-java-agent.jar");
        let result = validation(&agent);
        assert!(
            matches!(
                &result,
                Err(LaunchError::Validation("the canonical Java agent path cannot contain '='"))
            ),
            "baseline validation or expected delimiter check failed: {result:?}"
        );
    }

    #[test]
    fn refuses_build_tool_and_wrapper_launchers_before_any_side_effect() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        for command in [
            &["gradle", "bootRun"][..],
            &["./gradlew", "bootRun"][..],
            &["mvn", "spring-boot:run"][..],
            &["./mvnw", "spring-boot:run"][..],
            &["/usr/bin/env", "java", "-jar", "app.jar"][..],
            &["sh", "-c", "java -jar app.jar"][..],
            &["./run.sh"][..],
        ] {
            let command: Vec<OsString> = command.iter().map(OsString::from).collect();
            let error = JavaLaunch::validate(&agent, &command)
                .expect_err("non-direct launcher must be refused");
            assert!(
                matches!(&error, LaunchError::Validation(message)
                    if message.contains("only a direct executable named java")
                        && message.contains("gradle bootRun")),
                "{command:?}: {error:?}"
            );
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[test]
    fn rejects_fake_script_named_java_before_any_side_effect() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let bin = root.path().join("fake-bin");
        std::fs::create_dir_all(&bin).expect("fake bin");
        let fake_java = bin.join("java");
        std::fs::write(&fake_java, b"#!/bin/sh\nprintf 'openjdk version fake\\n' >&2\n")
            .expect("script");
        std::fs::set_permissions(&fake_java, std::fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        let path = std::env::join_paths([&bin]).expect("path");
        assert!(matches!(
            JavaLaunch::validate_with_path(&agent, &[OsString::from("java")], Some(&path)),
            Err(LaunchError::Validation("the Java launcher is not a native JDK binary"))
        ));
    }

    #[test]
    fn accepts_a_real_jdk_launcher_when_available() {
        let Some(java) = real_java() else { return };
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let result = JavaLaunch::validate(&agent, &[java.into_os_string()]);
        assert!(result.is_ok(), "real JDK preflight failed: {result:?}");
    }

    #[test]
    fn rejects_nul_arguments_before_project_preparation() {
        use std::os::unix::ffi::OsStringExt as _;
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let java = real_java().expect("runtime tests require a JDK");
        let command = vec![java.into_os_string(), OsString::from_vec(b"-Dbad\0value".to_vec())];
        assert!(matches!(
            JavaLaunch::validate(&agent, &command),
            Err(LaunchError::Validation("Java launch arguments cannot contain NUL bytes"))
        ));
    }

    #[test]
    fn rejects_java_argument_files_that_can_hide_agent_options() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let result = validation(&agent);
        assert!(result.is_ok(), "baseline agent distribution validation failed: {result:?}");
        let java = real_java().expect("runtime tests require a JDK");
        assert!(matches!(
            JavaLaunch::validate(&agent, &[java.into_os_string(), OsString::from("@hidden.args")]),
            Err(LaunchError::Validation(
                "Java @argfiles are unsupported because they can hide JVM options"
            ))
        ));
    }

    #[test]
    fn rejects_changed_jar_bytes_and_manifest_mismatch() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::write(&agent, b"PK\x03\x04altered").expect("alter agent bytes");
        let result = validation(&agent);
        assert!(
            matches!(
                &result,
                Err(LaunchError::Validation("the agent distribution digest does not match"))
            ),
            "baseline validation or changed-digest check failed: {result:?}"
        );

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let manifest = agent.parent().expect("agent dir").join("manifest.sha256");
        std::fs::write(&manifest, "0".repeat(64)).expect("bad manifest");
        assert!(validation(&agent).is_err());
    }

    #[test]
    fn rejects_extra_and_missing_runtime_jars() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::write(agent.parent().unwrap().join("runtime/extra.jar"), b"PK\x03\x04extra")
            .expect("extra jar");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::remove_file(agent.parent().unwrap().join("runtime/runtime.jar"))
            .expect("remove runtime jar");
        assert!(validation(&agent).is_err());
    }

    #[test]
    fn rejects_hard_links_and_group_or_other_writable_distribution_entries() {
        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::hard_link(&agent, root.path().join("agent-hardlink.jar")).expect("hard link");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o664))
            .expect("group-writable jar");
        assert!(validation(&agent).is_err(), "group-writable JAR must remain rejected");

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o666))
            .expect("world-writable jar");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let manifest = agent.parent().unwrap().join("manifest.sha256");
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o666))
            .expect("writable manifest");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        let manifest = agent.parent().unwrap().join("manifest.sha256");
        std::fs::hard_link(&manifest, root.path().join("manifest-hardlink.sha256"))
            .expect("manifest hard link");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::set_permissions(agent.parent().unwrap(), std::fs::Permissions::from_mode(0o777))
            .expect("writable distribution dir");
        assert!(validation(&agent).is_err());

        let root = tempfile::tempdir().expect("temp root");
        let agent = distribution(root.path());
        std::fs::set_permissions(
            agent.parent().unwrap().join("runtime"),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("writable runtime dir");
        assert!(validation(&agent).is_err());
    }

    #[test]
    fn launch_errors_have_stable_categories_and_exit_codes() {
        assert_eq!(LaunchError::Validation("bad input").code(), "XTR-RUN-INVALID-LAUNCH");
        assert_eq!(LaunchError::Validation("bad input").exit_code(), 2);
        assert_eq!(LaunchError::Process.code(), "XTR-RUN-PROCESS");
        assert_eq!(LaunchError::Process.exit_code(), 9);
    }
}
