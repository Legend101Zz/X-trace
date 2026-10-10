//! Capture options of `xtrace run` (CONTRACTS 11.2) and the private `capture.json` writer
//! (CONTRACTS 10.3).
//!
//! `capture.json` travels beside the bootstrap artifact, mode `0600`, so the bootstrap schema
//! stays byte-compatible with every shipped reader. The Java agent reads the application scope and
//! the capture mode; the daemon reads the capture mode to arm the session. Application roots may
//! be absolute because this file is private; they are never copied to logs or the API.

#[cfg(unix)]
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::error::CliError;

/// Name of the private capture file beside the bootstrap artifact; owned by the daemon's reader
/// so writer and reader can never disagree on it.
pub(crate) const CAPTURE_FILE_NAME: &str = xtrace_daemon::capture_config::CAPTURE_FILE_NAME;

const MAX_SOURCE_ROOTS: usize = 32;
const MAX_ROOT_BYTES: usize = 256;
/// Per-request focused line budget; matches the Java agent's per-request cap.
const FOCUSED_MAX_LINE_EVENTS: u64 = 8_192;
const MAX_VALUE_BYTES: u64 = 262_144;

/// Capture depth of a launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureDepth {
    /// Default method-level capture.
    Standard,
    /// Opt-in line and local-value capture inside the application scope.
    Focused,
}

impl CaptureDepth {
    pub(crate) fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "standard" => Ok(Self::Standard),
            "focused" => Ok(Self::Focused),
            _ => Err(CliError::InvalidArgument(
                "capture depth must be `standard` or `focused`".to_string(),
            )),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Focused => "focused",
        }
    }
}

/// Capture flags shared by `xtrace run`.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct CaptureArgs {
    /// Capture depth: `standard` (default) or `focused` (line events and local values).
    #[arg(long = "capture-depth", value_name = "DEPTH")]
    pub capture_depth: Option<String>,
    /// Application package prefix to capture (repeatable, Java). Without it the packages are
    /// read from a Spring Boot fat jar's `BOOT-INF/classes`.
    #[arg(long = "app-package", value_name = "PREFIX")]
    pub app_package: Vec<String>,
    /// Repo-relative source directory used to attest source locations (repeatable).
    #[arg(long = "source-root", value_name = "REPO_RELATIVE_DIR")]
    pub source_root: Vec<String>,
    /// Launch strategy: `direct` is the only strategy this build executes.
    #[arg(long = "launcher", value_name = "KIND")]
    pub launcher: Option<String>,
}

/// Validated capture options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaptureOptions {
    pub(crate) depth: CaptureDepth,
    pub(crate) app_packages: Vec<String>,
    pub(crate) source_roots: Vec<String>,
}

/// Capture options after scope resolution: exactly what `capture.json` carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedCapture {
    pub(crate) depth: CaptureDepth,
    /// Sanitized package prefixes (`xtrace_runtime::java_scope::resolve_scope`).
    pub(crate) application_packages: Vec<String>,
    pub(crate) source_roots: Vec<String>,
}

impl ResolvedCapture {
    /// The version-1 `capture.json` document for these options.
    pub(crate) fn document(&self) -> serde_json::Value {
        document(self.depth, &self.application_packages, &self.source_roots)
    }
}

#[cfg(unix)]
impl CaptureOptions {
    /// Resolves the application scope the way `xtrace run` does: explicit prefixes, else a
    /// Spring Boot fat jar's `BOOT-INF/classes` when a `jar` is known, else honestly empty.
    pub(crate) fn resolve(&self, jar: Option<&Path>) -> ResolvedCapture {
        let scope = xtrace_runtime::java_scope::resolve_scope(&self.app_packages, jar);
        ResolvedCapture {
            depth: self.depth,
            application_packages: scope.application_packages,
            source_roots: self.source_roots.clone(),
        }
    }
}

impl CaptureArgs {
    /// True when any capture flag was supplied.
    pub(crate) fn any_given(&self) -> bool {
        self.capture_depth.is_some()
            || !self.app_package.is_empty()
            || !self.source_root.is_empty()
            || self.launcher.is_some()
    }

    /// Validates every flag; nothing is silently dropped.
    pub(crate) fn validate(&self) -> Result<CaptureOptions, CliError> {
        let depth = match self.capture_depth.as_deref() {
            None => CaptureDepth::Standard,
            Some(value) => CaptureDepth::parse(value)?,
        };
        match self.launcher.as_deref() {
            None | Some("direct") => {}
            Some("maven" | "gradle" | "package-manager" | "supervisor") => {
                return Err(CliError::InvalidArgument(
                    "this build only executes `--launcher direct`".to_string(),
                ));
            }
            Some(_) => {
                return Err(CliError::InvalidArgument(
                    "launcher must be one of direct, maven, gradle, package-manager, supervisor"
                        .to_string(),
                ));
            }
        }
        #[cfg(unix)]
        {
            if self.app_package.len() > xtrace_runtime::java_scope::MAX_APPLICATION_PACKAGES {
                return Err(CliError::InvalidArgument(
                    "too many --app-package values (at most 64)".to_string(),
                ));
            }
            for package in &self.app_package {
                if !xtrace_runtime::java_scope::valid_package(package) {
                    return Err(CliError::InvalidArgument(
                        "--app-package must be a Java package prefix such as com.example.app"
                            .to_string(),
                    ));
                }
                if xtrace_runtime::java_scope::is_denied(package) {
                    return Err(CliError::InvalidArgument(
                        "--app-package names a JDK or infrastructure package that is never application \
                         code"
                            .to_string(),
                    ));
                }
            }
        }
        if self.source_root.len() > MAX_SOURCE_ROOTS {
            return Err(CliError::InvalidArgument(
                "too many --source-root values (at most 32)".to_string(),
            ));
        }
        for root in &self.source_root {
            if !is_safe_relative(root) {
                return Err(CliError::InvalidArgument(
                    "--source-root must be a repo-relative directory without `..` segments"
                        .to_string(),
                ));
            }
        }
        Ok(CaptureOptions {
            depth,
            app_packages: self.app_package.clone(),
            source_roots: self.source_root.clone(),
        })
    }
}

/// A repo-relative directory: no absolute path, no parent segments, no control characters.
pub(crate) fn is_safe_relative(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ROOT_BYTES || value.starts_with('/') {
        return false;
    }
    if value.chars().any(|c| c < ' ' || c == '\u{7f}' || c == '\\') {
        return false;
    }
    value.split('/').all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Builds the version-1 document.
pub(crate) fn document(
    depth: CaptureDepth,
    application_packages: &[String],
    source_roots: &[String],
) -> serde_json::Value {
    let focused = depth == CaptureDepth::Focused;
    json!({
        "capture_schema_version": 1,
        "launch": { "kind": "direct", "package_manager": null },
        "capture": {
            "mode": depth.as_str(),
            "max_line_events": if focused { FOCUSED_MAX_LINE_EVENTS } else { 0 },
            "max_value_bytes": MAX_VALUE_BYTES,
            "include_locals": focused,
        },
        "application_scope": {
            "application_packages": application_packages,
            "application_roots": [],
            "source_roots": source_roots,
            "deny_packages": [],
        },
        "launch_grant": { "launch_id": uuid_v4_like(), "multi_session": false },
    })
}

fn uuid_v4_like() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Writes `capture.json` beside `bootstrap_path` with mode `0600`, failing if one already exists.
#[cfg(unix)]
pub(crate) fn write_beside(
    bootstrap_path: &Path,
    document: &serde_json::Value,
) -> Result<PathBuf, CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = bootstrap_path.parent().ok_or(CliError::PrivateStorageUnavailable)?;
    let path = parent.join(CAPTURE_FILE_NAME);
    let bytes = serde_json::to_vec(document).map_err(|_| CliError::PrivateStorageUnavailable)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    Ok(path)
}

/// The depth the daemon will arm for a session whose bootstrap sits at `bootstrap_path`.
///
/// Delegates to the daemon's own reader (private, regular, non-symlink, size-bounded, same-inode
/// read), so this answer and the daemon's behaviour cannot drift apart. Anything unreadable is
/// `standard`, which is also what the daemon serves in that case.
#[cfg(unix)]
pub(crate) fn armed_depth_beside(bootstrap_path: &Path) -> CaptureDepth {
    match xtrace_daemon::capture_config::armed_mode_beside(bootstrap_path) {
        xtrace_domain::CaptureMode::Focused => CaptureDepth::Focused,
        _ => CaptureDepth::Standard,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixtures")]
mod tests {
    use super::*;

    fn args() -> CaptureArgs {
        CaptureArgs::default()
    }

    #[test]
    fn defaults_are_standard_without_scope() {
        let options = args().validate().expect("defaults");
        assert_eq!(options.depth, CaptureDepth::Standard);
        assert!(options.app_packages.is_empty() && options.source_roots.is_empty());
    }

    #[test]
    fn rejects_bad_depth_launcher_package_and_roots() {
        let mut a = args();
        a.capture_depth = Some("deep".into());
        assert!(a.validate().is_err());
        let mut a = args();
        a.launcher = Some("maven".into());
        assert!(a.validate().is_err(), "non-direct launcher must not be silently ignored");
        a.launcher = Some("rocket".into());
        assert!(a.validate().is_err());
        let mut a = args();
        a.app_package = vec!["not a package".into()];
        assert!(a.validate().is_err());
        let mut a = args();
        a.app_package = vec!["java.util".into()];
        assert!(a.validate().is_err(), "JDK packages are never application scope");
        for bad in ["/abs", "../up", "a/../b", "", "a//b", "a\\b"] {
            let mut a = args();
            a.source_root = vec![bad.into()];
            assert!(a.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn document_matches_the_published_schema_keys() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/capture/capture.schema.json"))
                .expect("schema parses");
        let doc =
            document(CaptureDepth::Focused, &["com.example".into()], &["src/main/java".into()]);
        for key in schema["required"].as_array().expect("required") {
            assert!(doc.get(key.as_str().expect("key")).is_some(), "missing {key}");
        }
        for section in ["launch", "capture", "application_scope", "launch_grant"] {
            for key in schema["properties"][section]["required"].as_array().expect("required") {
                assert!(doc[section].get(key.as_str().expect("key")).is_some(), "{section}.{key}");
            }
        }
        assert_eq!(doc["capture"]["mode"], "focused");
        assert_eq!(doc["capture"]["include_locals"], true);
        assert_eq!(doc["application_scope"]["application_packages"][0], "com.example");
        let standard = document(CaptureDepth::Standard, &[], &[]);
        assert_eq!(standard["capture"]["mode"], "standard");
        assert_eq!(standard["capture"]["max_line_events"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn writer_creates_a_private_file_and_refuses_to_overwrite() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("dir");
        let bootstrap = dir.path().join("bootstrap.json");
        let doc = document(CaptureDepth::Focused, &[], &[]);
        let path = write_beside(&bootstrap, &doc).expect("write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(armed_depth_beside(&bootstrap), CaptureDepth::Focused);
        assert!(write_beside(&bootstrap, &doc).is_err(), "never overwrite");
    }

    #[cfg(unix)]
    #[test]
    fn armed_depth_ignores_world_readable_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("dir");
        let bootstrap = dir.path().join("bootstrap.json");
        let path = write_beside(&bootstrap, &document(CaptureDepth::Focused, &[], &[])).expect("w");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            armed_depth_beside(&bootstrap),
            CaptureDepth::Standard,
            "a non-private file never arms focused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_keeps_depth_and_roots_and_drops_prefixes_that_are_never_application_code() {
        let options = CaptureOptions {
            depth: CaptureDepth::Focused,
            app_packages: vec![
                "com.example.app".into(),
                "java.util".into(),
                "com.example.app".into(),
            ],
            source_roots: vec!["src/main/java".into()],
        };
        let resolved = options.resolve(None);
        assert_eq!(resolved.depth, CaptureDepth::Focused);
        assert_eq!(resolved.application_packages, vec!["com.example.app".to_owned()]);
        assert_eq!(resolved.source_roots, vec!["src/main/java".to_owned()]);
        let document = resolved.document();
        assert_eq!(document["application_scope"]["application_packages"][0], "com.example.app");
        assert_eq!(document["application_scope"]["source_roots"][0], "src/main/java");
        let empty = CaptureOptions {
            depth: CaptureDepth::Standard,
            app_packages: Vec::new(),
            source_roots: Vec::new(),
        }
        .resolve(None);
        assert!(empty.application_packages.is_empty(), "no jar and no flag is honestly empty");
    }

    #[cfg(unix)]
    #[test]
    fn the_daemon_reader_arms_exactly_what_this_writer_wrote() {
        // Golden agreement between the CLI writer and the daemon's hardened reader: the
        // document `record` and `run` write is the document the daemon arms from.
        for (depth, mode) in [
            (CaptureDepth::Focused, xtrace_domain::CaptureMode::Focused),
            (CaptureDepth::Standard, xtrace_domain::CaptureMode::Standard),
        ] {
            let bytes = serde_json::to_vec(&document(depth, &["com.example".into()], &[]))
                .expect("serialize");
            assert_eq!(xtrace_daemon::capture_config::parse_armed_mode(&bytes), mode);
        }
        assert_eq!(CAPTURE_FILE_NAME, "capture.json");
    }
}
