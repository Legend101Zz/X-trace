//! Java application scope: which packages of a launched program are application code.
//!
//! The launcher resolves scope once, before the JVM starts, and hands it to the agent through the
//! private `capture.json` (see `application_scope`). Scope comes from, in order:
//!
//! 1. explicit `--app-package` prefixes (validated, deny-filtered), then
//! 2. the Spring Boot fat jar's `BOOT-INF/classes` entries (never `BOOT-INF/lib`), then
//! 3. nothing: the agent still records the request root and reports the handler as unresolved.
//!
//! The deny set mirrors the agent's `ApplicationScope.DENY_PREFIXES`. It cannot be widened by
//! configuration: a requested prefix inside it is dropped, never honored. Jar parsing reads only
//! the central directory, with hard bounds, and never extracts or executes anything.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Most packages a scope may name (matches the `capture.json` contract).
pub const MAX_APPLICATION_PACKAGES: usize = 64;

/// Longest accepted package prefix in bytes.
pub const MAX_PACKAGE_BYTES: usize = 256;

/// Package prefixes that are never application code. Keep in sync with the agent's
/// `ApplicationScope.DENY_PREFIXES`.
pub const DENY_PREFIXES: &[&str] = &[
    "java.",
    "javax.",
    "jakarta.",
    "jdk.",
    "sun.",
    "com.sun.",
    "dev.xtrace.agent.",
    "dev.xtrace.adapter.",
    "net.bytebuddy.",
    "org.bouncycastle.",
    "com.google.protobuf.",
    "org.slf4j.",
    "ch.qos.logback.",
    "org.apache.logging.",
];

const BOOT_CLASSES: &str = "BOOT-INF/classes/";
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 400_000;
const EOCD_SEARCH_BYTES: u64 = 65_557;
const GENERIC_ROOTS: &[&str] = &["com", "org", "net", "io", "dev", "edu", "gov", "app", "me"];

/// Where a resolved scope came from. Reported honestly, never inferred upward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeOrigin {
    /// Every prefix was named by the owner on the command line.
    Explicit,
    /// Prefixes were read from the fat jar's `BOOT-INF/classes` entries.
    FatJarClasses,
    /// No prefix could be determined; the agent reports `handler_unresolved`.
    None,
}

/// Application packages ready for `capture.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScope {
    /// Package prefixes (dot form), at most [`MAX_APPLICATION_PACKAGES`].
    pub application_packages: Vec<String>,
    /// How the prefixes were determined.
    pub origin: ScopeOrigin,
}

/// Why a jar could not be inspected. None of these fail a launch: scope falls back to none.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    /// The jar could not be opened or read.
    #[error("jar could not be read")]
    Unreadable,
    /// The archive structure is not a supported zip central directory.
    #[error("jar central directory is not supported")]
    Unsupported,
    /// The archive structure is inconsistent or exceeds a bound.
    #[error("jar central directory is malformed or too large")]
    Malformed,
}

/// Resolves scope from explicit prefixes, falling back to the fat jar, falling back to none.
pub fn resolve_scope(explicit: &[String], jar: Option<&Path>) -> ResolvedScope {
    let explicit = sanitize_prefixes(explicit);
    if !explicit.is_empty() {
        return ResolvedScope { application_packages: explicit, origin: ScopeOrigin::Explicit };
    }
    if let Some(jar) = jar {
        if let Ok(derived) = derive_fat_jar_packages(jar) {
            if !derived.is_empty() {
                return ResolvedScope {
                    application_packages: derived,
                    origin: ScopeOrigin::FatJarClasses,
                };
            }
        }
    }
    ResolvedScope { application_packages: Vec::new(), origin: ScopeOrigin::None }
}

/// Validates, deny-filters, de-duplicates and bounds requested prefixes.
pub fn sanitize_prefixes(requested: &[String]) -> Vec<String> {
    let mut accepted: Vec<String> = Vec::new();
    for value in requested {
        if accepted.len() >= MAX_APPLICATION_PACKAGES {
            break;
        }
        if !valid_package(value) || is_denied(value) || accepted.contains(value) {
            continue;
        }
        accepted.push(value.clone());
    }
    accepted
}

/// True when a package (or class) name is inside the fixed deny set.
pub fn is_denied(package: &str) -> bool {
    let probe = format!("{package}.");
    DENY_PREFIXES.iter().any(|prefix| probe.starts_with(prefix))
}

/// A Java package name: dot-separated identifiers, bounded.
pub fn valid_package(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_PACKAGE_BYTES {
        return false;
    }
    value.split('.').all(valid_identifier)
}

fn valid_identifier(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' || first == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Finds the jar path after `-jar` in a JVM argument vector, if any.
pub fn jar_from_java_args<S: AsRef<OsStr>>(args: &[S]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg.as_ref() == OsStr::new("-jar") {
            return iter.next().map(|path| PathBuf::from(path.as_ref()));
        }
    }
    None
}

/// Reads a fat jar's central directory and returns the application package prefixes found under
/// `BOOT-INF/classes/`. Dependency jars (`BOOT-INF/lib/`) and other trees never contribute.
pub fn derive_fat_jar_packages(jar: &Path) -> Result<Vec<String>, ScopeError> {
    let mut file = File::open(jar).map_err(|_| ScopeError::Unreadable)?;
    let names = central_directory_names(&mut file)?;
    Ok(package_roots(boot_class_packages(&names)))
}

fn central_directory_names(file: &mut File) -> Result<Vec<Vec<u8>>, ScopeError> {
    let length = file.metadata().map_err(|_| ScopeError::Unreadable)?.len();
    if length < 22 {
        return Err(ScopeError::Malformed);
    }
    let tail_len = length.min(EOCD_SEARCH_BYTES);
    file.seek(SeekFrom::Start(length - tail_len)).map_err(|_| ScopeError::Unreadable)?;
    let mut tail = vec![0_u8; tail_len as usize];
    file.read_exact(&mut tail).map_err(|_| ScopeError::Unreadable)?;
    let eocd = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|&at| tail[at..at + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or(ScopeError::Malformed)?;
    let record = &tail[eocd..];
    let entries = u64::from(u16::from_le_bytes([record[10], record[11]]));
    let directory_size =
        u64::from(u32::from_le_bytes([record[12], record[13], record[14], record[15]]));
    if entries == 0xFFFF || directory_size == 0xFFFF_FFFF {
        return Err(ScopeError::Unsupported);
    }
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES || entries as usize > MAX_ENTRIES {
        return Err(ScopeError::Malformed);
    }
    let eocd_at = length - tail_len + eocd as u64;
    // The directory ends where the end record starts; this stays correct when launcher scripts
    // are prepended to the archive and stored offsets are shifted.
    let start = eocd_at.checked_sub(directory_size).ok_or(ScopeError::Malformed)?;
    file.seek(SeekFrom::Start(start)).map_err(|_| ScopeError::Unreadable)?;
    let mut directory = vec![0_u8; directory_size as usize];
    file.read_exact(&mut directory).map_err(|_| ScopeError::Unreadable)?;
    parse_names(&directory, entries as usize)
}

fn parse_names(directory: &[u8], expected: usize) -> Result<Vec<Vec<u8>>, ScopeError> {
    let mut names = Vec::new();
    let mut at = 0_usize;
    while at < directory.len() {
        let header = directory.get(at..at + 46).ok_or(ScopeError::Malformed)?;
        if header[..4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(ScopeError::Malformed);
        }
        let name_len = usize::from(u16::from_le_bytes([header[28], header[29]]));
        let extra_len = usize::from(u16::from_le_bytes([header[30], header[31]]));
        let comment_len = usize::from(u16::from_le_bytes([header[32], header[33]]));
        let name = directory.get(at + 46..at + 46 + name_len).ok_or(ScopeError::Malformed)?;
        names.push(name.to_vec());
        at += 46 + name_len + extra_len + comment_len;
        if names.len() > MAX_ENTRIES {
            return Err(ScopeError::Malformed);
        }
    }
    if names.len() != expected {
        return Err(ScopeError::Malformed);
    }
    Ok(names)
}

/// Distinct dot-form packages of `.class` entries under `BOOT-INF/classes/`.
fn boot_class_packages(names: &[Vec<u8>]) -> Vec<String> {
    let mut packages: Vec<String> = Vec::new();
    for raw in names {
        let Ok(name) = std::str::from_utf8(raw) else { continue };
        let Some(rest) = name.strip_prefix(BOOT_CLASSES) else { continue };
        let Some(path) = rest.strip_suffix(".class") else { continue };
        let Some((directory, _class)) = path.rsplit_once('/') else { continue };
        let package = directory.replace('/', ".");
        if !valid_package(&package) || is_denied(&package) {
            continue;
        }
        if !packages.contains(&package) {
            packages.push(package);
        }
    }
    packages.sort();
    packages
}

/// Collapses packages to their application roots: the longest common prefix of each group, never a
/// bare generic root such as `com` or `org`.
fn package_roots(packages: Vec<String>) -> Vec<String> {
    let mut roots = Vec::new();
    group_roots(&packages, 0, &mut roots);
    roots.sort();
    roots.dedup();
    roots.truncate(MAX_APPLICATION_PACKAGES);
    roots
}

fn group_roots(packages: &[String], depth: usize, roots: &mut Vec<String>) {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for package in packages {
        let segments: Vec<&str> = package.split('.').collect();
        let key = segments[..(depth + 1).min(segments.len())].join(".");
        match groups.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, members)) => members.push(package.clone()),
            None => groups.push((key, vec![package.clone()])),
        }
    }
    for (key, members) in groups {
        let prefix = common_prefix(&members);
        let segments = prefix.split('.').count();
        let generic = segments == 1 && GENERIC_ROOTS.contains(&prefix.as_str());
        if generic && members.iter().any(|member| member != &prefix) {
            group_roots(&members, depth + 1, roots);
        } else if !generic {
            roots.push(prefix);
        } else {
            roots.push(key);
        }
    }
}

fn common_prefix(packages: &[String]) -> String {
    let mut prefix: Vec<&str> = packages[0].split('.').collect();
    for package in &packages[1..] {
        let segments: Vec<&str> = package.split('.').collect();
        let shared = prefix.iter().zip(&segments).take_while(|(a, b)| a == b).count();
        prefix.truncate(shared);
    }
    prefix.join(".")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests use constructed jars")]
mod tests {
    use super::*;
    use std::io::Write;

    fn jar(entries: &[&str], prefix: &[u8]) -> tempfile::NamedTempFile {
        let mut body: Vec<u8> = prefix.to_vec();
        let mut central: Vec<u8> = Vec::new();
        for name in entries {
            let offset = body.len() as u32;
            body.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            body.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0]);
            central.extend_from_slice(&[0; 20]);
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let directory_at = body.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(central.len() as u32).to_le_bytes());
        body.extend_from_slice(&directory_at.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        let mut file = tempfile::NamedTempFile::new().expect("temp jar");
        file.write_all(&body).expect("write jar");
        file
    }

    fn petclinic() -> Vec<&'static str> {
        vec![
            "META-INF/MANIFEST.MF",
            "BOOT-INF/classes/application.properties",
            "BOOT-INF/classes/org/springframework/samples/petclinic/PetClinicApplication.class",
            "BOOT-INF/classes/org/springframework/samples/petclinic/owner/OwnerController.class",
            "BOOT-INF/classes/org/springframework/samples/petclinic/vet/VetController.class",
            "BOOT-INF/classes/org/springframework/samples/petclinic/system/WebConfiguration.class",
            "BOOT-INF/lib/spring-web-7.0.0.jar",
            "org/springframework/boot/loader/launch/JarLauncher.class",
        ]
    }

    #[test]
    fn fat_jar_boot_inf_classes_yields_top_level_packages() {
        let file = jar(&petclinic(), b"");
        let packages = derive_fat_jar_packages(file.path()).expect("derive");
        assert_eq!(packages, vec!["org.springframework.samples.petclinic".to_owned()]);
    }

    #[test]
    fn dependency_jars_never_application_roots() {
        let file = jar(
            &[
                "BOOT-INF/lib/acme-shared.jar",
                "BOOT-INF/lib/com/acme/shared/Util.class",
                "com/acme/loader/Launcher.class",
                "BOOT-INF/classes/com/acme/app/Main.class",
            ],
            b"",
        );
        assert_eq!(
            derive_fat_jar_packages(file.path()).expect("derive"),
            vec!["com.acme.app".to_owned()]
        );
    }

    #[test]
    fn no_prefix_found_reports_none_and_an_empty_scope() {
        let file = jar(&["META-INF/MANIFEST.MF", "BOOT-INF/lib/a.jar"], b"");
        let scope = resolve_scope(&[], Some(file.path()));
        assert_eq!(scope.origin, ScopeOrigin::None);
        assert!(scope.application_packages.is_empty());
        let missing = resolve_scope(&[], Some(Path::new("/nonexistent/app.jar")));
        assert_eq!(missing.origin, ScopeOrigin::None);
        assert_eq!(resolve_scope(&[], None).origin, ScopeOrigin::None);
    }

    #[test]
    fn two_applications_under_one_generic_root_stay_separate() {
        let file = jar(
            &[
                "BOOT-INF/classes/com/acme/web/A.class",
                "BOOT-INF/classes/com/acme/web/api/B.class",
                "BOOT-INF/classes/com/other/svc/C.class",
            ],
            b"",
        );
        assert_eq!(
            derive_fat_jar_packages(file.path()).expect("derive"),
            vec!["com.acme.web".to_owned(), "com.other.svc".to_owned()]
        );
    }

    #[test]
    fn prepended_launch_script_does_not_break_the_directory_read() {
        let file = jar(&petclinic(), b"#!/bin/sh\nexec java -jar \"$0\"\n");
        assert_eq!(
            derive_fat_jar_packages(file.path()).expect("derive"),
            vec!["org.springframework.samples.petclinic".to_owned()]
        );
    }

    #[test]
    fn explicit_prefixes_win_and_the_deny_set_cannot_be_overridden() {
        let file = jar(&petclinic(), b"");
        let scope = resolve_scope(
            &[
                "java.lang".to_owned(),
                "dev.xtrace.agent".to_owned(),
                "jakarta.servlet".to_owned(),
                "com.acme..bad".to_owned(),
                "com.acme".to_owned(),
                "com.acme".to_owned(),
            ],
            Some(file.path()),
        );
        assert_eq!(scope.origin, ScopeOrigin::Explicit);
        assert_eq!(scope.application_packages, vec!["com.acme".to_owned()]);
        // Only denied requests: falls through to the jar rather than honoring them.
        let fallback = resolve_scope(&["java.util".to_owned()], Some(file.path()));
        assert_eq!(fallback.origin, ScopeOrigin::FatJarClasses);
    }

    #[test]
    fn denied_and_invalid_packages_in_a_jar_are_skipped() {
        let file = jar(
            &[
                "BOOT-INF/classes/javax/inject/Inject.class",
                "BOOT-INF/classes/dev/xtrace/agent/Bad.class",
                "BOOT-INF/classes/com/acme/1bad/X.class",
                "BOOT-INF/classes/com/acme/ok/Y.class",
            ],
            b"",
        );
        assert_eq!(
            derive_fat_jar_packages(file.path()).expect("derive"),
            vec!["com.acme.ok".to_owned()]
        );
    }

    #[test]
    fn corrupt_or_unsupported_archives_are_errors_not_panics() {
        let mut file = tempfile::NamedTempFile::new().expect("temp");
        file.write_all(b"not a zip at all, but long enough to search for a record").expect("write");
        assert_eq!(derive_fat_jar_packages(file.path()), Err(ScopeError::Malformed));
        let tiny = tempfile::NamedTempFile::new().expect("temp");
        assert_eq!(derive_fat_jar_packages(tiny.path()), Err(ScopeError::Malformed));
        // Entry count disagreeing with the directory is malformed.
        let good = jar(&petclinic(), b"");
        let mut bytes = std::fs::read(good.path()).expect("read");
        let at = bytes.len() - 22 + 10;
        bytes[at] = bytes[at].wrapping_add(1);
        std::fs::write(good.path(), bytes).expect("write");
        assert_eq!(derive_fat_jar_packages(good.path()), Err(ScopeError::Malformed));
    }

    #[test]
    fn package_count_is_bounded() {
        let names: Vec<String> =
            (0..100).map(|n| format!("BOOT-INF/classes/zz{n}/q/A.class")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let file = jar(&refs, b"");
        assert_eq!(
            derive_fat_jar_packages(file.path()).expect("derive").len(),
            MAX_APPLICATION_PACKAGES
        );
        let many: Vec<String> = (0..100).map(|n| format!("com.acme.p{n}")).collect();
        assert_eq!(sanitize_prefixes(&many).len(), MAX_APPLICATION_PACKAGES);
    }

    #[test]
    fn jar_is_found_after_the_jar_flag() {
        assert_eq!(
            jar_from_java_args(&["-Xmx1g", "-jar", "app.jar", "--server.port=1"]),
            Some(PathBuf::from("app.jar"))
        );
        assert_eq!(jar_from_java_args(&["-cp", "x", "Main"]), None);
        assert_eq!(jar_from_java_args(&["-jar"]), None);
    }

    #[test]
    fn package_validation_matches_the_agent() {
        assert!(valid_package("com.acme.web"));
        assert!(valid_package("a.b$c.d_e"));
        for bad in ["", ".a", "a.", "a..b", "1a", "a-b", "a/b", "a b"] {
            assert!(!valid_package(bad), "{bad}");
        }
        assert!(!valid_package(&"a".repeat(MAX_PACKAGE_BYTES + 1)));
        assert!(is_denied("java.lang"));
        assert!(is_denied("java"));
        assert!(!is_denied("javafoo"));
        assert!(is_denied("dev.xtrace.agent.runtime"));
        assert!(!is_denied("dev.xtrace.fixture"));
    }
}
