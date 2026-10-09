//! Installed language-pack discovery (lane P).
//!
//! Packs live at `<prefix>/share/xtrace/packs/<language>` relative to the running executable
//! (`<prefix>/bin/xtrace`). Discovery uses the executable path only: no environment variable, no
//! current directory and no command-line input can redirect it (ADR 0004: no trust input from the pack,
//! the environment or the CLI). Discovery reports what is there and what the fixed, compiled-in trust
//! table says about its manifest; it never launches anything.

use std::path::{Path, PathBuf};

use crate::signed_pack::{SignedPackError, verify_with_installed_trust};

const MANIFEST_NAME: &str = "xtrace-pack.json";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// What the fixed trust table says about an installed pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackTrustState {
    /// The directory exists but carries no `xtrace-pack.json`: an unsigned layout, never verified.
    UnsignedLayout,
    /// A manifest exists and its signature verifies against the compiled-in trust table.
    /// This says nothing about the pack's files: the file inventory is not re-hashed here.
    ManifestVerified,
    /// A manifest exists but cannot be trusted; the code is stable (`XTR-PACK-*` style, lower snake).
    Untrusted(&'static str),
}

/// One installed language pack as found on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledPack {
    /// Pack language directory name (`java` or `node`).
    pub language: &'static str,
    /// Absolute pack directory.
    pub directory: PathBuf,
    /// Trust state of the manifest, if any.
    pub trust: PackTrustState,
}

/// Returns `<prefix>/share/xtrace/packs` for an executable at `<prefix>/bin/<name>`.
#[must_use]
pub fn packs_root_for_executable(executable: &Path) -> Option<PathBuf> {
    // Resolve symlinks first so a symlinked invocation path (for example a user-controlled
    // `~/bin/xtrace`) never selects a pack directory next to the link (ADR 0004: executable only).
    let resolved = executable.canonicalize().unwrap_or_else(|_| executable.to_path_buf());
    let bin_dir = resolved.parent()?;
    let prefix = bin_dir.parent()?;
    Some(prefix.join("share").join("xtrace").join("packs"))
}

/// Finds the installed pack for `language` next to `executable`, or `None` when it is absent.
///
/// Symlinked pack directories are not followed.
#[must_use]
pub fn locate(executable: &Path, language: &'static str) -> Option<InstalledPack> {
    let directory = packs_root_for_executable(executable)?.join(language);
    let metadata = std::fs::symlink_metadata(&directory).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    let trust = trust_of(&directory);
    Some(InstalledPack { language, directory, trust })
}

fn trust_of(directory: &Path) -> PackTrustState {
    let manifest = directory.join(MANIFEST_NAME);
    let Ok(metadata) = std::fs::symlink_metadata(&manifest) else {
        return PackTrustState::UnsignedLayout;
    };
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return PackTrustState::Untrusted("manifest_invalid");
    }
    let Ok(bytes) = std::fs::read(&manifest) else {
        return PackTrustState::Untrusted("manifest_unreadable");
    };
    match verify_with_installed_trust(&bytes) {
        Ok(()) => PackTrustState::ManifestVerified,
        Err(error) => PackTrustState::Untrusted(error_code(error)),
    }
}

const fn error_code(error: SignedPackError) -> &'static str {
    match error {
        SignedPackError::InvalidManifest => "manifest_invalid",
        SignedPackError::UnsupportedManifest => "manifest_unsupported",
        SignedPackError::InventoryMismatch => "inventory_mismatch",
        SignedPackError::BuildHashMismatch => "build_hash_mismatch",
        SignedPackError::InvalidSignature => "signature_invalid",
        SignedPackError::TrustUnavailable => "trust_unavailable",
        SignedPackError::ResourceLimit => "resource_limit",
        SignedPackError::PrivateSnapshotUnavailable => "snapshot_unavailable",
        SignedPackError::SnapshotIncomplete => "snapshot_incomplete",
        SignedPackError::SnapshotCleanupUncertain => "snapshot_cleanup_uncertain",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "unit fixtures assert on temp dirs")]
mod tests {
    use super::*;

    fn prefix_with(languages: &[&str]) -> tempfile::TempDir {
        let prefix = tempfile::tempdir().expect("temp prefix");
        std::fs::create_dir_all(prefix.path().join("bin")).unwrap();
        for language in languages {
            std::fs::create_dir_all(prefix.path().join("share/xtrace/packs").join(language))
                .unwrap();
        }
        prefix
    }

    #[test]
    fn discovery_resolves_next_to_the_executable_only() {
        let prefix = prefix_with(&["java"]);
        let exe = prefix.path().join("bin/xtrace");
        let decoy = tempfile::tempdir().expect("decoy");
        std::fs::create_dir_all(decoy.path().join("share/xtrace/packs/node")).unwrap();
        // Discovery takes only the executable path (no env, cwd or CLI input), so a decoy pack tree
        // elsewhere cannot be selected.
        let java = locate(&exe, "java").expect("java pack");
        assert_eq!(java.directory, prefix.path().join("share/xtrace/packs/java"));
        assert_eq!(java.trust, PackTrustState::UnsignedLayout);
        assert!(locate(&exe, "node").is_none(), "a decoy elsewhere is not found");
    }

    #[test]
    fn a_manifest_outside_the_contract_is_untrusted_with_a_stable_code() {
        let prefix = prefix_with(&["node"]);
        let exe = prefix.path().join("bin/xtrace");
        std::fs::write(prefix.path().join("share/xtrace/packs/node/xtrace-pack.json"), b"{}")
            .unwrap();
        let node = locate(&exe, "node").expect("node pack");
        assert_eq!(node.trust, PackTrustState::Untrusted("manifest_unsupported"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pack_directories_are_not_followed() {
        let prefix = prefix_with(&[]);
        let real = tempfile::tempdir().expect("real");
        std::fs::create_dir_all(prefix.path().join("share/xtrace/packs")).unwrap();
        std::os::unix::fs::symlink(real.path(), prefix.path().join("share/xtrace/packs/java"))
            .unwrap();
        assert!(locate(&prefix.path().join("bin/xtrace"), "java").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_invocation_path_resolves_to_the_real_prefix() {
        let prefix = prefix_with(&[]);
        std::fs::create_dir_all(prefix.path().join("bin")).unwrap();
        let real = prefix.path().join("bin/xtrace");
        std::fs::write(&real, "x").unwrap();
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        std::fs::create_dir_all(elsewhere.path().join("bin")).unwrap();
        let link = elsewhere.path().join("bin/xtrace");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let root = packs_root_for_executable(&link).expect("root");
        assert_eq!(
            root,
            prefix.path().canonicalize().unwrap().join("share").join("xtrace").join("packs")
        );
    }

    #[test]
    fn executable_without_a_prefix_has_no_pack_root() {
        assert!(packs_root_for_executable(Path::new("xtrace")).is_none());
        assert_eq!(
            packs_root_for_executable(Path::new("/p/bin/xtrace")),
            Some(PathBuf::from("/p/share/xtrace/packs"))
        );
    }
}
