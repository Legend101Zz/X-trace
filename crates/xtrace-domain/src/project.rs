//! Project aggregate.
//!
//! A project is the durable identity of a repository under X-trace. It
//! is keyed by a content-derived fingerprint so a repository can move
//! across paths or clones without losing its catalog and run history.
//!
//! The project aggregate is intentionally tiny in Slice 1A: it stores
//! identity, creation time, and a reference to the active policies. It
//! does not own the catalog revisions, runs, or recordings that hang
//! off it; those are addressed by their own aggregate roots.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::ids::{PolicyId, ProjectId};
use crate::time::WallTime;

/// A `ContentHash`-derived fingerprint of the repository root.
///
/// Slice 1A derives the fingerprint from the canonical absolute path of
/// the repository root. A future slice will replace this with a
/// content-derived identity so moves across paths or clones continue to
/// resolve to the same project.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryFingerprint(String);

impl RepositoryFingerprint {
    /// Constructs a fingerprint from a canonical repository path.
    #[must_use]
    pub fn from_canonical_path(path: &str) -> Self {
        Self(ContentHash::of_bytes(path.as_bytes()).to_canonical())
    }

    /// Constructs a fingerprint from an already-canonical form.
    ///
    /// The input must be the exact `b3:<64 lowercase hex>` form
    /// produced by [`ContentHash::to_canonical`]. The constructor
    /// validates the prefix, length, and encoding so storage layers
    /// cannot accept corrupted rows. Use
    /// [`RepositoryFingerprint::from_canonical_path`] when deriving
    /// from a path; use this constructor only when reading a stored
    /// value back from disk.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintParseError`] when the input does not
    /// match the canonical form. Callers translate the error into a
    /// [`crate::AppError`] (typically
    /// [`crate::ErrorCategory::Corruption`]) at the port boundary.
    pub fn try_from_canonical(text: &str) -> Result<Self, FingerprintParseError> {
        // `ContentHash::from_str` validates the `b3:` prefix and the
        // 32-byte (64-hex-character) length. We additionally enforce
        // lowercase hex so two stored fingerprints that differ only
        // in case collide on `Ord` and `Hash`, which keeps the
        // canonical-form invariant honest.
        let hash = ContentHash::from_str(text)?;
        let canonical = hash.to_canonical();
        if canonical != text {
            return Err(FingerprintParseError::NonCanonical);
        }
        Ok(Self(canonical))
    }

    /// Returns the underlying canonical string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RepositoryFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepositoryFingerprint({})", self.0)
    }
}

impl fmt::Display for RepositoryFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.strip_prefix("b3:").unwrap_or(&self.0))
    }
}

/// Errors raised when parsing a [`RepositoryFingerprint`] from a
/// stored canonical form.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintParseError {
    /// The stored value is not a `b3:...` content hash.
    #[error("fingerprint must start with 'b3:'")]
    Prefix,
    /// The stored value has the wrong number of hex characters.
    #[error("fingerprint must encode 32 bytes")]
    Length,
    /// The stored value uses non-hex characters.
    #[error("invalid hex encoding: {0}")]
    Hex(String),
    /// The stored value decodes correctly but does not match the
    /// lowercase canonical encoding. This usually indicates a row
    /// produced by an older binary that wrote uppercase hex.
    #[error("fingerprint is not in lowercase canonical form")]
    NonCanonical,
}

impl From<crate::hash::HashParseError> for FingerprintParseError {
    fn from(err: crate::hash::HashParseError) -> Self {
        match err {
            crate::hash::HashParseError::Prefix => Self::Prefix,
            crate::hash::HashParseError::Length => Self::Length,
            crate::hash::HashParseError::Hex(message) => Self::Hex(message),
        }
    }
}

impl FromStr for RepositoryFingerprint {
    type Err = FingerprintParseError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from_canonical(text)
    }
}

/// Project aggregate root.
///
/// A project is created once per repository through `xtrace init` and
/// persisted as a single row in the `projects` table. The aggregate is
/// loaded by ID or by fingerprint and never copied across threads.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// Stable identifier.
    pub id: ProjectId,
    /// Canonical repository fingerprint.
    pub canonical_repo_hash: RepositoryFingerprint,
    /// Display name shown in the TUI and web viewer.
    pub display_name: String,
    /// Wall-clock time the project was first created.
    pub created_at: WallTime,
    /// Wall-clock time the project was last opened. Updated every time
    /// `xtrace open` succeeds so a cold start can detect abandoned work.
    pub last_opened_at: WallTime,
    /// Configuration schema version the project's `effective_config`
    /// was rendered against.
    pub config_schema_version: u32,
    /// Hash of the project's effective configuration. Stored alongside
    /// every run so future policy changes can be diffed.
    pub effective_config_hash: String,
    /// Active capture policy reference, if any.
    pub active_capture_policy_id: Option<PolicyId>,
    /// Active redaction policy reference, if any.
    pub active_redaction_policy_id: Option<PolicyId>,
}

impl Project {
    /// Returns the project's stable identifier.
    #[must_use]
    pub const fn id(&self) -> ProjectId {
        self.id
    }
}

impl fmt::Debug for Project {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Project")
            .field("id", &self.id)
            .field("canonical_repo_hash", &self.canonical_repo_hash)
            .field("display_name", &self.display_name)
            .field("created_at", &self.created_at)
            .field("last_opened_at", &self.last_opened_at)
            .field("config_schema_version", &self.config_schema_version)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_for_same_path() {
        let a = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        let b = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_differs_for_different_paths() {
        let a = RepositoryFingerprint::from_canonical_path("/tmp/repo-a");
        let b = RepositoryFingerprint::from_canonical_path("/tmp/repo-b");
        assert_ne!(a, b);
    }

    #[test]
    fn from_canonical_path_round_trips_through_try_from_canonical() {
        let fp = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        let parsed = RepositoryFingerprint::try_from_canonical(fp.as_str())
            .expect("from_canonical_path produces canonical form");
        assert_eq!(parsed, fp);
    }

    #[test]
    fn try_from_canonical_rejects_non_canonical_form() {
        let valid = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        let canonical = valid.as_str();
        // Keep the `b3:` prefix lowercase but uppercase the hex
        // body so the length and prefix validation pass while the
        // canonical-form check rejects the input.
        let (prefix, body) = canonical.split_at(3);
        let upper_body = body.to_ascii_uppercase();
        let mut upper = String::with_capacity(prefix.len() + upper_body.len());
        upper.push_str(prefix);
        upper.push_str(&upper_body);
        assert_ne!(upper, canonical);
        let err = RepositoryFingerprint::try_from_canonical(&upper).unwrap_err();
        assert!(matches!(err, FingerprintParseError::NonCanonical));
    }

    #[test]
    fn try_from_canonical_rejects_missing_prefix() {
        let fp = RepositoryFingerprint::from_canonical_path("/tmp/repo");
        let body = &fp.as_str()[3..];
        let err = RepositoryFingerprint::try_from_canonical(body).unwrap_err();
        assert!(matches!(err, FingerprintParseError::Prefix));
    }

    #[test]
    fn try_from_canonical_rejects_short_input() {
        let err = RepositoryFingerprint::try_from_canonical("b3:deadbeef").unwrap_err();
        assert!(matches!(err, FingerprintParseError::Length));
    }

    #[test]
    fn try_from_canonical_rejects_non_hex() {
        let err = RepositoryFingerprint::try_from_canonical(&format!("b3:{}", "z".repeat(64)))
            .unwrap_err();
        assert!(matches!(err, FingerprintParseError::Hex(_)));
    }
}
