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

use serde::{Deserialize, Serialize};

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
        Self(crate::hash::ContentHash::of_bytes(path.as_bytes()).to_canonical())
    }

    /// Constructs a fingerprint from an already-canonical form.
    ///
    /// The input is assumed to be a `ContentHash` canonical string
    /// (e.g. `b3:<hex>`). Storage layers call this when reading a
    /// stored fingerprint from disk; passing a non-canonical form
    /// will be detected by readers that validate the prefix.
    #[must_use]
    pub fn from_canonical(text: &str) -> Self {
        Self(text.to_string())
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
}
