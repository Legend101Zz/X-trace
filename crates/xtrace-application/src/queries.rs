//! Query types and their results.
//!
//! Queries are read-only projections. They never mutate state and
//! return [`QueryResult`] values that are safe to serialize as
//! machine-readable output.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use xtrace_domain::{Project, ProjectId, RepositoryFingerprint};

use crate::commands::ProjectSnapshot;

/// Fetch the project for a repository by its canonical path.
#[derive(Clone, Debug)]
pub struct GetProject {
    /// Canonical absolute path of the repository root.
    pub canonical_repo_path: String,
}

/// Fetch a machine-readable status report for the local store.
///
/// The report is the truthful spine view: it lists the schema version,
/// the project(s) registered, and explicitly states that no capture or
/// replay capability is wired in Slice 1A.
#[derive(Clone, Copy, Debug)]
pub struct GetStoreStatus;

/// Coarse capability summary for a Slice. Truthful reporting means
/// listing only the surfaces actually implemented in this build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Schema version this binary initializes a fresh store with.
    pub store_schema_version: u32,
    /// XTP-Agent protocol major version this binary speaks.
    pub protocol_major: u32,
    /// XTP-Agent protocol minor version this binary speaks.
    pub protocol_minor: u32,
    /// Capture/replay is intentionally not wired in Slice 1A.
    pub capture_supported: bool,
    /// Replay is intentionally not wired in Slice 1A.
    pub replay_supported: bool,
}

/// One row per project known to the local store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectStatus {
    /// Stable project identifier.
    pub project_id: ProjectId,
    /// Canonical repository fingerprint.
    pub fingerprint: RepositoryFingerprint,
    /// Display name supplied at initialization.
    pub display_name: String,
    /// Wall-clock time the project was first registered.
    pub created_at: String,
    /// Wall-clock time the project was most recently opened.
    pub last_opened_at: String,
}

/// Machine-readable status report returned by [`GetStoreStatus`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreStatusReport {
    /// Capability summary for this build.
    pub capabilities: CapabilityReport,
    /// Schema version actually present in the local store.
    pub current_schema_version: u32,
    /// Schema version this binary would apply on a fresh store.
    pub target_schema_version: u32,
    /// One row per registered project.
    pub projects: Vec<ProjectStatus>,
    /// Free-form, stable diagnostic labels.
    pub diagnostics: BTreeMap<String, String>,
}

/// Queries accepted by [`Application::query`].
///
/// [`Application::query`]: crate::application::Application::query
#[derive(Clone, Debug)]
pub enum Query {
    /// Fetch a hydrated project by its canonical repository path.
    GetProject(GetProject),
    /// Fetch the local store status report.
    GetStoreStatus(GetStoreStatus),
}

/// Query results. Variants mirror [`Query`] and stay in lockstep so a
/// new query automatically gets a new result variant.
#[derive(Clone, Debug)]
pub enum QueryResult {
    /// Result of [`Query::GetProject`].
    Project(ProjectSnapshot),
    /// Result of [`Query::GetStoreStatus`].
    StoreStatus(StoreStatusReport),
}

impl QueryResult {
    /// Renders the result into a stable, machine-readable JSON
    /// representation.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when serialization fails. Callers
    /// must surface the error rather than substitute a degraded form
    /// because the CLI promises truthful machine-readable output.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Project(snapshot) => serde_json::to_string_pretty(snapshot),
            Self::StoreStatus(report) => serde_json::to_string_pretty(report),
        }
    }
}

impl ProjectSnapshot {
    /// Constructs a snapshot from a hydrated project aggregate.
    #[must_use]
    pub const fn new(project: Project) -> Self {
        Self { project }
    }
}
