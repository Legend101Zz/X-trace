//! Catalog read services for the CLI (and the viewer routes C adds): revision history, runs,
//! operations with their claims, revision diff, conflicts and reconciliation with observed
//! recordings.
//!
//! These are application services over [`CatalogHistoryPort`]; the SQL lives in the store crate.
//! Nothing here writes. Removal is never inferred: an operation that an earlier revision had and
//! a later scan did not see is reported as `unknown` (the store never records `removed` from the
//! absence of a static claim).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use xtrace_domain::catalog_reconcile::{
    ObservedEndpoint, Reconciliation, StaticEndpoint, reconcile,
};
use xtrace_domain::{
    CatalogRevisionId, ContentHash, OperationId, ProjectId, RunId, SourceRevisionId,
};

use super::{CatalogChangeKind, CatalogSourceAvailability};
use crate::error::PortError;

/// Largest operation list one revision read returns (the revision cap).
pub const MAX_REVISION_OPERATIONS: usize = 4096;

/// One immutable catalog revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionEntry {
    /// Revision identity.
    pub revision_id: CatalogRevisionId,
    /// Position within its scope, starting at 1.
    pub ordinal: u32,
    /// Previous revision of the same scope.
    pub parent_revision_id: Option<CatalogRevisionId>,
    /// Stable scope identity.
    pub scope_digest: ContentHash,
    /// Source snapshot the scan pinned.
    pub source_revision_id: Option<SourceRevisionId>,
    /// Entries in the revision (including carried-forward `unknown` ones).
    pub operation_count: u32,
    /// Run that produced it.
    pub run_id: RunId,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Always `complete`: only complete runs publish a revision.
    pub completion: &'static str,
    /// Always `dev_unsigned` in this build.
    pub pack_status: &'static str,
}

/// One discovery run, whether or not it produced a revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunEntry {
    /// Run identity.
    pub run_id: RunId,
    /// `open`, `complete`, `incomplete`, `failed`, `invalid` or `superseded`.
    pub status: String,
    /// Stable scope identity.
    pub scope_digest: ContentHash,
    /// Claims the run accepted.
    pub accepted_claims: u32,
    /// Claims the run rejected.
    pub rejected_claims: u32,
    /// Declared gap codes.
    pub limitation_codes: Vec<String>,
    /// Revision it published, when complete.
    pub revision_id: Option<CatalogRevisionId>,
}

/// One operation of a revision with the claims behind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationView {
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Version of the operation in this revision (changes when its claims change).
    pub operation_version_id: String,
    /// Application component in the identity.
    pub application_component: String,
    /// Binding key in the identity.
    pub binding_key: String,
    /// HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
    /// Change against the preceding revision.
    pub change_kind: CatalogChangeKind,
    /// Source verification state.
    pub source_availability: CatalogSourceAvailability,
    /// Distinct claim provenance labels.
    pub provenance: Vec<String>,
    /// Highest claim confidence in basis points.
    pub confidence_basis_points: u16,
    /// Union of claim limitation codes, sorted.
    pub limitation_codes: Vec<String>,
    /// Distinct handler symbols.
    pub handlers: Vec<String>,
    /// More than one handler claims this operation.
    pub handler_conflict: bool,
    /// Number of claims in the revision.
    pub claim_count: usize,
    /// Repository-relative source file of the first claim.
    pub source_path: Option<String>,
    /// 1-based line of the first claim.
    pub source_line: Option<u32>,
}

/// An endpoint a recording matched, with the number of matching recordings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedOperation {
    /// Component of the observed identity.
    pub application_component: String,
    /// Binding key of the observed identity.
    pub binding_key: String,
    /// HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
    /// Recordings linked to it.
    pub recording_count: usize,
}

/// Read port the store implements.
pub trait CatalogHistoryPort: Send + Sync {
    /// Revisions of a project, newest first, at most `limit`.
    fn list_revisions(
        &self,
        project_id: ProjectId,
        limit: u32,
    ) -> Result<Vec<RevisionEntry>, PortError>;
    /// Runs of a project, newest first, at most `limit`.
    fn list_runs(&self, project_id: ProjectId, limit: u32) -> Result<Vec<RunEntry>, PortError>;
    /// One revision, `None` when it does not exist in the project.
    fn revision(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
    ) -> Result<Option<RevisionEntry>, PortError>;
    /// The run's record, `None` when it does not exist in the project.
    fn run(&self, project_id: ProjectId, run_id: RunId) -> Result<Option<RunEntry>, PortError>;
    /// All entries of a revision, ordered by route, method, component, binding, id.
    fn revision_operations(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
    ) -> Result<Vec<OperationView>, PortError>;
    /// Endpoints with at least one linked recording, from the observed-operation tables.
    fn observed_operations(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ObservedOperation>, PortError>;
}

/// Error of a catalog read service.
#[derive(Debug)]
pub enum HistoryError {
    /// The revision does not exist in this project.
    RevisionNotFound,
    /// The project has no revision yet.
    NoRevisions,
    /// Two revisions of different scopes cannot be compared.
    ScopeMismatch,
    /// Persistence failed.
    Port(PortError),
}

impl From<PortError> for HistoryError {
    fn from(error: PortError) -> Self {
        Self::Port(error)
    }
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionNotFound => f.write_str("catalog revision not found"),
            Self::NoRevisions => f.write_str("no catalog revision exists yet; run `xtrace scan`"),
            Self::ScopeMismatch => {
                f.write_str("the revisions cover different scopes and cannot be compared")
            }
            Self::Port(error) => write!(f, "catalog read failed: {}", error.message()),
        }
    }
}

impl std::error::Error for HistoryError {}

/// One operation in a revision diff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntry {
    /// `added`, `changed`, `unchanged` or `unknown` (seen in `from`, not in `to`).
    pub change: CatalogChangeKind,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
}

/// Difference between two revisions of one scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionDiff {
    /// Older side.
    pub from: CatalogRevisionId,
    /// Newer side.
    pub to: CatalogRevisionId,
    /// Counts per change label.
    pub counts: BTreeMap<String, usize>,
    /// Every operation whose label is not `unchanged`, ordered by route then method.
    pub entries: Vec<DiffEntry>,
    /// Why nothing is ever labelled `removed` here.
    pub note: &'static str,
}

/// A handler conflict inside one revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictEntry {
    /// Kind of conflict (`handler_conflict`).
    pub kind: &'static str,
    /// Operation involved.
    pub operation_id: OperationId,
    /// HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
    /// Handler symbols that claim the operation.
    pub handlers: Vec<String>,
}

/// Static claims reconciled with runtime observations for one revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionReconciliation {
    /// Revision the static side comes from.
    pub revision_id: CatalogRevisionId,
    /// Static operations linked to at least one recording.
    pub confirmed: usize,
    /// Static operations with no recording (unobserved).
    pub unobserved: usize,
    /// Observed endpoints the revision does not declare (undeclared).
    pub undeclared: usize,
    /// Static operations whose identity is a guess and so are not matched.
    pub unresolved: usize,
    /// Rows, ordered by route, method.
    pub reconciliation: Reconciliation,
    /// Honest scope statement.
    pub note: &'static str,
}

/// Catalog read service.
pub struct CatalogHistoryService<P> {
    port: P,
}

impl<P: CatalogHistoryPort> CatalogHistoryService<P> {
    /// Wraps a port.
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Revisions, newest first.
    pub fn history(
        &self,
        project: ProjectId,
        limit: u32,
    ) -> Result<Vec<RevisionEntry>, HistoryError> {
        Ok(self.port.list_revisions(project, limit.clamp(1, 200))?)
    }

    /// Runs, newest first.
    pub fn runs(&self, project: ProjectId, limit: u32) -> Result<Vec<RunEntry>, HistoryError> {
        Ok(self.port.list_runs(project, limit.clamp(1, 200))?)
    }

    /// Newest revision of the project.
    pub fn latest(&self, project: ProjectId) -> Result<RevisionEntry, HistoryError> {
        self.port.list_revisions(project, 1)?.into_iter().next().ok_or(HistoryError::NoRevisions)
    }

    /// Resolves an explicit id or the newest revision.
    pub fn resolve(
        &self,
        project: ProjectId,
        revision: Option<CatalogRevisionId>,
    ) -> Result<RevisionEntry, HistoryError> {
        match revision {
            None => self.latest(project),
            Some(id) => self.port.revision(project, id)?.ok_or(HistoryError::RevisionNotFound),
        }
    }

    /// Operations of a revision (newest when `revision` is `None`).
    pub fn operations(
        &self,
        project: ProjectId,
        revision: Option<CatalogRevisionId>,
    ) -> Result<(RevisionEntry, Vec<OperationView>), HistoryError> {
        let entry = self.resolve(project, revision)?;
        let operations = self.port.revision_operations(project, entry.revision_id)?;
        Ok((entry, operations))
    }

    /// Diff `from` -> `to`. Defaults: `to` = newest revision, `from` = its parent.
    pub fn diff(
        &self,
        project: ProjectId,
        from: Option<CatalogRevisionId>,
        to: Option<CatalogRevisionId>,
    ) -> Result<RevisionDiff, HistoryError> {
        let newer = self.resolve(project, to)?;
        let older = match from {
            Some(id) => self.resolve(project, Some(id))?,
            None => match newer.parent_revision_id {
                Some(parent) => self.resolve(project, Some(parent))?,
                None => {
                    // The first revision: everything in it is `added` against nothing.
                    return self.first_revision_diff(project, &newer);
                }
            },
        };
        if older.scope_digest != newer.scope_digest {
            return Err(HistoryError::ScopeMismatch);
        }
        let before = self.port.revision_operations(project, older.revision_id)?;
        let after = self.port.revision_operations(project, newer.revision_id)?;
        Ok(diff_operations(older.revision_id, newer.revision_id, &before, &after))
    }

    fn first_revision_diff(
        &self,
        project: ProjectId,
        newer: &RevisionEntry,
    ) -> Result<RevisionDiff, HistoryError> {
        let after = self.port.revision_operations(project, newer.revision_id)?;
        Ok(diff_operations(newer.revision_id, newer.revision_id, &[], &after))
    }

    /// Handler conflicts of a revision.
    pub fn conflicts(
        &self,
        project: ProjectId,
        revision: Option<CatalogRevisionId>,
    ) -> Result<(RevisionEntry, Vec<ConflictEntry>), HistoryError> {
        let (entry, operations) = self.operations(project, revision)?;
        let conflicts = operations
            .iter()
            .filter(|operation| operation.handler_conflict)
            .map(|operation| ConflictEntry {
                kind: "handler_conflict",
                operation_id: operation.operation_id,
                method: operation.method.clone(),
                route_template: operation.route_template.clone(),
                handlers: operation.handlers.clone(),
            })
            .collect();
        Ok((entry, conflicts))
    }

    /// Reconciles a revision with the endpoints recordings were linked to.
    pub fn reconcile_with_observations(
        &self,
        project: ProjectId,
        revision: Option<CatalogRevisionId>,
    ) -> Result<RevisionReconciliation, HistoryError> {
        let (entry, operations) = self.operations(project, revision)?;
        let observed = self.port.observed_operations(project)?;
        Ok(reconcile_revision(entry.revision_id, &operations, &observed))
    }
}

/// Pure reconciliation of one revision's operations with observed operations. Only operations
/// scanned in this revision count as declared (carried-forward `unknown` entries were not seen
/// by the latest scan and are left out), and observed endpoints are restricted to the same
/// application component and binding key as the scanned operations.
#[must_use]
pub fn reconcile_revision(
    revision_id: CatalogRevisionId,
    operations: &[OperationView],
    observed: &[ObservedOperation],
) -> RevisionReconciliation {
    let scanned: Vec<&OperationView> =
        operations.iter().filter(|op| op.change_kind != CatalogChangeKind::Unknown).collect();
    let scopes: BTreeSet<(&str, &str)> = scanned
        .iter()
        .map(|op| (op.application_component.as_str(), op.binding_key.as_str()))
        .collect();
    let statics: Vec<StaticEndpoint> = scanned
        .iter()
        .map(|op| StaticEndpoint {
            method: op.method.clone(),
            route_template: op.route_template.clone(),
            confidence_basis_points: u32::from(op.confidence_basis_points),
            limitation_codes: op.limitation_codes.clone(),
        })
        .collect();
    let observed: Vec<ObservedEndpoint> = observed
        .iter()
        .filter(|op| scopes.contains(&(op.application_component.as_str(), op.binding_key.as_str())))
        .map(|op| ObservedEndpoint {
            method: op.method.clone(),
            route_template: op.route_template.clone(),
            recording_count: op.recording_count,
        })
        .collect();
    let reconciliation = reconcile(&statics, &observed);
    use xtrace_domain::catalog_reconcile::ReconcileStatus as S;
    RevisionReconciliation {
        revision_id,
        confirmed: reconciliation.count(S::Confirmed),
        unobserved: reconciliation.count(S::StaticOnly),
        undeclared: reconciliation.count(S::ObservedOnly),
        unresolved: reconciliation.count(S::StaticUnresolved),
        reconciliation,
        note: "recordings are linked to operations by the runtime classifier; historical \
               recordings are never re-linked, so an endpoint recorded before it was classified \
               counts as undeclared/unobserved here",
    }
}

fn diff_operations(
    from: CatalogRevisionId,
    to: CatalogRevisionId,
    before: &[OperationView],
    after: &[OperationView],
) -> RevisionDiff {
    let old: BTreeMap<OperationId, &OperationView> =
        before.iter().map(|op| (op.operation_id, op)).collect();
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for op in after {
        seen.insert(op.operation_id);
        let change = match old.get(&op.operation_id) {
            None => CatalogChangeKind::Added,
            // Carried forward without being seen by the newer scan.
            Some(_) if op.change_kind == CatalogChangeKind::Unknown => CatalogChangeKind::Unknown,
            Some(previous) if previous.operation_version_id == op.operation_version_id => {
                CatalogChangeKind::Unchanged
            }
            Some(_) => CatalogChangeKind::Changed,
        };
        entries.push(DiffEntry {
            change,
            operation_id: op.operation_id,
            method: op.method.clone(),
            route_template: op.route_template.clone(),
        });
    }
    for op in before {
        if !seen.contains(&op.operation_id) {
            entries.push(DiffEntry {
                change: CatalogChangeKind::Unknown,
                operation_id: op.operation_id,
                method: op.method.clone(),
                route_template: op.route_template.clone(),
            });
        }
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &entries {
        *counts.entry(entry.change.as_str().to_owned()).or_default() += 1;
    }
    entries.retain(|entry| entry.change != CatalogChangeKind::Unchanged);
    entries.sort_by(|a, b| {
        (&a.route_template, &a.method, a.operation_id).cmp(&(
            &b.route_template,
            &b.method,
            b.operation_id,
        ))
    });
    RevisionDiff {
        from,
        to,
        counts,
        entries,
        note: "absence from a static scan is reported as unknown, never as removed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xtrace_domain::ids::Id as _;

    fn view(
        id: u128,
        method: &str,
        route: &str,
        version: &str,
        kind: CatalogChangeKind,
    ) -> OperationView {
        OperationView {
            operation_id: OperationId::from_uuid(uuid::Uuid::from_u128(id)),
            operation_version_id: version.to_owned(),
            application_component: "app".into(),
            binding_key: "default".into(),
            method: method.into(),
            route_template: route.into(),
            change_kind: kind,
            source_availability: CatalogSourceAvailability::Unverified,
            provenance: vec!["static_inferred".into()],
            confidence_basis_points: 9000,
            limitation_codes: Vec::new(),
            handlers: vec!["h".into()],
            handler_conflict: false,
            claim_count: 1,
            source_path: None,
            source_line: None,
        }
    }

    fn rev() -> CatalogRevisionId {
        CatalogRevisionId::new()
    }

    #[test]
    fn diff_labels_added_changed_unchanged_and_never_removed() {
        use CatalogChangeKind as K;
        let before = vec![
            view(1, "GET", "/a", "v1", K::Added),
            view(2, "GET", "/b", "v1", K::Added),
            view(3, "GET", "/gone", "v1", K::Added),
        ];
        let after = vec![
            view(1, "GET", "/a", "v1", K::Unchanged),
            view(2, "GET", "/b", "v2", K::Changed),
            view(4, "POST", "/new", "v1", K::Added),
        ];
        let diff = diff_operations(rev(), rev(), &before, &after);
        assert_eq!(diff.counts.get("unchanged"), Some(&1));
        assert_eq!(diff.counts.get("changed"), Some(&1));
        assert_eq!(diff.counts.get("added"), Some(&1));
        assert_eq!(diff.counts.get("unknown"), Some(&1));
        assert!(!diff.counts.contains_key("removed"));
        assert!(diff.entries.iter().all(|entry| entry.change != K::Unchanged));
        assert!(diff.entries.iter().any(|e| e.route_template == "/gone" && e.change == K::Unknown));
    }

    #[test]
    fn reconcile_ignores_carried_forward_and_foreign_component_observations() {
        use CatalogChangeKind as K;
        let ops = vec![
            view(1, "POST", "/orders", "v1", K::Added),
            view(2, "GET", "/pets", "v1", K::Added),
            view(3, "GET", "/old", "v1", K::Unknown),
        ];
        let observed = vec![
            ObservedOperation {
                application_component: "app".into(),
                binding_key: "default".into(),
                method: "POST".into(),
                route_template: "/orders".into(),
                recording_count: 3,
            },
            ObservedOperation {
                application_component: "app".into(),
                binding_key: "default".into(),
                method: "GET".into(),
                route_template: "/undeclared".into(),
                recording_count: 1,
            },
            ObservedOperation {
                application_component: "other".into(),
                binding_key: "default".into(),
                method: "GET".into(),
                route_template: "/pets".into(),
                recording_count: 9,
            },
        ];
        let result = reconcile_revision(rev(), &ops, &observed);
        assert_eq!((result.confirmed, result.unobserved, result.undeclared), (1, 1, 1));
        assert!(result.reconciliation.rows.iter().all(|row| row.route_template != "/old"));
    }
}
