//! Shared adapter from application catalog reads to the deterministic exporter.
//!
//! The caller owns project admission, reads and snapshot policy. This module performs no SQL,
//! filesystem, network or command execution. Its application dependency points inward: both
//! CLI and viewer adapters can use the same conversion without depending on each other.

use std::collections::BTreeSet;

use xtrace_application::CatalogChangeKind;
use xtrace_application::catalog_discovery::history::{
    ObservedOperation, OperationView, RevisionEntry,
};

use crate::{
    ClaimInput, EffectiveState, ExportError, ExportInput, ExportOutput, ExportRequest,
    OperationInput, RevisionInput,
};

type OperationIdentity = (String, String, String, String);

fn state_of(view: &OperationView, confirmed: &BTreeSet<OperationIdentity>) -> EffectiveState {
    if view.change_kind == CatalogChangeKind::Unknown {
        return EffectiveState::Unknown;
    }
    if confirmed.contains(&(
        view.application_component.clone(),
        view.binding_key.clone(),
        view.method.clone(),
        view.route_template.clone(),
    )) {
        return EffectiveState::Observed;
    }
    if view.provenance.iter().all(|p| p == "static_inferred") {
        EffectiveState::StaticOnly
    } else {
        EffectiveState::Registered
    }
}

fn operation_input(
    view: &OperationView,
    confirmed: &BTreeSet<OperationIdentity>,
) -> OperationInput {
    let operation_id = serde_json::to_value(view.operation_id)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    OperationInput {
        operation_id,
        method: view.method.clone(),
        route_template: view.route_template.clone(),
        application_component: view.application_component.clone(),
        binding_key: view.binding_key.clone(),
        effective_state: state_of(view, confirmed),
        claims_available: view.claims_available,
        claims: view
            .claims
            .iter()
            .map(|claim| ClaimInput {
                claim_id: claim.claim_id.to_string(),
                provenance: claim.provenance.clone(),
                handler_symbol: claim.handler_symbol.clone(),
                confidence_basis_points: claim.confidence_basis_points,
                limitation_codes: claim.limitation_codes.clone(),
                empty_limitations_reported: claim.limitation_codes.is_empty(),
                source_evidence: Some(claim.source_evidence.clone()),
                ..ClaimInput::default()
            })
            .collect(),
        catalog_summary: None,
    }
}

/// Converts already-read catalog and linked-observation facts into renderer input.
///
/// Both inputs must belong to the same project. No snapshot consistency is implied: the CLI
/// currently reads linked observations separately from its immutable catalog revision. A caller
/// binding preview to save must compare the rendered content digest, not only the revision id.
/// Observed state requires a positive linked count and an exact component/binding/method/route
/// match; unknown revision entries remain unknown even when that identity was observed.
#[must_use]
pub fn prepare(
    entry: &RevisionEntry,
    views: &[OperationView],
    observed: &[ObservedOperation],
) -> ExportInput {
    let confirmed: BTreeSet<OperationIdentity> = observed
        .iter()
        .filter(|row| row.recording_count > 0)
        .map(|row| {
            (
                row.application_component.clone(),
                row.binding_key.clone(),
                row.method.clone(),
                row.route_template.clone(),
            )
        })
        .collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.export.catalog.v1\0");
    let mut identities: Vec<String> = views
        .iter()
        .map(|v| {
            format!(
                "{}\0{}\0{}\0{}\0{}",
                v.method,
                v.route_template,
                v.application_component,
                v.binding_key,
                v.operation_version_id
            )
        })
        .collect();
    identities.sort();
    for identity in &identities {
        hasher.update(identity.as_bytes());
        hasher.update(b"\n");
    }
    let components: BTreeSet<&str> =
        views.iter().map(|v| v.application_component.as_str()).collect();
    let application_name = match components.iter().collect::<Vec<_>>().as_slice() {
        [one] => (**one).to_owned(),
        _ => String::new(),
    };
    ExportInput {
        revision: RevisionInput {
            revision_id: entry.revision_id.to_string(),
            ordinal: entry.ordinal,
            catalog_hash: hasher.finalize().to_hex().to_string(),
            policy_digest: String::new(),
            application_name,
        },
        operations: views.iter().map(|v| operation_input(v, &confirmed)).collect(),
        truncated: false,
    }
}

/// Failure while selecting and rendering an already-read catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogExportError {
    /// First requested operation id absent from the input, in request order.
    OperationNotFound {
        /// Requested id; callers must not echo unvalidated input in diagnostics.
        operation_id: String,
    },
    /// The pure renderer rejected the document. Adapter diagnostics must not echo offender paths.
    Render(ExportError),
}

/// Validates selection before invoking the pure renderer.
///
/// Selection matches stable operation ids, never route text. `None` selects all operations;
/// an explicitly empty selection stays empty. Duplicate requested ids keep the renderer's set
/// semantics. The CLI converts its absent/repeated argument form before calling this function.
///
/// # Errors
/// Returns the first missing requested id before rendering, or the unchanged renderer failure.
pub fn render(
    input: &ExportInput,
    request: &ExportRequest,
) -> Result<ExportOutput, CatalogExportError> {
    if let Some(selection) = &request.operation_ids {
        let known: BTreeSet<&str> =
            input.operations.iter().map(|operation| operation.operation_id.as_str()).collect();
        if let Some(missing) = selection.iter().find(|id| !known.contains(id.as_str())) {
            return Err(CatalogExportError::OperationNotFound { operation_id: missing.clone() });
        }
    }
    crate::export(input, request).map_err(CatalogExportError::Render)
}
