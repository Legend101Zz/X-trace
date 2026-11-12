//! Order-independent, sanitized view of the input that every format renders.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use xtrace_domain::catalog_discovery::ClaimSourceEvidence;

use crate::request::{
    CatalogSummaryInput, ClaimInput, EffectiveState, ExampleOrigin, ExportInput, ExportRequest,
    HandlerInput, Omission, OperationInput, RevisionInput,
};
use crate::sanitize;

const MAX_LEGACY_HANDLER_SYMBOL_BYTES: usize = 200;
// ValidatedEndpointClaim's bound for a recorded handler symbol.
const MAX_CLAIM_HANDLER_SYMBOL_BYTES: usize = 512;

/// A disagreement between claims that is reported, never merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conflict {
    /// `param_type` or `response_description`.
    pub kind: &'static str,
    /// Subject (`query:page`, `200`).
    pub subject: String,
    /// `(claim_id, value)` pairs, sorted.
    pub values: Vec<(String, String)>,
}

/// A merged parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedParam {
    /// Name.
    pub name: String,
    /// Location.
    pub location: String,
    /// Agreed type, `None` when unknown or conflicting.
    pub type_name: Option<String>,
    /// Required (always true for path parameters).
    pub required: bool,
}

/// A merged response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedResponse {
    /// Status text.
    pub status: String,
    /// Agreed description, `None` when empty or conflicting.
    pub description: Option<String>,
}

/// A kept example.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreparedExample {
    /// Target (`request_body` or `param:<name>`).
    pub target: String,
    /// Label.
    pub label: String,
    /// Origin name.
    pub origin: &'static str,
    /// Value text.
    pub value: String,
}

/// One operation ready to render.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedOp {
    /// Operation id.
    pub operation_id: String,
    /// Upper-case method.
    pub method: String,
    /// Normalised `{param}` path template.
    pub path: String,
    /// Component.
    pub component: String,
    /// Binding key.
    pub binding_key: String,
    /// Effective state.
    pub state: EffectiveState,
    /// Claims projection available.
    pub claims_available: bool,
    /// Merged parameters sorted by (location, name).
    pub params: Vec<PreparedParam>,
    /// Merged responses sorted by status.
    pub responses: Vec<PreparedResponse>,
    /// Kept examples, sorted.
    pub examples: Vec<PreparedExample>,
    /// Provenance labels, sorted unique.
    pub provenance: Vec<String>,
    /// Lowest reported confidence for legacy-only claims.
    pub confidence_bp: Option<u16>,
    /// Limitation codes, sorted unique.
    pub limitation_codes: Vec<String>,
    /// Conflicts.
    pub conflicts: Vec<Conflict>,
    /// Handlers sorted by (path, line, symbol).
    pub handlers: Vec<HandlerInput>,
    /// Request body media type, when any claim declares one.
    pub request_media: Option<String>,
    /// Aggregate catalog facts, kept separate from individual claims.
    pub catalog_summary: Option<CatalogSummaryInput>,
    /// Per-claim metadata after checking source paths and handler symbols.
    claim_metadata: Option<Value>,
}

/// The whole prepared export.
#[derive(Clone, Debug, PartialEq)]
pub struct Prepared {
    /// Revision.
    pub revision: RevisionInput,
    /// Operations in canonical order.
    pub ops: Vec<PreparedOp>,
    /// Omissions, sorted unique.
    pub omissions: Vec<Omission>,
    /// YAML requested.
    pub yaml: bool,
}

/// Method ordering used everywhere.
#[must_use]
pub fn method_rank(method: &str) -> u8 {
    match method {
        "GET" => 0,
        "HEAD" => 1,
        "POST" => 2,
        "PUT" => 3,
        "PATCH" => 4,
        "DELETE" => 5,
        "OPTIONS" => 6,
        "TRACE" => 7,
        _ => 8,
    }
}

/// Safe (non-mutating) methods per RFC 9110.
#[must_use]
pub fn is_safe_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// Rewrites `:id` segments to `{id}` and returns the template.
#[must_use]
pub fn normalize_path(template: &str) -> String {
    let body = template
        .split('/')
        .map(|seg| match seg.strip_prefix(':') {
            Some(name) if !name.is_empty() => format!("{{{name}}}"),
            _ => seg.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/");
    if body.starts_with('/') { body } else { format!("/{body}") }
}

/// Names of `{param}` segments in a template, in order.
#[must_use]
pub fn path_param_names(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        let name = &after[..close];
        if !name.is_empty() && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
        rest = &after[close + 1..];
    }
    names
}

fn canonical_key(op: &PreparedOp) -> (String, u8, String, String, String, String) {
    (
        op.path.clone(),
        method_rank(&op.method),
        op.method.clone(),
        op.component.clone(),
        op.binding_key.clone(),
        op.operation_id.clone(),
    )
}

/// Builds the prepared view. Pure and order-independent.
#[must_use]
pub fn prepare(input: &ExportInput, request: &ExportRequest) -> Prepared {
    let mut omissions: BTreeSet<Omission> = BTreeSet::new();
    let wanted: Option<BTreeSet<&str>> =
        request.operation_ids.as_ref().map(|ids| ids.iter().map(String::as_str).collect());
    if let Some(wanted) = &wanted {
        let have: BTreeSet<&str> =
            input.operations.iter().map(|o| o.operation_id.as_str()).collect();
        for id in wanted.difference(&have) {
            omissions.insert(Omission {
                operation_id: (*id).to_owned(),
                what: "operation".to_owned(),
                reason: "not_in_catalog_view".to_owned(),
            });
        }
    }
    if input.truncated {
        omissions.insert(Omission {
            operation_id: String::new(),
            what: "operations".to_owned(),
            reason: "catalog_view_truncated".to_owned(),
        });
    }
    let mut ops: Vec<PreparedOp> = input
        .operations
        .iter()
        .filter(|o| wanted.as_ref().is_none_or(|w| w.contains(o.operation_id.as_str())))
        .map(|o| prepare_op(o, &mut omissions))
        .collect();
    ops.sort_by_key(canonical_key);
    ops.dedup_by(|a, b| a.operation_id == b.operation_id);
    Prepared {
        revision: input.revision.clone(),
        ops,
        omissions: omissions.into_iter().collect(),
        yaml: request.yaml,
    }
}

fn example_digest(label: &str, value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(&[0]);
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex().as_str()[..8].to_owned()
}

fn omit(set: &mut BTreeSet<Omission>, op: &str, what: String, reason: &str) {
    set.insert(Omission { operation_id: op.to_owned(), what, reason: reason.to_owned() });
}

fn prepare_op(op: &OperationInput, omissions: &mut BTreeSet<Omission>) -> PreparedOp {
    let method = op.method.to_ascii_uppercase();
    let path = normalize_path(&op.route_template);
    let mut claims: Vec<_> = op.claims.iter().filter(|_| op.claims_available).collect();
    claims.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
    let claims_available =
        op.claims_available && (!claims.is_empty() || op.catalog_summary.is_none());
    if !claims_available {
        omit(omissions, &op.operation_id, "claims".to_owned(), "claims_projection_unavailable");
    }

    // parameters
    let mut types: BTreeMap<(String, String), BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    let mut required: BTreeMap<(String, String), bool> = BTreeMap::new();
    for claim in &claims {
        for p in &claim.params {
            let key = (p.location.clone(), p.name.clone());
            let slot = types.entry(key.clone()).or_default();
            slot.entry(p.type_name.clone()).or_default().insert(claim.claim_id.clone());
            *required.entry(key).or_insert(false) |= p.required;
        }
    }
    let template_params = path_param_names(&path);
    let mut conflicts = Vec::new();
    let mut params = Vec::new();
    for ((location, name), by_type) in &types {
        if location == "path" && !template_params.contains(name) {
            omit(
                omissions,
                &op.operation_id,
                format!("param:path:{name}"),
                "path_param_not_in_template",
            );
            continue;
        }
        if !matches!(location.as_str(), "path" | "query" | "header" | "cookie") {
            omit(
                omissions,
                &op.operation_id,
                format!("param:{location}:{name}"),
                "unknown_param_location",
            );
            continue;
        }
        let distinct: Vec<&String> = by_type.keys().filter(|t| !t.is_empty()).collect();
        let type_name = match distinct.as_slice() {
            [one] => Some((*one).clone()),
            [] => None,
            _ => {
                let mut values = Vec::new();
                for t in &distinct {
                    for id in &by_type[*t] {
                        values.push((id.clone(), (*t).clone()));
                    }
                }
                values.sort();
                conflicts.push(Conflict {
                    kind: "param_type",
                    subject: format!("{location}:{name}"),
                    values,
                });
                None
            }
        };
        let is_required = location == "path"
            || required.get(&(location.clone(), name.clone())).copied().unwrap_or(false);
        params.push(PreparedParam {
            name: name.clone(),
            location: location.clone(),
            type_name,
            required: is_required,
        });
    }
    for name in &template_params {
        if !params.iter().any(|p| p.location == "path" && &p.name == name) {
            params.push(PreparedParam {
                name: name.clone(),
                location: "path".to_owned(),
                type_name: None,
                required: true,
            });
        }
    }
    params.sort_by(|a, b| (&a.location, &a.name).cmp(&(&b.location, &b.name)));

    // responses
    let mut by_status: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for claim in &claims {
        for r in &claim.responses {
            by_status
                .entry(r.status.clone())
                .or_default()
                .entry(r.description.clone())
                .or_default()
                .insert(claim.claim_id.clone());
        }
    }
    let mut responses = Vec::new();
    for (status, by_desc) in &by_status {
        let distinct: Vec<&String> = by_desc.keys().filter(|d| !d.is_empty()).collect();
        let description = match distinct.as_slice() {
            [one] => Some((*one).clone()),
            [] => None,
            _ => {
                let mut values = Vec::new();
                for d in &distinct {
                    for id in &by_desc[*d] {
                        values.push((id.clone(), (*d).clone()));
                    }
                }
                values.sort();
                conflicts.push(Conflict {
                    kind: "response_description",
                    subject: status.clone(),
                    values,
                });
                None
            }
        };
        responses.push(PreparedResponse { status: status.clone(), description });
    }
    conflicts.sort_by(|a, b| (a.kind, &a.subject).cmp(&(b.kind, &b.subject)));

    // examples
    let mut examples = BTreeSet::new();
    for claim in &claims {
        for ex in &claim.examples {
            let param_secret =
                ex.target.strip_prefix("param:").is_some_and(sanitize::is_secret_name);
            let parsed: Option<Value> = serde_json::from_str(&ex.value).ok();
            let body_secret = parsed.as_ref().is_some_and(sanitize::json_has_secret);
            let secret = param_secret
                || body_secret
                || sanitize::is_secret_name(&ex.label)
                || sanitize::is_secret_value(&ex.value);
            if secret {
                omit(
                    omissions,
                    &op.operation_id,
                    // Labels and values may themselves be secret-shaped: identify the
                    // dropped example by target and a digest, never by its text.
                    format!("example:{}:{}", ex.target, example_digest(&ex.label, &ex.value)),
                    "secret_shaped",
                );
                continue;
            }
            examples.insert(PreparedExample {
                target: ex.target.clone(),
                label: ex.label.clone(),
                origin: match ex.origin {
                    ExampleOrigin::Scenario => "scenario",
                    ExampleOrigin::Claim => "claim",
                    ExampleOrigin::Inferred => "inferred",
                },
                value: ex.value.clone(),
            });
        }
    }
    if examples.is_empty() {
        omit(omissions, &op.operation_id, "examples".to_owned(), "no_scenario_or_claim_example");
    }

    let mut provenance: BTreeSet<String> = claims.iter().map(|c| c.provenance.clone()).collect();
    let mut limitation_codes: BTreeSet<String> =
        claims.iter().flat_map(|c| c.limitation_codes.iter().cloned()).collect();
    // Keep the aggregate location list and minimum reported confidence for legacy consumers.
    let legacy_only = !claims.is_empty()
        && claims.iter().all(|c| c.source_evidence.is_none() && c.handler_symbol.is_none());
    let (claim_metadata, mut handlers) = if claims_available {
        let (metadata, handlers) = exact_claim_metadata(op, &claims, omissions, legacy_only);
        (Some(metadata), handlers)
    } else {
        (None, Vec::new())
    };
    let mut catalog_summary = op.catalog_summary.clone().filter(|_| !claims_available);
    if let Some(summary) = &mut catalog_summary {
        summary.handler_symbols.sort();
        summary.handler_symbols.dedup();
        summary.handler_conflict |= summary.handler_symbols.len() > 1;
        summary.handler_symbols.retain(|symbol| {
            checked_handler_symbol(op, omissions, symbol, MAX_LEGACY_HANDLER_SYMBOL_BYTES).is_some()
        });
        summary.provenance.sort();
        summary.provenance.dedup();
        summary.limitation_codes.sort();
        summary.limitation_codes.dedup();
        provenance.extend(summary.provenance.iter().cloned());
        limitation_codes.extend(summary.limitation_codes.iter().cloned());
        // Even a singleton summary has no end line. Multiple claims also lack
        // the symbol/location associations, so none can be chosen as a winner.
        let reason =
            if let (1, Some(handler)) = (summary.claim_count, &mut summary.single_claim_handler) {
                handler.line_end = None;
                if safe_handler_path(op, omissions, &handler.path)
                    && checked_handler_symbol(
                        op,
                        omissions,
                        &handler.symbol,
                        MAX_LEGACY_HANDLER_SYMBOL_BYTES,
                    )
                    .is_some()
                {
                    handlers.push(handler.clone());
                }
                "source_end_line_unavailable"
            } else {
                summary.single_claim_handler = None;
                "per_claim_locations_unavailable"
            };
        omit(omissions, &op.operation_id, "source".to_owned(), reason);
        omit(
            omissions,
            &op.operation_id,
            "confidence".to_owned(),
            "per_claim_confidence_unavailable",
        );
        if summary.handler_conflict {
            omit(omissions, &op.operation_id, "handler".to_owned(), "handler_conflict_unresolved");
        }
    }
    handlers.sort_by(|a, b| {
        (&a.path, a.line_start, &a.symbol, a.line_end).cmp(&(
            &b.path,
            b.line_start,
            &b.symbol,
            b.line_end,
        ))
    });
    handlers.dedup();
    let request_media = claims.iter().filter_map(|c| c.request_body_media_type.clone()).min();

    PreparedOp {
        operation_id: op.operation_id.clone(),
        method,
        path,
        component: op.application_component.clone(),
        binding_key: op.binding_key.clone(),
        state: op.effective_state,
        claims_available,
        params,
        responses,
        examples: examples.into_iter().collect(),
        provenance: provenance.into_iter().collect(),
        confidence_bp: if legacy_only {
            claims.iter().filter_map(|c| c.confidence_basis_points).min()
        } else {
            None
        },
        limitation_codes: limitation_codes.into_iter().collect(),
        conflicts,
        handlers,
        request_media,
        catalog_summary,
        claim_metadata,
    }
}

fn exact_claim_metadata(
    op: &OperationInput,
    claims: &[&ClaimInput],
    omissions: &mut BTreeSet<Omission>,
    legacy_only: bool,
) -> (Value, Vec<HandlerInput>) {
    let mut reported_symbols = BTreeSet::new();
    let mut safe_symbols = BTreeSet::new();
    let mut rows = Vec::with_capacity(claims.len());
    let mut handlers = Vec::new();
    for claim in claims {
        let persisted_symbol = claim.handler_symbol.as_deref();
        reported_symbols.extend(persisted_symbol);
        let safe_persisted_symbol = persisted_symbol.and_then(|symbol| {
            checked_handler_symbol(op, omissions, symbol, MAX_CLAIM_HANDLER_SYMBOL_BYTES)
        });
        safe_symbols.extend(safe_persisted_symbol);
        let safe_legacy_symbol = claim.handler.as_ref().and_then(|handler| {
            reported_symbols.insert(handler.symbol.as_str());
            checked_handler_symbol(op, omissions, &handler.symbol, MAX_LEGACY_HANDLER_SYMBOL_BYTES)
        });
        safe_symbols.extend(safe_legacy_symbol);
        let evidence = claim.source_evidence.as_ref().map(|items| {
            items.iter().map(|item| source_evidence_json(item, op, omissions)).collect::<Vec<_>>()
        });
        let mut row = json!({
            "claim_id": claim.claim_id,
            "provenance": claim.provenance,
            "handler_symbol": safe_persisted_symbol,
            "confidence_basis_points": claim.confidence_basis_points,
            "limitation_codes": claim.limitation_codes,
            "source_evidence": evidence,
        });
        if let Some(handler) = &claim.handler
            && safe_handler_path(op, omissions, &handler.path)
            && safe_legacy_symbol.is_some()
        {
            row["handler_location"] = handler_json(handler);
            if legacy_only {
                handlers.push(handler.clone());
            }
        }
        rows.push(row);
    }
    let handler_conflict = reported_symbols.len() > 1;
    if handler_conflict {
        omit(omissions, &op.operation_id, "handler".to_owned(), "handler_conflict_unresolved");
    }
    let metadata = json!({
        "claims_projection": "available",
        "claim_count": rows.len(),
        "handler_symbols": safe_symbols,
        "handler_conflict": handler_conflict,
        "claims": rows,
    });
    (metadata, handlers)
}

fn source_evidence_json(
    evidence: &ClaimSourceEvidence,
    op: &OperationInput,
    omissions: &mut BTreeSet<Omission>,
) -> Value {
    let mut value = json!(evidence);
    let verification = match evidence {
        ClaimSourceEvidence::Unavailable { .. } => "unavailable",
        _ => "unverified",
    };
    value["verification"] = json!(verification);
    if let Some(fields) = value.as_object_mut()
        && fields
            .get("relative_path")
            .and_then(Value::as_str)
            .is_some_and(|path| !xtrace_domain::is_safe_repo_relative_path(path))
    {
        for field in ["relative_path", "start_line", "start_column", "end_line", "end_column"] {
            fields.remove(field);
        }
        fields.insert("location_omitted".to_owned(), json!("path_not_repo_relative"));
        omit(omissions, &op.operation_id, "source".to_owned(), "source_path_not_repo_relative");
    }
    value
}

fn checked_handler_symbol<'a>(
    op: &OperationInput,
    omissions: &mut BTreeSet<Omission>,
    symbol: &'a str,
    max_bytes: usize,
) -> Option<&'a str> {
    let safe = symbol.len() <= max_bytes
        && !symbol.chars().any(|c| c == '/' || c == '\\' || c.is_control());
    let matches_claim_bound =
        max_bytes != MAX_CLAIM_HANDLER_SYMBOL_BYTES || (!symbol.is_empty() && symbol.is_ascii());
    if safe && matches_claim_bound {
        Some(symbol)
    } else {
        omit(omissions, &op.operation_id, "handler".to_owned(), "handler_symbol_invalid");
        None
    }
}

fn safe_handler_path(op: &OperationInput, omissions: &mut BTreeSet<Omission>, path: &str) -> bool {
    let safe = xtrace_domain::is_safe_repo_relative_path(path);
    if !safe {
        omit(omissions, &op.operation_id, "handler".to_owned(), "handler_path_not_repo_relative");
    }
    safe
}

/// Catalog claim metadata carries the same associations, gaps and scope in every format.
pub(crate) fn catalog_metadata(op: &PreparedOp) -> Value {
    let mut metadata = op.claim_metadata.clone().unwrap_or_else(|| json!({}));
    metadata["operation_id"] = json!(op.operation_id);
    metadata["application_component"] = json!(op.component);
    metadata["binding_key"] = json!(op.binding_key);
    metadata["effective_state"] = json!(op.state.name());
    if !op.claims_available {
        metadata["claims_projection"] = json!("unavailable");
    }
    if let Some(summary) = &op.catalog_summary {
        metadata["claim_count"] = json!(summary.claim_count);
        metadata["handler_symbols"] = json!(summary.handler_symbols);
        metadata["handler_conflict"] = json!(summary.handler_conflict);
        metadata["highest_confidence_basis_points"] =
            json!(summary.highest_confidence_basis_points);
        metadata["source_locations"] = json!("per-claim locations unavailable");
        metadata["claim_confidence"] = json!("not available per claim");
    }
    if !op.provenance.is_empty() || op.catalog_summary.is_some() {
        metadata["provenance"] = json!(op.provenance);
    }
    if !op.limitation_codes.is_empty() || op.catalog_summary.is_some() {
        metadata["limitation_codes"] = json!(op.limitation_codes);
    }
    if let Some(bp) = op.confidence_bp {
        metadata["confidence_basis_points"] = json!(bp);
    }
    if !op.handlers.is_empty() {
        metadata["handlers"] = Value::Array(op.handlers.iter().map(handler_json).collect());
    }
    metadata
}

/// An unknown extent is omitted, never replaced with the start line.
fn handler_json(handler: &HandlerInput) -> Value {
    let mut value = json!({"symbol": handler.symbol, "path": handler.path});
    if handler.line_start != 0 {
        value["line_start"] = json!(handler.line_start);
    }
    if let Some(end) = handler.line_end {
        value["line_end"] = json!(end);
    }
    value
}
