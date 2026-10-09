//! Order-independent, sanitized view of the input that every format renders.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::request::{
    EffectiveState, ExampleOrigin, ExportInput, ExportRequest, HandlerInput, Omission,
    OperationInput, RevisionInput,
};
use crate::sanitize;

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
    /// Lowest confidence across claims.
    pub confidence_bp: Option<u16>,
    /// Limitation codes, sorted unique.
    pub limitation_codes: Vec<String>,
    /// Conflicts.
    pub conflicts: Vec<Conflict>,
    /// Handlers sorted by (path, line, symbol).
    pub handlers: Vec<HandlerInput>,
    /// Request body media type, when any claim declares one.
    pub request_media: Option<String>,
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
    let mut claims: Vec<_> = op.claims.iter().collect();
    claims.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
    if !op.claims_available {
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

    let provenance: BTreeSet<String> = claims.iter().map(|c| c.provenance.clone()).collect();
    let limitation_codes: BTreeSet<String> =
        claims.iter().flat_map(|c| c.limitation_codes.iter().cloned()).collect();
    let mut handlers: Vec<HandlerInput> = claims.iter().filter_map(|c| c.handler.clone()).collect();
    handlers.sort_by(|a, b| {
        (&a.path, a.line_start, &a.symbol).cmp(&(&b.path, b.line_start, &b.symbol))
    });
    handlers.dedup();
    // Handler paths are source locations from claims: only repo-relative ones
    // may leave the product (no absolute owner paths, `..`, backslashes).
    handlers.retain(|h| {
        let safe = xtrace_domain::is_safe_repo_relative_path(&h.path);
        if !safe {
            omit(
                omissions,
                &op.operation_id,
                "handler".to_owned(),
                "handler_path_not_repo_relative",
            );
        }
        safe
    });
    let request_media = claims.iter().filter_map(|c| c.request_body_media_type.clone()).min();

    PreparedOp {
        operation_id: op.operation_id.clone(),
        method,
        path,
        component: op.application_component.clone(),
        binding_key: op.binding_key.clone(),
        state: op.effective_state,
        claims_available: op.claims_available,
        params,
        responses,
        examples: examples.into_iter().collect(),
        provenance: provenance.into_iter().collect(),
        confidence_bp: claims.iter().filter_map(|c| c.confidence_basis_points).min(),
        limitation_codes: limitation_codes.into_iter().collect(),
        conflicts,
        handlers,
        request_media,
    }
}
