//! Deterministic OpenAPI 3.1 projector with `x-xtrace` extensions.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::canonical;
use crate::projection::{Conflict, Prepared, PreparedOp};
use crate::request::{EffectiveState, ExportError, ExportFile, ExportOutput, Omission};
use crate::{sanitize, validate};

fn schema_for(type_name: Option<&str>) -> Value {
    match type_name {
        Some(t @ ("string" | "integer" | "number" | "boolean" | "array" | "object")) => {
            json!({ "type": t })
        }
        Some(other) => json!({ "x-xtrace-declared-type": other }),
        None => json!({}),
    }
}

fn pascal(segment: &str) -> String {
    segment
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut chars = p.chars();
            chars
                .next()
                .map_or_else(String::new, |f| f.to_ascii_uppercase().to_string() + chars.as_str())
        })
        .collect()
}

fn base_operation_id(op: &PreparedOp) -> String {
    let mut id = op.method.to_ascii_lowercase();
    for seg in op.path.split('/').filter(|s| !s.is_empty()) {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            id.push_str("By");
            id.push_str(&pascal(name));
        } else {
            id.push_str(&pascal(seg));
        }
    }
    if id.len() == op.method.len() {
        id.push_str("Root");
    }
    id
}

fn operation_ids(ops: &[&PreparedOp]) -> Vec<String> {
    let bases: Vec<String> = ops.iter().map(|o| base_operation_id(o)).collect();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for b in &bases {
        *counts.entry(b.as_str()).or_default() += 1;
    }
    ops.iter()
        .zip(&bases)
        .map(|(op, base)| {
            if counts.get(base.as_str()).copied().unwrap_or(0) > 1 {
                let digest = blake3::hash(op.operation_id.as_bytes()).to_hex();
                format!("{base}_{}", &digest.as_str()[..8])
            } else {
                base.clone()
            }
        })
        .collect()
}

fn conflict_json(c: &Conflict) -> Value {
    json!({
        "kind": c.kind,
        "subject": c.subject,
        "claims": c.values.iter().map(|(id, v)| json!({"claim_id": id, "value": v})).collect::<Vec<_>>(),
    })
}

fn example_value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
}

fn operation_json(op: &PreparedOp, operation_id: &str) -> Value {
    let mut out = Map::new();
    out.insert("operationId".into(), json!(operation_id));
    if !op.component.is_empty() {
        out.insert("tags".into(), json!([op.component]));
    }
    let params: Vec<Value> = op
        .params
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "in": p.location,
                "required": p.required,
                "schema": schema_for(p.type_name.as_deref()),
            })
        })
        .collect();
    if !params.is_empty() {
        out.insert("parameters".into(), Value::Array(params));
    }
    if let Some(media) = &op.request_media {
        out.insert("requestBody".into(), json!({"content": {media.clone(): {"schema": {}}}}));
    }
    let mut responses = Map::new();
    for r in &op.responses {
        let description = r.description.clone().unwrap_or_else(|| {
            "Declared by catalog claims (description unavailable or conflicting)".to_owned()
        });
        responses.insert(r.status.clone(), json!({ "description": description }));
    }
    if responses.is_empty() {
        responses.insert(
            "default".into(),
            json!({"description": "No response claim in the catalog for this operation"}),
        );
    }
    out.insert("responses".into(), Value::Object(responses));

    let mut x = Map::new();
    x.insert("operation_id".into(), json!(op.operation_id));
    x.insert("effective_state".into(), json!(op.state.name()));
    if !op.binding_key.is_empty() {
        x.insert("binding_key".into(), json!(op.binding_key));
    }
    if !op.component.is_empty() {
        x.insert("application_component".into(), json!(op.component));
    }
    if !op.provenance.is_empty() {
        x.insert("provenance".into(), json!(op.provenance));
    }
    if let Some(bp) = op.confidence_bp {
        x.insert("confidence_basis_points".into(), json!(bp));
    }
    if !op.limitation_codes.is_empty() {
        x.insert("limitation_codes".into(), json!(op.limitation_codes));
    }
    if !op.claims_available {
        x.insert("claims_projection".into(), json!("unavailable"));
    }
    if !op.conflicts.is_empty() {
        x.insert(
            "conflicts".into(),
            Value::Array(op.conflicts.iter().map(conflict_json).collect()),
        );
    }
    if !op.handlers.is_empty() {
        x.insert(
            "handlers".into(),
            Value::Array(
                op.handlers
                    .iter()
                    .map(|h| {
                        json!({"symbol": h.symbol, "path": h.path,
                               "line_start": h.line_start, "line_end": h.line_end})
                    })
                    .collect(),
            ),
        );
    }
    if !op.examples.is_empty() {
        x.insert(
            "examples".into(),
            Value::Array(
                op.examples
                    .iter()
                    .map(|e| {
                        // Examples never come from observed bodies (none are retained).
                        json!({"target": e.target, "label": e.label, "origin": e.origin,
                               "x-xtrace-observation": "inferred",
                               "value": example_value(&e.value)})
                    })
                    .collect(),
            ),
        );
    }
    // CONTRACTS 9.1 export marker: only an Observed operation is `observed`;
    // static, registered, conflicted and unknown ones are `inferred`.
    let observation = if op.state == EffectiveState::Observed { "observed" } else { "inferred" };
    out.insert("x-xtrace-observation".into(), json!(observation));
    out.insert("x-xtrace".into(), Value::Object(x));
    Value::Object(out)
}

/// Builds the OpenAPI document value and the omissions it carries.
#[must_use]
pub fn document(prepared: &Prepared) -> (Value, Vec<Omission>) {
    let mut omissions = prepared.omissions.clone();
    // Two operations can share (method, path); OpenAPI cannot hold both.
    let mut winners: Vec<&PreparedOp> = Vec::new();
    for op in &prepared.ops {
        if let Some(first) = winners.iter().find(|w| w.method == op.method && w.path == op.path) {
            omissions.push(Omission {
                operation_id: op.operation_id.clone(),
                what: "operation".to_owned(),
                reason: format!("duplicate_method_path_of:{}", first.operation_id),
            });
        } else {
            winners.push(op);
        }
    }
    let ids = operation_ids(&winners);
    let mut paths: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for (op, id) in winners.iter().zip(&ids) {
        paths
            .entry(op.path.clone())
            .or_default()
            .insert(op.method.to_ascii_lowercase(), operation_json(op, id));
    }
    omissions.sort();
    omissions.dedup();
    let rev = &prepared.revision;
    let title = if rev.application_name.is_empty() {
        "X-trace catalog export".to_owned()
    } else {
        rev.application_name.clone()
    };
    let doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": format!("catalog-r{}", rev.ordinal),
            "x-xtrace": {
                "revision_id": rev.revision_id,
                "catalog_hash": rev.catalog_hash,
                "policy_digest": rev.policy_digest,
                "notice": "Generated from the X-trace catalog. effective_state says how each operation was learned; no request or response bodies were observed or retained.",
                "omissions": omissions.iter().map(|o| json!({
                    "operation_id": o.operation_id, "what": o.what, "reason": o.reason,
                })).collect::<Vec<_>>(),
            },
        },
        "paths": paths.into_iter().map(|(k, v)| (k, Value::Object(v))).collect::<Map<_, _>>(),
    });
    (doc, omissions)
}

/// Renders `openapi.json` or `openapi.yaml`.
///
/// # Errors
///
/// Fails when the sanitizer gate or the structural validator rejects the
/// finished document.
pub fn render(prepared: &Prepared) -> Result<ExportOutput, ExportError> {
    let (doc, omissions) = document(prepared);
    if let Some(path) = sanitize::gate_with_metadata(&doc, &["/info/x-xtrace/omissions"]) {
        return Err(ExportError::SecretShaped { path });
    }
    let problems = validate::openapi_31(&doc);
    if !problems.is_empty() {
        return Err(ExportError::InvalidDocument { problems });
    }
    let (name, text) = if prepared.yaml {
        ("openapi.yaml", canonical::yaml(&doc))
    } else {
        ("openapi.json", canonical::json_pretty(&doc))
    };
    let file = ExportFile { path: name.to_owned(), mode: 0o644, bytes: text.into_bytes() };
    Ok(crate::finish(vec![file], omissions))
}
