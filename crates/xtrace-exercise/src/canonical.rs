//! Canonical plan encoding and the plan hash.

use serde_json::{Value, json};
use xtrace_export::canonical::json_compact;

use crate::plan::{Plan, PlanItem};

fn item_value(item: &PlanItem) -> Value {
    json!({
        "item_id": item.item_id,
        "operation_id": item.operation_id,
        "method": item.method,
        "path_template": item.path_template,
        "effect": item.effect.name(),
        "selected": item.selected,
        "selection_reason": item.selection_reason,
        "needs_approval": item.needs_approval,
        "params": item.params.iter().map(|p| json!({
            "name": p.name,
            "location": p.location,
            "value": p.value,
            "source": p.source.name(),
            "required": p.required,
        })).collect::<Vec<_>>(),
    })
}

/// Everything the hash covers (everything except the hash itself).
#[must_use]
pub fn content_value(
    revision_id: &str,
    catalog_hash: &str,
    target: &str,
    items: &[PlanItem],
) -> Value {
    json!({
        "version": 1,
        "revision_id": revision_id,
        "catalog_hash": catalog_hash,
        "target": target,
        "items": items.iter().map(item_value).collect::<Vec<_>>(),
    })
}

/// Domain-separated BLAKE3 over the canonical content.
#[must_use]
pub fn hash_content(content: &Value) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.exercise.plan.v1\0");
    hasher.update(json_compact(content).as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Canonical JSON of a whole plan including its hash.
#[must_use]
pub fn plan_value(plan: &Plan) -> Value {
    let mut v = content_value(&plan.revision_id, &plan.catalog_hash, &plan.target, &plan.items);
    if let Value::Object(map) = &mut v {
        map.insert("plan_hash".to_owned(), Value::String(plan.plan_hash.clone()));
    }
    v
}

/// Recomputes the hash from the plan's content.
#[must_use]
pub fn recompute_hash(plan: &Plan) -> String {
    hash_content(&content_value(&plan.revision_id, &plan.catalog_hash, &plan.target, &plan.items))
}
