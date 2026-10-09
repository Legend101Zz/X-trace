//! Canonical plan encoding and the plan hash.

use serde_json::{Value, json};
use xtrace_export::canonical::json_compact;

use crate::plan::{Plan, PlanItem};

fn item_value(item: &PlanItem) -> Value {
    json!({
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

/// Everything the hash covers (everything except the hash itself and the
/// item ids, which are derived from the hash).
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
        if let Some(Value::Array(items)) = map.get_mut("items") {
            for (value, item) in items.iter_mut().zip(&plan.items) {
                if let Value::Object(obj) = value {
                    obj.insert("item_id".to_owned(), Value::String(item.item_id.clone()));
                }
            }
        }
        map.insert("plan_hash".to_owned(), Value::String(plan.plan_hash.clone()));
    }
    v
}

/// Recomputes the hash from the plan's content.
#[must_use]
pub fn recompute_hash(plan: &Plan) -> String {
    hash_content(&content_value(&plan.revision_id, &plan.catalog_hash, &plan.target, &plan.items))
}

/// Deterministic UUID text (version 8, RFC 9562 custom layout) for an item,
/// derived from the plan hash and the operation id. Differs between plans
/// that contain the same operation; stable for one plan. Persistence may
/// substitute a UUIDv7 and keep it outside the plan hash.
#[must_use]
pub fn item_uuid(plan_hash: &str, operation_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.exercise.item.v2\0");
    hasher.update(plan_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(operation_id.as_bytes());
    let digest = hasher.finalize();
    let mut b = [0_u8; 16];
    b.copy_from_slice(&digest.as_bytes()[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
