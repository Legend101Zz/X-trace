//! Zero-request preview of a plan. Pure function over a plan value.

use serde_json::{Value, json};

use crate::plan::{Plan, ValueSource};

/// Describes what a run would do, without doing it. `requests_sent` is the
/// constant `0`: there is no code path from here to a socket.
#[must_use]
pub fn preview(plan: &Plan) -> Value {
    let items: Vec<Value> = plan
        .items
        .iter()
        .map(|item| {
            let unresolved: Vec<&str> = item
                .params
                .iter()
                .filter(|p| p.required && p.source == ValueSource::Unresolved)
                .map(|p| p.name.as_str())
                .collect();
            let credentials: Vec<&str> = item
                .params
                .iter()
                .filter(|p| p.source == ValueSource::Credential)
                .map(|p| p.name.as_str())
                .collect();
            json!({
                "item_id": item.item_id,
                "operation_id": item.operation_id,
                "request": format!("{} {}", item.method, item.path_template),
                "selected": item.selected,
                "selection_reason": item.selection_reason,
                "effect": item.effect.name(),
                "needs_approval": item.needs_approval,
                "unresolved_required": unresolved,
                "credentials_needed_at_run_time": credentials,
                "ready": item.selected && unresolved.is_empty(),
            })
        })
        .collect();
    let selected = plan.items.iter().filter(|i| i.selected).count();
    let approvals = plan.items.iter().filter(|i| i.selected && i.needs_approval).count();
    json!({
        "plan_hash": plan.plan_hash,
        "revision_id": plan.revision_id,
        "target": plan.target,
        "requests_sent": 0,
        "selected_items": selected,
        "items_needing_approval": approvals,
        "items": items,
    })
}
