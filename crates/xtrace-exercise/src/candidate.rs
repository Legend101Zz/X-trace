//! Candidate synthesis: catalog operations in, an immutable plan out.

use xtrace_export::sanitize;

use crate::canonical;
use crate::effect::{Effect, classify};
use crate::plan::{ParamValue, Plan, PlanItem, ValueSource};

/// Catalog change kind relative to the previous revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// New in this revision.
    Added,
    /// Changed in this revision.
    Changed,
    /// Unchanged.
    Unchanged,
    /// Unknown.
    Unknown,
}

/// A parameter with every value source the catalog or a scenario offers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateParam {
    /// Name.
    pub name: String,
    /// Location.
    pub location: String,
    /// Required.
    pub required: bool,
    /// Value from a scenario file.
    pub scenario_value: Option<String>,
    /// Example from a claim.
    pub claim_example: Option<String>,
    /// Catalog default.
    pub default_value: Option<String>,
}

/// One catalog operation as a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateOp {
    /// Operation id.
    pub operation_id: String,
    /// Method.
    pub method: String,
    /// Route template.
    pub route_template: String,
    /// Change kind.
    pub change_kind: ChangeKind,
    /// Recordings observed for it (`None` = not computed).
    pub observed_recording_count: Option<u32>,
    /// Sources disagree about this operation.
    pub conflicted: bool,
    /// Per-claim effect hints.
    pub effect_hints: Vec<Effect>,
    /// Parameters.
    pub params: Vec<CandidateParam>,
}

/// Plan input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanInput {
    /// Revision id.
    pub revision_id: String,
    /// Catalog hash.
    pub catalog_hash: String,
    /// Target base URL (stored, never contacted by this crate).
    pub target: String,
    /// Candidates in any order.
    pub ops: Vec<CandidateOp>,
    /// When set, only these operation ids are selected (overrides defaults).
    pub explicit_selection: Option<Vec<String>>,
}

fn resolve(param: &CandidateParam) -> ParamValue {
    let base = |value: Option<String>, source| ParamValue {
        name: param.name.clone(),
        location: param.location.clone(),
        value,
        source,
        required: param.required,
    };
    if sanitize::is_secret_name(&param.name) {
        // Never copy a value into a plan for a credential-shaped parameter.
        return base(None, ValueSource::Credential);
    }
    let ordered = [
        (&param.scenario_value, ValueSource::Scenario),
        (&param.claim_example, ValueSource::ClaimExample),
        (&param.default_value, ValueSource::CatalogDefault),
    ];
    for (value, source) in ordered {
        if let Some(v) = value {
            if sanitize::is_secret_value(v) {
                continue;
            }
            return base(Some(v.clone()), source);
        }
    }
    base(None, ValueSource::Unresolved)
}

fn method_rank(method: &str) -> u8 {
    match method {
        "GET" => 0,
        "HEAD" => 1,
        "POST" => 2,
        "PUT" => 3,
        "PATCH" => 4,
        "DELETE" => 5,
        _ => 6,
    }
}

fn default_selection(op: &CandidateOp) -> (bool, &'static str) {
    match op.change_kind {
        ChangeKind::Added => return (true, "new_in_revision"),
        ChangeKind::Changed => return (true, "changed_in_revision"),
        ChangeKind::Unchanged | ChangeKind::Unknown => {}
    }
    if op.observed_recording_count == Some(0) {
        return (true, "never_observed");
    }
    (false, "already_observed_and_unchanged")
}

/// Builds the plan. Same candidates in any order give the same plan and hash.
#[must_use]
pub fn synthesize(input: &PlanInput) -> Plan {
    let mut ops: Vec<&CandidateOp> = input.ops.iter().collect();
    ops.sort_by(|a, b| {
        (&a.route_template, method_rank(&a.method.to_ascii_uppercase()), &a.operation_id).cmp(&(
            &b.route_template,
            method_rank(&b.method.to_ascii_uppercase()),
            &b.operation_id,
        ))
    });
    ops.dedup_by(|a, b| a.operation_id == b.operation_id);
    let mut items: Vec<PlanItem> = ops
        .into_iter()
        .map(|op| {
            let mut params: Vec<ParamValue> = op.params.iter().map(resolve).collect();
            params.sort_by(|a, b| (&a.location, &a.name).cmp(&(&b.location, &b.name)));
            let effect = classify(&op.method, &op.effect_hints, op.conflicted);
            let (selected, reason) = match &input.explicit_selection {
                Some(ids) => (
                    ids.contains(&op.operation_id),
                    if ids.contains(&op.operation_id) {
                        "explicitly_selected"
                    } else {
                        "not_in_explicit_selection"
                    },
                ),
                None => default_selection(op),
            };
            PlanItem {
                item_id: String::new(),
                operation_id: op.operation_id.clone(),
                method: op.method.to_ascii_uppercase(),
                path_template: op.route_template.clone(),
                params,
                effect,
                selected,
                selection_reason: reason.to_owned(),
                needs_approval: effect != Effect::ReadOnly,
            }
        })
        .collect();
    let plan_hash = canonical::hash_content(&canonical::content_value(
        &input.revision_id,
        &input.catalog_hash,
        &input.target,
        &items,
    ));
    for item in &mut items {
        item.item_id = canonical::item_uuid(&plan_hash, &item.operation_id);
    }
    Plan {
        revision_id: input.revision_id.clone(),
        catalog_hash: input.catalog_hash.clone(),
        target: input.target.clone(),
        items,
        plan_hash,
    }
}
