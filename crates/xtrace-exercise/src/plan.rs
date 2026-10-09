//! Plan types.

use crate::effect::Effect;

/// Where a value came from, in priority order (earlier wins).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueSource {
    /// Scenario file.
    Scenario,
    /// Catalog claim example.
    ClaimExample,
    /// Catalog default.
    CatalogDefault,
    /// No value available; the run cannot send this item until one is supplied.
    Unresolved,
    /// A credential: resolved just in time at run time, never stored in a plan.
    Credential,
}

impl ValueSource {
    /// Stable name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Scenario => "scenario",
            Self::ClaimExample => "claim_example",
            Self::CatalogDefault => "catalog_default",
            Self::Unresolved => "unresolved",
            Self::Credential => "credential",
        }
    }
}

/// One resolved parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamValue {
    /// Name.
    pub name: String,
    /// `path`, `query`, `header` or `cookie`.
    pub location: String,
    /// Value; always `None` for `Unresolved` and `Credential`.
    pub value: Option<String>,
    /// Source.
    pub source: ValueSource,
    /// Declared required.
    pub required: bool,
}

/// One planned request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanItem {
    /// UUID text derived from (plan hash, operation id); not part of the hash.
    pub item_id: String,
    /// Operation id.
    pub operation_id: String,
    /// Upper-case method.
    pub method: String,
    /// Path template.
    pub path_template: String,
    /// Resolved parameters sorted by (location, name).
    pub params: Vec<ParamValue>,
    /// Effect.
    pub effect: Effect,
    /// Selected by default or by the caller.
    pub selected: bool,
    /// Why it is (not) selected.
    pub selection_reason: String,
    /// Needs explicit approval before it may run.
    pub needs_approval: bool,
}

/// An immutable plan. `plan_hash` binds every other field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// Catalog revision.
    pub revision_id: String,
    /// Catalog content hash.
    pub catalog_hash: String,
    /// Target base URL as given (not contacted).
    pub target: String,
    /// Items in canonical order.
    pub items: Vec<PlanItem>,
    /// Hex BLAKE3 plan hash.
    pub plan_hash: String,
}
