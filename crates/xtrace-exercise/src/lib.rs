//! Exercise plans (lane W).
//!
//! Building and previewing a plan is pure: this crate contains no networking
//! code at all. Execution, approval and the destination guard arrive in later
//! stages and will live in separate modules behind explicit approval.
//!
//! The plan hash is a domain-separated BLAKE3 over the canonical JSON of the
//! plan content, so any change to any item, value or flag changes the hash,
//! and the hash does not depend on the order candidates were supplied in.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]

pub mod candidate;
pub mod canonical;
pub mod effect;
pub mod input_json;
pub mod plan;
pub mod preview;

pub use candidate::{
    CandidateOp, CandidateParam, ChangeKind, PlanError, PlanInput, synthesize, validate_target,
};
pub use effect::{Effect, classify};
pub use plan::{ParamValue, Plan, PlanItem, ValueSource};
pub use preview::preview;
