//! Private, expiring owner-reviewed exercise plans. No request sender exists here.
//!
//! Transport adapters authenticate the operator and implement the project-scoped
//! evidence/storage port. Approval is never inferred from preview, a safe method,
//! persisted UI state, or the presence of a credential reference.

mod body_json;
mod model;
mod service;

pub use model::*;
pub use service::{ExercisePlanService, review_document};
