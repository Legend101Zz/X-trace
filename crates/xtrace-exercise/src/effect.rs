//! Effect classification: does exercising this operation change state?

/// What exercising an operation may do to the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Safe method, no contradicting evidence.
    ReadOnly,
    /// May change state.
    Mutating,
    /// Evidence conflicts or the method is unrecognised. Treated as needing
    /// approval, never as read-only.
    Unknown,
}

impl Effect {
    /// Stable name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Mutating => "mutating",
            Self::Unknown => "unknown",
        }
    }
}

fn from_method(method: &str) -> Effect {
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => Effect::ReadOnly,
        "POST" | "PUT" | "PATCH" | "DELETE" => Effect::Mutating,
        _ => Effect::Unknown,
    }
}

/// Classifies an operation from its method, per-claim hints and whether the
/// catalog says its sources are in conflict.
#[must_use]
pub fn classify(method: &str, hints: &[Effect], conflicted: bool) -> Effect {
    if conflicted {
        return Effect::Unknown;
    }
    let by_method = from_method(method);
    if hints.iter().any(|h| *h != by_method) {
        return Effect::Unknown;
    }
    by_method
}
