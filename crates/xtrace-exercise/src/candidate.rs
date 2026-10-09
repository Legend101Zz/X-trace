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
    match (op.change_kind, op.observed_recording_count) {
        (_, Some(0)) => (true, "never_observed"),
        (ChangeKind::Unchanged, Some(_)) => (false, "already_observed_and_unchanged"),
        // Nothing proves it was observed or unchanged: select it.
        _ => (true, "change_and_observation_unknown"),
    }
}

/// Why a plan could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The target is not a plain `http(s)://host[:port][/path]` URL. The
    /// rejected text is deliberately not echoed.
    InvalidTarget(&'static str),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(why) => write!(f, "invalid exercise target: {why}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Checks a target base URL: http/https, host present, no userinfo, query,
/// fragment, whitespace or control characters, and not secret-shaped.
///
/// # Errors
///
/// [`PlanError::InvalidTarget`] with a fixed reason.
pub fn validate_target(target: &str) -> Result<(), PlanError> {
    let bad = |why| Err(PlanError::InvalidTarget(why));
    if target.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return bad("whitespace_or_control_character");
    }
    let Some((scheme, rest)) = target.split_once("://") else {
        return bad("missing_scheme");
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return bad("scheme_not_http_or_https");
    }
    if rest.contains(['?', '#']) {
        return bad("query_or_fragment");
    }
    // Backslash is a path separator to many URL parsers and not to others: a
    // host differential. Refuse it anywhere.
    if rest.contains('\\') {
        return bad("backslash");
    }
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return bad("userinfo");
    }
    if authority.is_empty() || authority.starts_with(':') {
        return bad("missing_host");
    }
    if authority.contains('%') {
        return bad("percent_encoded_authority");
    }
    if parse_authority(authority).is_none() {
        return bad("malformed_authority");
    }
    if sanitize::is_secret_value(target) {
        return bad("secret_shaped");
    }
    Ok(())
}

/// How a validated target host is classified. A future sender must allow
/// [`HostClass::Loopback`] only unless the owner explicitly allows more, and
/// must re-check the resolved address at connect time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostClass {
    /// `localhost`, `*.localhost`, `127.0.0.0/8`, `::1`.
    Loopback,
    /// Private, link-local, unspecified or otherwise non-public IP literal.
    NonPublicIp,
    /// Public IP literal.
    PublicIp,
    /// A DNS name that is not a loopback name (resolution is not done here).
    Name,
}

/// Splits `host[:port]` into a lowercase host and optional port. Hosts are a
/// bracketed IPv6 literal, a canonical dotted IPv4, or a DNS name of
/// letters, digits, `-` and `.`. Non-canonical numeric forms (`127.1`, `0x7f.1`,
/// `2130706433`) are refused so classification cannot be bypassed.
fn parse_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        h.parse::<core::net::Ipv6Addr>().ok()?;
        (format!("[{}]", h.to_ascii_lowercase()), port)
    } else {
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if h.is_empty() || h.len() > 253 {
            return None;
        }
        if !h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) {
            return None;
        }
        let last = h.rsplit('.').next().unwrap_or("");
        let numeric_like = last.bytes().all(|b| b.is_ascii_digit())
            || last.starts_with("0x")
            || last.starts_with("0X");
        if numeric_like && h.parse::<core::net::Ipv4Addr>().is_err() {
            return None;
        }
        (h.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(p.parse::<u16>().ok()?)
        }
    };
    Some((host, port))
}

/// Classifies the host of a target that passed [`validate_target`].
///
/// # Errors
///
/// [`PlanError::InvalidTarget`] when the target does not validate.
pub fn classify_target_host(target: &str) -> Result<HostClass, PlanError> {
    validate_target(target)?;
    let rest = target.split_once("://").map_or("", |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or("");
    let Some((host, _)) = parse_authority(authority) else {
        return Err(PlanError::InvalidTarget("malformed_authority"));
    };
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: core::net::Ipv6Addr =
            inner.parse().map_err(|_| PlanError::InvalidTarget("malformed_authority"))?;
        if let Some(v4) = ip.to_ipv4_mapped() {
            return Ok(classify_v4(v4));
        }
        return Ok(if ip.is_loopback() {
            HostClass::Loopback
        } else if ip.is_unspecified()
            || ip.is_multicast()
            || (ip.segments()[0] & 0xfe00) == 0xfc00
            || (ip.segments()[0] & 0xffc0) == 0xfe80
        {
            HostClass::NonPublicIp
        } else {
            HostClass::PublicIp
        });
    }
    if let Ok(v4) = host.parse::<core::net::Ipv4Addr>() {
        return Ok(classify_v4(v4));
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Ok(HostClass::Loopback);
    }
    Ok(HostClass::Name)
}

fn classify_v4(ip: core::net::Ipv4Addr) -> HostClass {
    if ip.is_loopback() {
        HostClass::Loopback
    } else if ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.octets()[0] == 0
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
    {
        HostClass::NonPublicIp
    } else {
        HostClass::PublicIp
    }
}

/// Builds the plan. Same candidates in any order give the same plan and hash.
///
/// # Errors
///
/// [`PlanError`] when the target is not acceptable.
pub fn synthesize(input: &PlanInput) -> Result<Plan, PlanError> {
    validate_target(&input.target)?;
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
    Ok(Plan {
        revision_id: input.revision_id.clone(),
        catalog_hash: input.catalog_hash.clone(),
        target: input.target.clone(),
        items,
        plan_hash,
    })
}
