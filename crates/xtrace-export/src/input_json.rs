//! JSON file codec for [`ExportInput`]. This is the interim input path until
//! the catalog read port is wired: a caller supplies the same plain structs as
//! a JSON document. Output produced from such a file says so; it is a fixture
//! style input, not catalog evidence.

use serde_json::Value;

use crate::request::{
    ClaimInput, EffectiveState, ExampleInput, ExampleOrigin, ExportInput, HandlerInput,
    OperationInput, ParamInput, ResponseInput, RevisionInput,
};

type Obj = serde_json::Map<String, Value>;

fn obj<'a>(v: &'a Value, at: &str) -> Result<&'a Obj, String> {
    v.as_object().ok_or_else(|| format!("{at}: expected an object"))
}

fn s(o: &Obj, key: &str, at: &str) -> Result<String, String> {
    match o.get(key) {
        Some(Value::String(v)) => Ok(v.clone()),
        Some(_) => Err(format!("{at}.{key}: expected a string")),
        None => Ok(String::new()),
    }
}

fn req(o: &Obj, key: &str, at: &str) -> Result<String, String> {
    let v = s(o, key, at)?;
    if v.is_empty() { Err(format!("{at}.{key}: required")) } else { Ok(v) }
}

fn b(o: &Obj, key: &str, default: bool, at: &str) -> Result<bool, String> {
    match o.get(key) {
        Some(Value::Bool(v)) => Ok(*v),
        Some(_) => Err(format!("{at}.{key}: expected a boolean")),
        None => Ok(default),
    }
}

fn n(o: &Obj, key: &str, at: &str) -> Result<Option<u64>, String> {
    match o.get(key) {
        Some(Value::Number(v)) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{at}.{key}: expected a non-negative integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("{at}.{key}: expected a number")),
    }
}

fn arr<'a>(o: &'a Obj, key: &str, at: &str) -> Result<&'a [Value], String> {
    match o.get(key) {
        Some(Value::Array(v)) => Ok(v),
        Some(_) => Err(format!("{at}.{key}: expected an array")),
        None => Ok(&[]),
    }
}

fn state(name: &str, at: &str) -> Result<EffectiveState, String> {
    Ok(match name {
        "static_only" => EffectiveState::StaticOnly,
        "registered" => EffectiveState::Registered,
        "observed" => EffectiveState::Observed,
        "conflicted" => EffectiveState::Conflicted,
        "unknown" | "" => EffectiveState::Unknown,
        other => return Err(format!("{at}.effective_state: unknown state {other}")),
    })
}

fn origin(name: &str, at: &str) -> Result<ExampleOrigin, String> {
    Ok(match name {
        "scenario" => ExampleOrigin::Scenario,
        "claim" => ExampleOrigin::Claim,
        "inferred" => ExampleOrigin::Inferred,
        other => return Err(format!("{at}.origin: {other} is not scenario, claim or inferred")),
    })
}

/// Parses an export input document.
///
/// # Errors
///
/// Returns a message naming the first offending field.
pub fn parse(doc: &Value) -> Result<ExportInput, String> {
    let root = obj(doc, "$")?;
    let rev = match root.get("revision") {
        Some(v) => {
            let o = obj(v, "revision")?;
            RevisionInput {
                revision_id: s(o, "revision_id", "revision")?,
                ordinal: u32::try_from(n(o, "ordinal", "revision")?.unwrap_or(0))
                    .map_err(|_| "revision.ordinal: too large".to_owned())?,
                catalog_hash: s(o, "catalog_hash", "revision")?,
                policy_digest: s(o, "policy_digest", "revision")?,
                application_name: s(o, "application_name", "revision")?,
            }
        }
        None => RevisionInput::default(),
    };
    let mut operations = Vec::new();
    for (i, v) in arr(root, "operations", "$")?.iter().enumerate() {
        let at = format!("operations[{i}]");
        let o = obj(v, &at)?;
        let mut claims = Vec::new();
        for (j, c) in arr(o, "claims", &at)?.iter().enumerate() {
            claims.push(claim(c, &format!("{at}.claims[{j}]"))?);
        }
        operations.push(OperationInput {
            operation_id: req(o, "operation_id", &at)?,
            method: req(o, "method", &at)?,
            route_template: req(o, "route_template", &at)?,
            application_component: s(o, "application_component", &at)?,
            binding_key: s(o, "binding_key", &at)?,
            effective_state: state(&s(o, "effective_state", &at)?, &at)?,
            claims_available: b(o, "claims_available", true, &at)?,
            claims,
        });
    }
    Ok(ExportInput { revision: rev, operations, truncated: b(root, "truncated", false, "$")? })
}

fn claim(v: &Value, at: &str) -> Result<ClaimInput, String> {
    let o = obj(v, at)?;
    let mut out = ClaimInput {
        claim_id: req(o, "claim_id", at)?,
        provenance: s(o, "provenance", at)?,
        confidence_basis_points: n(o, "confidence_basis_points", at)?
            .map(|x| {
                u16::try_from(x).map_err(|_| format!("{at}.confidence_basis_points: too large"))
            })
            .transpose()?,
        request_body_media_type: match o.get("request_body_media_type") {
            Some(Value::String(m)) => Some(m.clone()),
            _ => None,
        },
        ..Default::default()
    };
    for c in arr(o, "limitation_codes", at)? {
        if let Value::String(code) = c {
            out.limitation_codes.push(code.clone());
        }
    }
    for (i, p) in arr(o, "params", at)?.iter().enumerate() {
        let a = format!("{at}.params[{i}]");
        let po = obj(p, &a)?;
        out.params.push(ParamInput {
            name: req(po, "name", &a)?,
            location: req(po, "location", &a)?,
            type_name: s(po, "type_name", &a)?,
            required: b(po, "required", false, &a)?,
            source: s(po, "source", &a)?,
        });
    }
    for (i, r) in arr(o, "responses", at)?.iter().enumerate() {
        let a = format!("{at}.responses[{i}]");
        let ro = obj(r, &a)?;
        out.responses.push(ResponseInput {
            status: req(ro, "status", &a)?,
            description: s(ro, "description", &a)?,
        });
    }
    for (i, e) in arr(o, "examples", at)?.iter().enumerate() {
        let a = format!("{at}.examples[{i}]");
        let eo = obj(e, &a)?;
        out.examples.push(ExampleInput {
            label: s(eo, "label", &a)?,
            target: req(eo, "target", &a)?,
            origin: origin(&req(eo, "origin", &a)?, &a)?,
            value: s(eo, "value", &a)?,
        });
    }
    if let Some(h) = o.get("handler") {
        let a = format!("{at}.handler");
        let ho = obj(h, &a)?;
        let line = |k: &str| -> Result<u32, String> {
            u32::try_from(n(ho, k, &a)?.unwrap_or(0)).map_err(|_| format!("{a}.{k}: too large"))
        };
        out.handler = Some(HandlerInput {
            symbol: s(ho, "symbol", &a)?,
            path: s(ho, "path", &a)?,
            line_start: line("line_start")?,
            line_end: line("line_end")?,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_and_reports_the_bad_field() {
        let ok = parse(&json!({"operations": [{"operation_id": "a", "method": "GET", "route_template": "/x"}]})).unwrap();
        assert_eq!(ok.operations.len(), 1);
        assert!(ok.operations[0].claims_available);
        let err =
            parse(&json!({"operations": [{"operation_id": "a", "method": "GET"}]})).unwrap_err();
        assert_eq!(err, "operations[0].route_template: required");
        let err = parse(&json!({"operations": [{"operation_id": "a", "method": "GET", "route_template": "/x",
            "claims": [{"claim_id": "c", "examples": [{"target": "request_body", "origin": "observed"}]}]}]})).unwrap_err();
        assert!(err.contains("origin"), "{err}");
    }
}
