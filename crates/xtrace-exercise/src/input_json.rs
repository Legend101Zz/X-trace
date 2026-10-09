//! JSON file codec for [`PlanInput`]: the interim input path until the
//! catalog read port is wired. Plans built from such a file are fixture-style
//! input, not catalog evidence.

use serde_json::Value;

use crate::candidate::{CandidateOp, CandidateParam, ChangeKind, PlanInput};
use crate::effect::Effect;

type Obj = serde_json::Map<String, Value>;

fn obj<'a>(v: &'a Value, at: &str) -> Result<&'a Obj, String> {
    v.as_object().ok_or_else(|| format!("{at}: expected an object"))
}

fn text(o: &Obj, key: &str, at: &str) -> Result<String, String> {
    match o.get(key) {
        Some(Value::String(v)) => Ok(v.clone()),
        Some(_) => Err(format!("{at}.{key}: expected a string")),
        None => Ok(String::new()),
    }
}

fn required(o: &Obj, key: &str, at: &str) -> Result<String, String> {
    let v = text(o, key, at)?;
    if v.is_empty() { Err(format!("{at}.{key}: required")) } else { Ok(v) }
}

fn opt_text(o: &Obj, key: &str, at: &str) -> Result<Option<String>, String> {
    match o.get(key) {
        Some(Value::String(v)) => Ok(Some(v.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("{at}.{key}: expected a string")),
    }
}

fn flag(o: &Obj, key: &str, at: &str) -> Result<bool, String> {
    match o.get(key) {
        Some(Value::Bool(v)) => Ok(*v),
        Some(_) => Err(format!("{at}.{key}: expected a boolean")),
        None => Ok(false),
    }
}

fn items<'a>(o: &'a Obj, key: &str, at: &str) -> Result<&'a [Value], String> {
    match o.get(key) {
        Some(Value::Array(v)) => Ok(v),
        Some(_) => Err(format!("{at}.{key}: expected an array")),
        None => Ok(&[]),
    }
}

fn param(v: &Value, at: &str) -> Result<CandidateParam, String> {
    let o = obj(v, at)?;
    Ok(CandidateParam {
        name: required(o, "name", at)?,
        location: required(o, "location", at)?,
        required: flag(o, "required", at)?,
        scenario_value: opt_text(o, "scenario_value", at)?,
        claim_example: opt_text(o, "claim_example", at)?,
        default_value: opt_text(o, "default_value", at)?,
    })
}

fn effect(name: &str, at: &str) -> Result<Effect, String> {
    match name {
        "read_only" => Ok(Effect::ReadOnly),
        "mutating" => Ok(Effect::Mutating),
        "unknown" => Ok(Effect::Unknown),
        other => Err(format!("{at}: unknown effect {other:?}")),
    }
}

fn candidate(v: &Value, at: &str) -> Result<CandidateOp, String> {
    let o = obj(v, at)?;
    let change_kind = match text(o, "change_kind", at)?.as_str() {
        "added" => ChangeKind::Added,
        "changed" => ChangeKind::Changed,
        "unchanged" => ChangeKind::Unchanged,
        "" | "unknown" => ChangeKind::Unknown,
        other => return Err(format!("{at}.change_kind: unknown value {other:?}")),
    };
    let observed_recording_count = match o.get("observed_recording_count") {
        Some(Value::Number(n)) => Some(
            n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| format!("{at}.observed_recording_count: expected a u32"))?,
        ),
        Some(Value::Null) | None => None,
        Some(_) => return Err(format!("{at}.observed_recording_count: expected a number")),
    };
    let mut effect_hints = Vec::new();
    for (i, h) in items(o, "effect_hints", at)?.iter().enumerate() {
        let name =
            h.as_str().ok_or_else(|| format!("{at}.effect_hints[{i}]: expected a string"))?;
        effect_hints.push(effect(name, &format!("{at}.effect_hints[{i}]"))?);
    }
    let mut params = Vec::new();
    for (i, p) in items(o, "params", at)?.iter().enumerate() {
        params.push(param(p, &format!("{at}.params[{i}]"))?);
    }
    Ok(CandidateOp {
        operation_id: required(o, "operation_id", at)?,
        method: required(o, "method", at)?,
        route_template: required(o, "route_template", at)?,
        change_kind,
        observed_recording_count,
        conflicted: flag(o, "conflicted", at)?,
        effect_hints,
        params,
    })
}

/// Parses a plan-input JSON document.
///
/// # Errors
///
/// Returns a message naming the offending field.
pub fn parse(text_in: &str) -> Result<PlanInput, String> {
    let root: Value = serde_json::from_str(text_in).map_err(|e| format!("invalid JSON: {e}"))?;
    let o = obj(&root, "$")?;
    let mut ops = Vec::new();
    for (i, v) in items(o, "ops", "$")?.iter().enumerate() {
        ops.push(candidate(v, &format!("$.ops[{i}]"))?);
    }
    let explicit_selection = match o.get("explicit_selection") {
        Some(Value::Array(v)) => {
            let mut ids = Vec::new();
            for (i, id) in v.iter().enumerate() {
                ids.push(
                    id.as_str()
                        .ok_or_else(|| format!("$.explicit_selection[{i}]: expected a string"))?
                        .to_owned(),
                );
            }
            Some(ids)
        }
        Some(Value::Null) | None => None,
        Some(_) => return Err("$.explicit_selection: expected an array".to_owned()),
    };
    Ok(PlanInput {
        revision_id: required(o, "revision_id", "$")?,
        catalog_hash: required(o, "catalog_hash", "$")?,
        target: required(o, "target", "$")?,
        ops,
        explicit_selection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        let ok = r#"{"revision_id":"r","catalog_hash":"h","target":"http://127.0.0.1:1",
            "ops":[{"operation_id":"a","method":"get","route_template":"/a","change_kind":"added",
            "effect_hints":["read_only"],"params":[{"name":"id","location":"path","required":true,"scenario_value":"7"}]}]}"#;
        let p = parse(ok).unwrap();
        assert_eq!(p.ops.len(), 1);
        assert_eq!(p.ops[0].params[0].scenario_value.as_deref(), Some("7"));
        assert!(parse("{}").unwrap_err().contains("revision_id"));
        assert!(parse("[]").is_err());
        assert!(parse(&ok.replace("read_only", "nope")).unwrap_err().contains("effect"));
    }
}
