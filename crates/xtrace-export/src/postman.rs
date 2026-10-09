//! Postman Collection v2.1 projector (local file only; nothing is uploaded).
//!
//! Secret-named parameters never carry a value: a required one becomes a
//! `{{variable}}` placeholder, an optional one is omitted and listed. The
//! collection variable `baseUrl` is empty so the user chooses the target.

use serde_json::{Map, Value, json};

use crate::projection::{Prepared, PreparedOp};
use crate::request::{ExportError, ExportFile, ExportOutput, Omission};
use crate::{canonical, sanitize};

fn var_name(prefix: &str, name: &str) -> String {
    let base: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("{prefix}_{base}")
}

fn item(op: &PreparedOp, omissions: &mut Vec<Omission>) -> Value {
    let mut omit = |what: String, reason: &str| {
        omissions.push(Omission {
            operation_id: op.operation_id.clone(),
            what,
            reason: reason.to_owned(),
        });
    };
    let example = |target: &str| op.examples.iter().find(|e| e.target == target);

    let mut variables = Vec::new();
    let segments: Vec<String> = op
        .path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => {
                variables.push(json!({"key": name, "value": ""}));
                format!(":{name}")
            }
            None => seg.to_owned(),
        })
        .collect();

    let mut query = Vec::new();
    for p in op.params.iter().filter(|p| p.location == "query") {
        if sanitize::is_secret_name(&p.name) {
            omit(format!("param:query:{}", p.name), "credential_not_embedded");
            continue;
        }
        match (example(&format!("param:{}", p.name)), p.required) {
            (Some(e), _) => query.push(json!({"key": p.name, "value": e.value})),
            (None, true) => query.push(
                json!({"key": p.name, "value": format!("{{{{{}}}}}", var_name("query", &p.name))}),
            ),
            (None, false) => omit(format!("param:query:{}", p.name), "optional_without_example"),
        }
    }

    let mut header = Vec::new();
    for p in op.params.iter().filter(|p| p.location == "header") {
        if sanitize::is_secret_name(&p.name) {
            if p.required {
                let v = format!("{{{{{}}}}}", var_name("header", &p.name));
                header.push(json!({"key": p.name, "value": v}));
            } else {
                omit(format!("param:header:{}", p.name), "credential_not_embedded");
            }
            continue;
        }
        match (example(&format!("param:{}", p.name)), p.required) {
            (Some(e), _) if !e.value.contains(['\r', '\n']) => {
                header.push(json!({"key": p.name, "value": e.value}));
            }
            (Some(_), _) => omit(format!("param:header:{}", p.name), "header_value_has_line_break"),
            (None, true) => {
                let v = format!("{{{{{}}}}}", var_name("header", &p.name));
                header.push(json!({"key": p.name, "value": v}));
            }
            (None, false) => omit(format!("param:header:{}", p.name), "optional_without_example"),
        }
    }

    let mut request = Map::new();
    request.insert("method".into(), json!(op.method));
    let mut body = None;
    if let Some(media) = &op.request_media {
        header.push(json!({"key": "Content-Type", "value": media}));
        match example("request_body") {
            Some(e) => {
                body = Some(json!({"mode": "raw", "raw": e.value}));
            }
            None => omit("request_body".to_owned(), "no_body_example"),
        }
    }
    request.insert("header".into(), Value::Array(header));
    if let Some(b) = body {
        request.insert("body".into(), b);
    }
    let raw_path = segments.join("/");
    let mut raw = format!("{{{{baseUrl}}}}/{raw_path}");
    if !query.is_empty() {
        let q: Vec<String> = query
            .iter()
            .map(|q| {
                format!(
                    "{}={}",
                    q["key"].as_str().unwrap_or_default(),
                    q["value"].as_str().unwrap_or_default()
                )
            })
            .collect();
        raw.push('?');
        raw.push_str(&q.join("&"));
    }
    let mut url = json!({"raw": raw, "host": ["{{baseUrl}}"], "path": segments});
    if let Value::Object(u) = &mut url {
        if !query.is_empty() {
            u.insert("query".into(), Value::Array(query));
        }
        if !variables.is_empty() {
            u.insert("variable".into(), Value::Array(variables));
        }
    }
    request.insert("url".into(), url);
    let observation =
        if op.state == crate::request::EffectiveState::Observed { "observed" } else { "inferred" };
    request.insert(
        "description".into(),
        json!(format!(
            "operation: {}\ncatalog state: {}\nx-xtrace-observation: {observation}",
            op.operation_id,
            op.state.name()
        )),
    );
    json!({"name": format!("{} {}", op.method, op.path), "request": Value::Object(request)})
}

/// Renders `collection.postman.json`.
///
/// # Errors
///
/// Fails when the sanitizer gate finds a secret-shaped value.
pub fn render(prepared: &Prepared) -> Result<ExportOutput, ExportError> {
    let mut omissions = prepared.omissions.clone();
    let items: Vec<Value> = prepared.ops.iter().map(|op| item(op, &mut omissions)).collect();
    let rev = &prepared.revision;
    let name = if rev.application_name.is_empty() {
        "X-trace catalog export".to_owned()
    } else {
        rev.application_name.clone()
    };
    let doc = json!({
        "info": {
            "name": name,
            "description": format!(
                "Generated by X-trace from catalog revision {} ({}). Local file; nothing is uploaded. Set the baseUrl variable before sending.",
                rev.revision_id, rev.catalog_hash
            ),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [{"key": "baseUrl", "value": ""}],
        "item": items,
    });
    if let Some(path) = sanitize::gate(&doc) {
        return Err(ExportError::SecretShaped { path });
    }
    let file = ExportFile {
        path: "collection.postman.json".to_owned(),
        mode: 0o644,
        bytes: canonical::json_pretty(&doc).into_bytes(),
    };
    Ok(crate::finish(vec![file], omissions))
}
