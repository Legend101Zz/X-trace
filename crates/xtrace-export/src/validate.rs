//! Structural validator for generated OpenAPI 3.1 documents.
//!
//! This is NOT the official OpenAPI JSON Schema: that needs a JSON-Schema
//! crate that is not in the lockfile (request filed to the C surface). It
//! checks the rules a consumer trips over: version, required fields, path
//! parameter declaration, response shape and operationId uniqueness.

use std::collections::BTreeSet;

use serde_json::Value;

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

fn status_ok(status: &str) -> bool {
    if status == "default" {
        return true;
    }
    let b = status.as_bytes();
    b.len() == 3
        && (b'1'..=b'5').contains(&b[0])
        && b[1..].iter().all(|c| c.is_ascii_digit() || *c == b'X')
}

/// Returns every structural problem found (empty = passes).
#[must_use]
pub fn openapi_31(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(root) = doc.as_object() else {
        return vec!["document is not an object".to_owned()];
    };
    match root.get("openapi").and_then(Value::as_str) {
        Some(v) if v.starts_with("3.1.") => {}
        other => problems.push(format!("openapi must be 3.1.x, got {other:?}")),
    }
    match root.get("info").and_then(Value::as_object) {
        Some(info) => {
            for key in ["title", "version"] {
                if info.get(key).and_then(Value::as_str).is_none_or(str::is_empty) {
                    problems.push(format!("info.{key} is required"));
                }
            }
        }
        None => problems.push("info is required".to_owned()),
    }
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        problems.push("paths is required".to_owned());
        return problems;
    };
    let mut ids = BTreeSet::new();
    for (path, item) in paths {
        if !path.starts_with('/') {
            problems.push(format!("path {path} must start with /"));
        }
        let Some(item) = item.as_object() else {
            problems.push(format!("path item {path} is not an object"));
            continue;
        };
        let declared = crate::projection::path_param_names(path);
        for (method, op) in item {
            if !METHODS.contains(&method.as_str()) {
                if !method.starts_with("x-") {
                    problems.push(format!("{path}: unknown key {method}"));
                }
                continue;
            }
            let at = format!("{method} {path}");
            let Some(op) = op.as_object() else {
                problems.push(format!("{at}: operation is not an object"));
                continue;
            };
            if let Some(id) = op.get("operationId").and_then(Value::as_str) {
                if !ids.insert(id.to_owned()) {
                    problems.push(format!("{at}: duplicate operationId {id}"));
                }
            }
            let params: Vec<&serde_json::Map<String, Value>> = op
                .get("parameters")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_object).collect())
                .unwrap_or_default();
            let mut seen = BTreeSet::new();
            for p in &params {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let loc = p.get("in").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() {
                    problems.push(format!("{at}: parameter without name"));
                }
                if !matches!(loc, "path" | "query" | "header" | "cookie") {
                    problems.push(format!("{at}: parameter {name} has invalid in={loc}"));
                }
                if !seen.insert((name.to_owned(), loc.to_owned())) {
                    problems.push(format!("{at}: duplicate parameter {loc}:{name}"));
                }
                if loc == "path" && p.get("required") != Some(&Value::Bool(true)) {
                    problems.push(format!("{at}: path parameter {name} must be required: true"));
                }
                if p.get("schema").is_none() && p.get("content").is_none() {
                    problems.push(format!("{at}: parameter {name} needs schema or content"));
                }
            }
            for name in &declared {
                let ok = params.iter().any(|p| {
                    p.get("in").and_then(Value::as_str) == Some("path")
                        && p.get("name").and_then(Value::as_str) == Some(name)
                });
                if !ok {
                    problems.push(format!("{at}: path parameter {name} is not declared"));
                }
            }
            match op.get("responses").and_then(Value::as_object) {
                Some(r) if !r.is_empty() => {
                    for (status, resp) in r {
                        if !status_ok(status) {
                            problems.push(format!("{at}: bad response status {status}"));
                        }
                        if resp.get("description").and_then(Value::as_str).is_none() {
                            problems.push(format!("{at}: response {status} needs a description"));
                        }
                    }
                }
                _ => problems.push(format!("{at}: responses must be non-empty")),
            }
        }
    }
    problems
}
