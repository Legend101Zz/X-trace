//! Deterministic JSON encoding shared by plan identities and exports.

use serde_json::Value;

/// Compact canonical JSON (sorted keys, no whitespace).
#[must_use]
pub fn json_compact(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, &mut out, None, 0);
    out
}

/// Pretty canonical JSON (sorted keys, two-space indent, trailing newline).
#[must_use]
pub fn json_pretty(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, &mut out, Some(2), 0);
    out.push('\n');
    out
}

/// Quote a string with the same escaping used in canonical JSON.
#[must_use]
pub fn quote(s: &str) -> String {
    // `to_string` on a `&str` cannot fail; the fallback keeps the function total.
    serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""))
}

fn newline(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(step) = indent {
        out.push('\n');
        for _ in 0..step * depth {
            out.push(' ');
        }
    }
}

/// Iterate object members in canonical lexical key order.
#[must_use]
pub fn sorted_entries(map: &serde_json::Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
}

fn write_json(value: &Value, out: &mut String, indent: Option<usize>, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&quote(s)),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write_json(item, out, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (key, item)) in sorted_entries(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                out.push_str(&quote(key));
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_json(item, out, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push('}');
        }
    }
}
