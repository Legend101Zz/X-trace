//! Canonical JSON and YAML emitters. Object keys are sorted explicitly so the
//! output never depends on the `serde_json` map implementation.

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

fn quote(s: &str) -> String {
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

fn sorted_entries(map: &serde_json::Map<String, Value>) -> Vec<(&String, &Value)> {
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

/// Canonical YAML (block style, sorted keys). Every string scalar is
/// double-quoted using JSON escapes, which YAML 1.2 accepts, so no scalar can
/// be re-typed by a YAML parser (`"yes"` stays a string).
#[must_use]
pub fn yaml(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) if !map.is_empty() => yaml_map(map, 0, &mut out),
        Value::Array(items) if !items.is_empty() => yaml_seq(items, 0, &mut out),
        other => {
            out.push_str(&yaml_scalar(other));
            out.push('\n');
        }
    }
    out
}

fn is_plain_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return false;
    }
    !matches!(
        key.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "y" | "n"
    )
}

fn yaml_key(key: &str) -> String {
    if is_plain_key(key) { key.to_owned() } else { quote(key) }
}

fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote(s),
        Value::Array(_) => "[]".to_owned(),
        Value::Object(_) => "{}".to_owned(),
    }
}

fn is_block(value: &Value) -> bool {
    match value {
        Value::Object(map) => !map.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => false,
    }
}

fn pad(out: &mut String, depth: usize) {
    for _ in 0..depth * 2 {
        out.push(' ');
    }
}

fn yaml_map(map: &serde_json::Map<String, Value>, depth: usize, out: &mut String) {
    for (key, value) in sorted_entries(map) {
        pad(out, depth);
        out.push_str(&yaml_key(key));
        out.push(':');
        yaml_child(value, depth, out);
    }
}

fn yaml_seq(items: &[Value], depth: usize, out: &mut String) {
    for item in items {
        pad(out, depth);
        out.push('-');
        yaml_child(item, depth, out);
    }
}

fn yaml_child(value: &Value, depth: usize, out: &mut String) {
    if is_block(value) {
        out.push('\n');
        match value {
            Value::Object(map) => yaml_map(map, depth + 1, out),
            Value::Array(items) => yaml_seq(items, depth + 1, out),
            _ => {}
        }
    } else {
        out.push(' ');
        out.push_str(&yaml_scalar(value));
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_in_json_and_yaml() {
        let v = json!({"b": 1, "a": {"z": [1, "x"], "c": null}});
        assert_eq!(json_compact(&v), r#"{"a":{"c":null,"z":[1,"x"]},"b":1}"#);
        assert_eq!(yaml(&v), "a:\n  c: null\n  z:\n    - 1\n    - \"x\"\nb: 1\n");
    }

    #[test]
    fn yaml_quotes_reserved_words_and_paths() {
        let v = json!({"yes": "no", "/orders/{id}": "1.0", "empty": [], "obj": {}});
        assert_eq!(yaml(&v), "\"/orders/{id}\": \"1.0\"\nempty: []\nobj: {}\n\"yes\": \"no\"\n");
    }

    #[test]
    fn pretty_json_is_stable() {
        let v = json!({"a": [1, 2], "b": {}});
        assert_eq!(json_pretty(&v), "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {}\n}\n");
    }
}
