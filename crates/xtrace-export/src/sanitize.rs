//! Sanitizer gate: secret-shaped keys and values are never emitted.

use serde_json::Value;

const SECRET_NAME_PARTS: &[&str] = &[
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api-key",
    "api_key",
    "apikey",
    "credential",
    "session",
    "bearer",
    "private-key",
    "private_key",
    "x-amz-security",
    "signature",
];

/// True when a header, parameter or object-key name is secret-shaped.
#[must_use]
pub fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_NAME_PARTS.iter().any(|part| lower.contains(part))
}

fn has_run(s: &str, prefix: &str, min_tail: usize, ok: impl Fn(char) -> bool) -> bool {
    let mut from = 0;
    while let Some(pos) = s[from..].find(prefix) {
        let start = from + pos + prefix.len();
        let tail = s[start..].chars().take_while(|c| ok(*c)).count();
        if tail >= min_tail {
            return true;
        }
        from = start;
    }
    false
}

/// True when a string value looks like a credential regardless of its key.
#[must_use]
pub fn is_secret_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("-----begin") || lower.contains("canary") {
        return true;
    }
    if has_run(&lower, "bearer ", 8, |c| c.is_ascii_alphanumeric() || "-._~+/=".contains(c))
        || has_run(&lower, "basic ", 8, |c| c.is_ascii_alphanumeric() || "+/=".contains(c))
    {
        return true;
    }
    let alnum = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if has_run(value, "eyJ", 10, alnum) && value.matches('.').count() >= 2 {
        return true;
    }
    if has_run(value, "AKIA", 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
        || has_run(value, "ghp_", 20, alnum)
        || has_run(value, "xoxb-", 10, alnum)
        || has_run(value, "sk-", 20, alnum)
    {
        return true;
    }
    if lower.contains("password=") || lower.contains("secret=") || lower.contains("token=") {
        return true;
    }
    // userinfo with a password: scheme://user:pass@host
    if let Some(pos) = value.find("://") {
        let rest = &value[pos + 3..];
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if let Some((userinfo, _)) = authority.split_once('@') {
            if userinfo.contains(':') {
                return true;
            }
        }
    }
    false
}

/// True when a JSON value carries a secret-shaped key or string anywhere.
#[must_use]
pub fn json_has_secret(value: &Value) -> bool {
    match value {
        Value::String(s) => is_secret_value(s),
        Value::Array(items) => items.iter().any(json_has_secret),
        Value::Object(map) => {
            map.iter().any(|(key, item)| is_secret_name(key) || json_has_secret(item))
        }
        _ => false,
    }
}

/// Final gate over a finished document: any secret-shaped string value fails.
/// Returns the path of the first offender (never the value).
#[must_use]
pub fn gate(value: &Value) -> Option<String> {
    fn walk(value: &Value, path: &mut String) -> Option<String> {
        match value {
            Value::String(s) if is_secret_value(s) => Some(path.clone()),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push_str(&format!("/{i}"));
                    if let Some(found) = walk(item, path) {
                        return Some(found);
                    }
                    path.truncate(len);
                }
                None
            }
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    let len = path.len();
                    path.push('/');
                    path.push_str(key);
                    if let Some(item) = map.get(key) {
                        if let Some(found) = walk(item, path) {
                            return Some(found);
                        }
                    }
                    path.truncate(len);
                }
                None
            }
            _ => None,
        }
    }
    walk(value, &mut String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for n in ["Authorization", "X-Api-Key", "Set-Cookie", "sessionId", "client_secret"] {
            assert!(is_secret_name(n), "{n}");
        }
        for n in ["id", "page", "Content-Type", "X-Request-Id"] {
            assert!(!is_secret_name(n), "{n}");
        }
    }

    #[test]
    fn values() {
        for v in [
            "Bearer abcdefghijklmnop",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
            "AKIAABCDEFGHIJKLMNOP",
            "-----BEGIN PRIVATE KEY-----",
            "https://u:p@host/x",
            "xtrace-canary-1",
        ] {
            assert!(is_secret_value(v), "{v}");
        }
        for v in ["hello", "42", "https://example.com/a?b=c", "Basic", "sk-short"] {
            assert!(!is_secret_value(v), "{v}");
        }
    }
}
