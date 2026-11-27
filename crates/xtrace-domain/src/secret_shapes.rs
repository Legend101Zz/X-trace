//! Shared recognition of credential-shaped names, values and JSON fields.

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

/// Extra names only checked in `name<sep>value` text (short, so they need a
/// word boundary before them).
const SHORT_NAME_PARTS: &[&str] = &["pwd", "sig"];

/// True when text contains a secret-shaped name directly followed (after
/// optional whitespace) by `=`, `:`, `>` or a quote, as in `password: x`,
/// `apikey=x`, `<token>x` or a truncated JSON `"secret":`.
#[must_use]
pub fn has_secret_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // A quote after the name only counts as the JSON-key form `"name":`.
    let follows = |end: usize| {
        let rest = lower[end..].trim_start();
        match rest.chars().next() {
            Some('=' | ':' | '>') => true,
            Some('"' | '\'') => rest[1..].trim_start().starts_with(':'),
            _ => false,
        }
    };
    for part in SECRET_NAME_PARTS {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(part) {
            let end = from + pos + part.len();
            if follows(end) {
                return true;
            }
            from = end;
        }
    }
    for part in SHORT_NAME_PARTS {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(part) {
            let start = from + pos;
            let end = start + part.len();
            let boundary =
                lower[..start].chars().next_back().is_none_or(|c| !c.is_ascii_alphanumeric());
            if boundary && follows(end) {
                return true;
            }
            from = end;
        }
    }
    false
}

/// True when a string value looks like a credential regardless of its key.
#[must_use]
pub fn is_secret_value(value: &str) -> bool {
    is_secret_shape(value) || has_secret_assignment(value)
}

/// Token shapes, PEM blocks, bearer/basic runs, URL passwords and the
/// `password=`-style assignments only (no name-followed-by-separator scan).
#[must_use]
pub fn is_secret_shape(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("-----begin") || lower.contains("xtrace-canary") {
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
        || has_run(value, "sk_live_", 10, alnum)
        || has_run(value, "sk_test_", 10, alnum)
        || has_run(value, "rk_live_", 10, alnum)
        || has_run(value, "AIza", 30, alnum)
        || has_run(value, "ASIA", 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
        || has_run(value, "github_pat_", 20, alnum)
        || has_run(value, "gho_", 20, alnum)
        || has_run(value, "ghs_", 20, alnum)
        || has_run(value, "ghu_", 20, alnum)
        || has_run(value, "glpat-", 16, alnum)
        || ["xoxa-", "xoxp-", "xoxr-", "xoxs-"].iter().any(|p| has_run(value, p, 10, alnum))
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
