//! Sanitizer gate: a best-effort deny-list. Secret-shaped keys, key/value
//! text and well-known token shapes are refused. It is NOT proof that no
//! secret is present; the independent check is the shared Q canary scanner.

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

/// Final gate over a finished document: any secret-shaped string value fails.
/// Returns the path of the first offender (never the value).
#[must_use]
pub fn gate(value: &Value) -> Option<String> {
    gate_with_metadata(value, &[])
}

/// Like [`gate`], but strings under any of the `metadata` JSON-pointer
/// prefixes (for example the omissions list, which names dropped secret-named
/// fields on purpose) get the token-shape check only, not the name scan.
#[must_use]
pub fn gate_with_metadata(value: &Value, metadata: &[&str]) -> Option<String> {
    fn walk(value: &Value, path: &mut String, metadata: &[&str]) -> Option<String> {
        match value {
            Value::String(s) => {
                // Free-text descriptions are prose: token shapes only, no name scan.
                let meta = path.ends_with("/description")
                    || metadata.iter().any(|m| path.starts_with(m));
                let bad = if meta { is_secret_shape(s) } else { is_secret_value(s) };
                bad.then(|| path.clone())
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push_str(&format!("/{i}"));
                    if let Some(found) = walk(item, path, metadata) {
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
                        if let Some(found) = walk(item, path, metadata) {
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
    walk(value, &mut String::new(), metadata)
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

    #[test]
    fn table_positive_text_forms() {
        for v in [
            "password: hunter2",
            "<password>hunter2</password>",
            "{\"password\":\"x\",}",
            "apikey=abc123",
            "api_key = abc",
            "passwd=x",
            "pwd=x",
            "sig=abcdef",
            "client_secret: s",
            "credential=zzz",
            "authorization: Negotiate abc",
            "a=1&token=abc&b=2",
            "<token>abc</token>",
            "sk_live_abcdefghijklmnop",
            "rk_live_abcdefghijklmnop",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "ASIAABCDEFGHIJKLMNOP",
            "github_pat_11ABCDEFG0123456789abc",
            "gho_abcdefghijklmnopqrstuv",
            "ghs_abcdefghijklmnopqrstuv",
            "ghu_abcdefghijklmnopqrstuv",
            "glpat-abcdefghijklmnopqrst",
            "xoxp-1234567890-abc",
            "xoxa-1234567890-abc",
            "xoxr-1234567890-abc",
            "xoxs-1234567890-abc",
            "sk_test_abcdefghijklmnop",
        ] {
            assert!(is_secret_value(v), "{v}");
        }
    }

    #[test]
    fn table_negative_text_forms() {
        for v in [
            "design: modern",
            "the session expires soon",
            "tokens are discussed elsewhere",
            "/auth/token",
            "'/oauth/token'",
            "\"${BASE_URL}\"'/api/session'",
            "'/auth/password' \\",
            "/csrf-token",
            "/canary/deploy",
            "sigma=3",
            "application/json",
            "{\"name\":\"Ada\",\"count\":3}",
            "<name>Ada</name>",
            "page=2&limit=10",
        ] {
            assert!(!is_secret_value(v), "{v}");
        }
    }
}
