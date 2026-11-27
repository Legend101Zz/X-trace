//! Sanitizer gate: a best-effort deny-list. Secret-shaped keys, key/value
//! text and well-known token shapes are refused. It is NOT proof that no
//! secret is present; the independent check is the shared Q canary scanner.

use serde_json::Value;

pub use xtrace_domain::secret_shapes::{
    has_secret_assignment, is_secret_name, is_secret_shape, is_secret_value, json_has_secret,
};

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
                let meta =
                    path.ends_with("/description") || metadata.iter().any(|m| path.starts_with(m));
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
                    // An object key (an OpenAPI path template, say) can carry a token shape.
                    if is_secret_shape(key) {
                        return Some(path.clone());
                    }
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
    fn token_shaped_object_keys_fail_the_gate() {
        let leaky = serde_json::json!({"paths": {"/keys/sk-abcdefghijklmnopqrstuvwxyz0123": {}}});
        assert!(gate(&leaky).is_some());
        let fine = serde_json::json!({"paths": {"/auth/token": {}, "/orders/{id}": {}}});
        assert_eq!(gate(&fine), None);
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
