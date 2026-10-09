//! POSIX `sh` cURL recipe generator.
//!
//! Every dynamic string reaches the script through [`sh_quote`] (single
//! quotes, embedded quote as `'\''`) or through a validated identifier, so no
//! catalog text can break out of its argument. Scripts are written with mode
//! 0644 and X-trace never executes them. `all.sh` runs only safe-method
//! recipes (GET/HEAD/OPTIONS); mutating recipes are listed as comments.

use std::collections::BTreeSet;

use crate::projection::{Prepared, PreparedOp, is_safe_method};
use crate::request::{ExportError, ExportFile, ExportOutput, Omission};
use crate::sanitize;

/// Single-quotes a string for POSIX `sh`. Returns `None` for strings that
/// contain NUL, which no shell argument can carry.
#[must_use]
pub fn sh_quote(s: &str) -> Option<String> {
    if s.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Some(out)
}

fn comment_safe(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

fn env_name(prefix: &str, name: &str, taken: &mut BTreeSet<String>) -> String {
    let mut base: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    base.truncate(40);
    let mut candidate = format!("{prefix}_{base}");
    if !taken.insert(candidate.clone()) {
        let digest = blake3::hash(name.as_bytes()).to_hex();
        candidate = format!("{prefix}_{base}_{}", &digest.as_str()[..6]);
        taken.insert(candidate.clone());
    }
    candidate
}

fn slug(path: &str) -> String {
    let mut s: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-');
    let mut s = s.to_owned();
    s.truncate(40);
    let s = s.trim_matches('-').to_owned();
    if s.is_empty() { "root".to_owned() } else { s }
}

struct Recipe {
    script: String,
    omissions: Vec<Omission>,
}

fn recipe(op: &PreparedOp, ordinal: u32) -> Recipe {
    let mut omissions = Vec::new();
    let mut omit = |what: String, reason: &str| {
        omissions.push(Omission {
            operation_id: op.operation_id.clone(),
            what,
            reason: reason.to_owned(),
        });
    };
    let mut taken = BTreeSet::new();
    taken.insert("BASE_URL".to_owned());
    let mut required_env: Vec<String> = vec!["BASE_URL".to_owned()];
    let mut args: Vec<String> = Vec::new();

    // URL: "${BASE_URL}" + quoted literals + "${VAR}" for path parameters.
    let mut url = String::from("\"${BASE_URL}\"");
    let mut rest = op.path.as_str();
    loop {
        match rest.find('{') {
            Some(open) => {
                let after = &rest[open + 1..];
                let Some(close) = after.find('}') else {
                    push_literal(&mut url, rest, &mut omit);
                    break;
                };
                push_literal(&mut url, &rest[..open], &mut omit);
                let name = &after[..close];
                let var = env_name("XT_PATH", name, &mut taken);
                required_env.push(var.clone());
                url.push_str(&format!("\"${{{var}}}\""));
                rest = &after[close + 1..];
            }
            None => {
                push_literal(&mut url, rest, &mut omit);
                break;
            }
        }
    }

    // query
    let mut first_query = true;
    for p in op.params.iter().filter(|p| p.location == "query") {
        if sanitize::is_secret_name(&p.name) {
            omit(format!("param:query:{}", p.name), "credential_not_embedded");
            continue;
        }
        let example = op
            .examples
            .iter()
            .find(|e| e.target == format!("param:{}", p.name))
            .map(|e| e.value.clone());
        let sep = if first_query { '?' } else { '&' };
        let key = format!("{sep}{}=", percent_encode(&p.name));
        match (example, p.required) {
            (Some(value), _) => {
                push_literal(&mut url, &format!("{key}{}", percent_encode(&value)), &mut omit);
                first_query = false;
            }
            (None, true) => {
                let var = env_name("XT_QUERY", &p.name, &mut taken);
                required_env.push(var.clone());
                push_literal(&mut url, &key, &mut omit);
                url.push_str(&format!("\"${{{var}}}\""));
                first_query = false;
            }
            (None, false) => omit(format!("param:query:{}", p.name), "optional_without_example"),
        }
    }

    // headers
    for p in op.params.iter().filter(|p| p.location == "header") {
        if !is_header_token(&p.name) {
            omit(format!("param:header:{}", p.name), "invalid_header_name");
            continue;
        }
        if sanitize::is_secret_name(&p.name) {
            if p.required {
                let var = env_name("XT_HEADER", &p.name, &mut taken);
                required_env.push(var.clone());
                args.push(format!("-H \"{}: ${{{var}}}\"", p.name));
            } else {
                omit(format!("param:header:{}", p.name), "credential_not_embedded");
            }
            continue;
        }
        let example = op.examples.iter().find(|e| e.target == format!("param:{}", p.name));
        match example {
            Some(e) if !e.value.contains(['\r', '\n']) => {
                if let Some(q) = sh_quote(&format!("{}: {}", p.name, e.value)) {
                    args.push(format!("-H {q}"));
                }
            }
            Some(_) => omit(format!("param:header:{}", p.name), "header_value_has_line_break"),
            None if p.required => {
                let var = env_name("XT_HEADER", &p.name, &mut taken);
                required_env.push(var.clone());
                args.push(format!("-H \"{}: ${{{var}}}\"", p.name));
            }
            None => omit(format!("param:header:{}", p.name), "optional_without_example"),
        }
    }

    // body
    if let Some(media) = &op.request_media {
        if let Some(q) =
            sh_quote(&format!("Content-Type: {media}")).filter(|_| !media.contains(['\r', '\n']))
        {
            args.push(format!("-H {q}"));
        }
        match op
            .examples
            .iter()
            .find(|e| e.target == "request_body")
            .and_then(|e| sh_quote(&e.value))
        {
            Some(q) => args.push(format!("--data-binary {q}")),
            None => omit("request_body".to_owned(), "no_body_example"),
        }
    }

    let mutating = !is_safe_method(&op.method);
    let method_q = sh_quote(&op.method).unwrap_or_else(|| "''".to_owned());
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    s.push_str("# Generated by X-trace. X-trace never runs this file.\n");
    s.push_str(&format!("# operation: {}\n", comment_safe(&op.operation_id)));
    s.push_str(&format!("# route: {} {}\n", comment_safe(&op.method), comment_safe(&op.path)));
    s.push_str(&format!("# catalog state: {}\n", op.state.name()));
    if mutating {
        s.push_str(&format!(
            "# MUTATING: {} may change state on the target. Review it before running.\n",
            comment_safe(&op.method)
        ));
    }
    s.push_str(&format!("# recipe {ordinal:03}\n"));
    s.push_str("set -eu\n");
    for var in &required_env {
        if var == "BASE_URL" {
            s.push_str(": \"${BASE_URL:?set BASE_URL, for example http://127.0.0.1:8080}\"\n");
        } else {
            s.push_str(&format!(": \"${{{var}:?set {var}}}\"\n"));
        }
    }
    s.push_str(&format!("curl --silent --show-error --fail-with-body -X {method_q}"));
    for a in &args {
        s.push_str(" \\\n  ");
        s.push_str(a);
    }
    s.push_str(" \\\n  ");
    s.push_str(&url);
    s.push('\n');
    Recipe { script: s, omissions }
}

fn push_literal(url: &mut String, literal: &str, omit: &mut impl FnMut(String, &str)) {
    if literal.is_empty() {
        return;
    }
    match sh_quote(literal) {
        Some(q) => url.push_str(&q),
        None => omit("path_literal".to_owned(), "contains_nul"),
    }
}

/// File name for the recipe at `index` (1-based) of `op`.
fn file_name(index: usize, op: &PreparedOp) -> String {
    format!(
        "{index:03}-{}-{}.sh",
        op.method
            .to_ascii_lowercase()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>(),
        slug(&op.path)
    )
}

/// Renders one `.sh` per operation plus a non-executing-by-default `all.sh`.
///
/// # Errors
///
/// Fails when a generated script contains a secret-shaped value.
pub fn render(prepared: &Prepared) -> Result<ExportOutput, ExportError> {
    let mut files = Vec::new();
    let mut omissions = prepared.omissions.clone();
    let mut all = String::new();
    all.push_str("#!/bin/sh\n");
    all.push_str("# Generated by X-trace. Run it yourself: `sh all.sh`. X-trace never does.\n");
    all.push_str("# Only safe-method recipes (GET/HEAD/OPTIONS) are invoked here.\n");
    all.push_str("# Mutating recipes are listed as comments and must be run one by one.\n");
    all.push_str("set -u\n");
    all.push_str("DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n");
    for (i, op) in prepared.ops.iter().enumerate() {
        let name = file_name(i + 1, op);
        let r = recipe(op, u32::try_from(i + 1).unwrap_or(u32::MAX));
        if let Some(path) = secret_in(&r.script) {
            return Err(ExportError::SecretShaped { path: format!("{name}:{path}") });
        }
        omissions.extend(r.omissions);
        if is_safe_method(&op.method) {
            all.push_str(&format!("sh \"$DIR/{name}\"\n"));
        } else {
            all.push_str(&format!("# not run (mutating {}): {name}\n", comment_safe(&op.method)));
        }
        files.push(ExportFile { path: name, mode: 0o644, bytes: r.script.into_bytes() });
    }
    files.push(ExportFile { path: "all.sh".to_owned(), mode: 0o644, bytes: all.into_bytes() });
    Ok(crate::finish(files, omissions))
}

fn secret_in(script: &str) -> Option<String> {
    script
        .lines()
        .enumerate()
        .find(|(_, line)| sanitize::is_secret_value(line))
        .map(|(n, _)| format!("line {}", n + 1))
}
