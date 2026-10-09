//! cURL recipe quoting against a real POSIX `sh`. Fixture input only.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{claim, example, op, param, response, spring_orders, text};
use xtrace_export::curl::sh_quote;
use xtrace_export::{ExampleOrigin, ExportFormat, ExportRequest, export};

const ALPHABET: &[&str] = &[
    "'",
    "\"",
    "\\",
    "$",
    "`",
    "\n",
    "\r",
    "\t",
    ";",
    "&",
    "|",
    "*",
    "?",
    " ",
    "!",
    "#",
    "%",
    "~",
    "{",
    "}",
    "(",
    ")",
    "<",
    ">",
    "[",
    "]",
    "=",
    "$(id)",
    "`id`",
    "${X}",
    "'; echo pwned; '",
    "\\'",
    "--",
    "-n",
    "é",
    "日本",
    "\u{7f}",
    "\u{1b}[31m",
    "@",
    "@/etc/hosts",
    "$(touch pwnflag)",
    "`touch pwnflag`",
    "a",
    "Z",
    "0",
    "/",
    ".",
    "-",
    "_",
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn hostile(&mut self) -> String {
        let len = (self.next() % 24) as usize;
        (0..len).map(|_| ALPHABET[(self.next() as usize) % ALPHABET.len()]).collect()
    }
}

fn run_sh(script: &str, args: &[&str]) -> Vec<u8> {
    run_sh_in(script, args, std::path::Path::new("."))
}

fn run_sh_in(script: &str, args: &[&str], cwd: &std::path::Path) -> Vec<u8> {
    let mut child = Command::new("/bin/sh")
        .current_dir(cwd)
        .arg("-s")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Write on a thread: sh fills the stdout pipe while we are still writing.
    let mut stdin = child.stdin.take().unwrap();
    let bytes = script.as_bytes().to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(
        out.status.success(),
        "sh failed: {}\nscript tail: {:?}",
        String::from_utf8_lossy(&out.stderr),
        script.lines().rev().take(14).collect::<Vec<_>>()
    );
    out.stdout
}

#[test]
fn curl_quoting_roundtrips_hostile_inputs_10k() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let inputs: Vec<String> = (0..10_000).map(|_| rng.hostile()).collect();
    let mut script = String::new();
    for s in &inputs {
        script.push_str(&format!("printf '%s\\0' {}\n", sh_quote(s).unwrap()));
    }
    let out = run_sh(&script, &[]);
    let got: Vec<&[u8]> = out.split(|b| *b == 0).collect();
    // trailing empty chunk after the last NUL
    assert_eq!(got.len(), inputs.len() + 1);
    for (i, s) in inputs.iter().enumerate() {
        assert_eq!(got[i], s.as_bytes(), "input {i}: {s:?}");
    }
}

#[test]
fn nul_cannot_be_quoted() {
    assert_eq!(sh_quote("a\0b"), None);
    assert_eq!(sh_quote("").as_deref(), Some("''"));
    assert_eq!(sh_quote("it's").as_deref(), Some("'it'\\''s'"));
}

/// Runs a generated recipe with `curl` replaced by an argv printer, so the
/// test sees exactly the arguments curl would receive.
fn recipe_argv(script: &str, env: &[(&str, &str)]) -> Vec<String> {
    recipe_argv_in(script, env, std::path::Path::new("."))
}

fn recipe_argv_in(script: &str, env: &[(&str, &str)], cwd: &std::path::Path) -> Vec<String> {
    let mut wrapped = String::from("curl() { printf '%s\\0' \"$@\"; }\n");
    for (k, v) in env {
        wrapped.push_str(&format!("{k}={}; export {k}\n", sh_quote(v).unwrap()));
    }
    // Drop the shebang; the rest is plain sh.
    wrapped.push_str(script.split_once('\n').unwrap().1);
    let out = run_sh_in(&wrapped, &[], cwd);
    let mut parts: Vec<String> =
        out.split(|b| *b == 0).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    parts.pop();
    parts
}

const TCHAR_EXTRA: &[&str] =
    &["$", "`", "!", "#", "%", "&", "'", "*", "+", "^", "|", "~", ".", "-", "_"];

/// A header name made only of RFC token characters, including the shell
/// metacharacters `$` and the backtick, and never secret-shaped.
fn hostile_header_name(rng: &mut Rng) -> String {
    loop {
        let len = 1 + (rng.next() % 12) as usize;
        let mut n = String::from("X");
        for _ in 0..len {
            match rng.next() % 6 {
                0 => n.push_str("$(touch pwnflag)".replace([' ', '(', ')'], "").as_str()),
                1 => n.push_str("`touch${IFS}pwnflag`"),
                2 => n.push('a'),
                _ => n.push_str(TCHAR_EXTRA[(rng.next() as usize) % TCHAR_EXTRA.len()]),
            }
        }
        if !xtrace_export::sanitize::is_secret_name(&n)
            && n.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
        {
            return n;
        }
        // `{` / `}` / `(` would not pass the token check anyway
        let cleaned: String = n
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(*c))
            .collect();
        if !xtrace_export::sanitize::is_secret_name(&cleaned) {
            return cleaned;
        }
    }
}

fn pct(s: &str) -> String {
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

fn env_var_for(name: &str) -> String {
    let mut base: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    base.truncate(40);
    format!("XT_HEADER_{base}")
}

#[test]
fn hostile_catalog_text_cannot_escape_the_recipe() {
    let dir = std::env::temp_dir().join(format!("xtrace-w-curl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = Rng(42);
    let mut refused = 0;
    for round in 0..300 {
        let route_tail = rng.hostile().replace(['{', '}'], "");
        let route = format!("/h/{{id}}/{route_tail}");
        let body = rng.hostile();
        let header_val = rng.hostile().replace(['\r', '\n'], "");
        let req_header = hostile_header_name(&mut rng);
        let val_header = format!("{}v", hostile_header_name(&mut rng));
        let query_name = format!("q{}", rng.hostile());
        let query_val = rng.hostile();
        let tainted = |t: &str| {
            xtrace_export::sanitize::is_secret_name(t)
                || xtrace_export::sanitize::is_secret_value(t)
        };
        // Dropped-by-design examples are covered by export tests; here every
        // generated value must survive so the argv can be compared exactly.
        if [&body, &header_val, &query_name, &query_val].iter().any(|t| tainted(t)) {
            refused += 1;
            continue;
        }
        let media = format!("text/{}", rng.hostile().replace(['\r', '\n'], ""));
        let op_id = rng.hostile();
        let binding = rng.hostile();
        let mut c = claim("c");
        c.params = vec![
            param("id", "path", "string", true),
            param(&req_header, "header", "string", true),
            param(&val_header, "header", "string", false),
            param(&query_name, "query", "string", true),
        ];
        c.request_body_media_type = Some(media.clone());
        c.responses = vec![response("200", "ok")];
        c.examples = vec![
            example("request_body", "b", ExampleOrigin::Scenario, &body),
            example(&format!("param:{val_header}"), "h", ExampleOrigin::Scenario, &header_val),
            example(&format!("param:{query_name}"), "q", ExampleOrigin::Scenario, &query_val),
        ];
        let mut input = spring_orders();
        let mut o = op(&op_id, "POST", &route, vec![c]);
        o.binding_key = binding;
        input.operations = vec![o];
        // The gate may refuse hostile text that looks like `passwd'`; that is
        // the safe outcome, so such rounds only count as refused.
        let Ok(out) = export(&input, &ExportRequest::new(ExportFormat::Curl)) else {
            refused += 1;
            continue;
        };
        let script = text(out.files.iter().find(|f| f.path.starts_with("001-")).unwrap());
        let id_value = format!("v{}", rng.hostile());
        let req_value = rng.hostile().replace(['\r', '\n'], "");
        let req_var = env_var_for(&req_header);
        let argv = recipe_argv_in(
            script,
            &[("BASE_URL", "http://h.invalid"), ("XT_PATH_ID", &id_value), (&req_var, &req_value)],
            &dir,
        );
        let url = argv.last().unwrap();
        assert_eq!(
            url,
            &format!(
                "http://h.invalid/h/{id_value}/{}?{}={}",
                normalised(&route_tail),
                pct(&query_name),
                pct(&query_val)
            ),
            "round {round}"
        );
        // @ must never reach curl's --data (file reading); --data-raw only.
        assert!(!argv.iter().any(|a| a.starts_with("--data-binary") || a == "-d" || a == "--data"));
        let at = argv.iter().position(|a| a == "--data-raw").expect("--data-raw");
        assert_eq!(argv[at + 1], body, "round {round}");
        assert!(argv.contains(&format!("{val_header}: {header_val}")), "round {round}");
        assert!(
            argv.contains(&format!("{req_header}: {req_value}")),
            "round {round}: {req_header:?}"
        );
        assert!(argv.contains(&format!("Content-Type: {media}")), "round {round}");
        assert!(argv.contains(&"--globoff".to_owned()));
        assert!(argv.contains(&"=http,https".to_owned()));
        assert_eq!(argv[argv.iter().position(|a| a == "-X").unwrap() + 1], "POST");
        assert!(!dir.join("pwnflag").exists(), "pwnflag side effect in round {round}");
    }
    assert!(refused < 150, "gate refused too many rounds: {refused}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hostile_method_cannot_escape_the_recipe() {
    let dir = std::env::temp_dir().join(format!("xtrace-w-curlm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = claim("c");
    c.responses = vec![response("200", "ok")];
    let mut input = spring_orders();
    input.operations = vec![op("op-m", "GET; touch pwnflag", "/m", vec![c])];
    if let Ok(out) = export(&input, &ExportRequest::new(ExportFormat::Curl)) {
        for f in out.files.iter().filter(|f| f.path != "all.sh") {
            let _ = recipe_argv_in(text(f), &[("BASE_URL", "http://h.invalid")], &dir);
        }
    }
    assert!(!dir.join("pwnflag").exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// The route text after normalisation: `:name` segments become `{name}`, which
/// the recipe turns into a placeholder, so test routes avoid leading ':' and
/// braces; everything else is literal.
fn normalised(tail: &str) -> String {
    tail.split('/').map(|s| s.to_owned()).collect::<Vec<_>>().join("/")
}
