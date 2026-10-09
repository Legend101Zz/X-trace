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
    let mut child = Command::new("/bin/sh")
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
    assert!(out.status.success(), "sh failed: {}", String::from_utf8_lossy(&out.stderr));
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
    let mut wrapped = String::from("curl() { printf '%s\\0' \"$@\"; }\n");
    for (k, v) in env {
        wrapped.push_str(&format!("{k}={}; export {k}\n", sh_quote(v).unwrap()));
    }
    // Drop the shebang; the rest is plain sh.
    wrapped.push_str(script.split_once('\n').unwrap().1);
    let out = run_sh(&wrapped, &[]);
    let mut parts: Vec<String> =
        out.split(|b| *b == 0).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    parts.pop();
    parts
}

#[test]
fn hostile_catalog_text_cannot_escape_the_recipe() {
    let mut rng = Rng(42);
    for round in 0..200 {
        let route_tail = rng.hostile().replace(['{', '}'], "");
        let route = format!("/h/{{id}}/{route_tail}");
        let body = rng.hostile();
        let header_val = rng.hostile().replace(['\r', '\n'], "");
        let mut c = claim("c");
        c.params = vec![
            param("id", "path", "string", true),
            param("X-Trace-Hdr", "header", "string", true),
        ];
        c.request_body_media_type = Some("text/plain".into());
        c.responses = vec![response("200", "ok")];
        c.examples = vec![
            example("request_body", "b", ExampleOrigin::Scenario, &body),
            example("param:X-Trace-Hdr", "h", ExampleOrigin::Scenario, &header_val),
        ];
        let mut input = spring_orders();
        input.operations = vec![op("op-h", "POST", &route, vec![c])];
        let out = export(&input, &ExportRequest::new(ExportFormat::Curl)).unwrap();
        let script = text(out.files.iter().find(|f| f.path.starts_with("001-")).unwrap());
        let id_value = format!("v{}", rng.hostile());
        let argv =
            recipe_argv(script, &[("BASE_URL", "http://h.invalid"), ("XT_PATH_ID", &id_value)]);
        let url = argv.last().unwrap();
        assert_eq!(
            url,
            &format!("http://h.invalid/h/{id_value}/{}", normalised(&route_tail)),
            "round {round}"
        );
        assert!(argv.contains(&"--data-binary".to_owned()), "round {round}");
        let at = argv.iter().position(|a| a == "--data-binary").unwrap();
        assert_eq!(argv[at + 1], body, "round {round}");
        assert!(argv.contains(&format!("X-Trace-Hdr: {header_val}")), "round {round}");
        assert_eq!(argv[argv.iter().position(|a| a == "-X").unwrap() + 1], "POST");
    }
}

/// The route text after normalisation: `:name` segments become `{name}`, which
/// the recipe turns into a placeholder, so test routes avoid leading ':' and
/// braces; everything else is literal.
fn normalised(tail: &str) -> String {
    tail.split('/').map(|s| s.to_owned()).collect::<Vec<_>>().join("/")
}
