//! cURL recipe set. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{assert_golden, spring_orders, text};
use xtrace_export::{ExportFormat, ExportOutput, ExportRequest, export};

fn out() -> ExportOutput {
    export(&spring_orders(), &ExportRequest::new(ExportFormat::Curl)).unwrap()
}

#[test]
fn curl_golden() {
    let o = out();
    let names: Vec<&str> = o.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        names,
        [
            "001-get-orders.sh",
            "002-get-orders.sh",
            "003-post-orders.sh",
            "004-get-orders-id.sh",
            "005-delete-orders-id.sh",
            "all.sh"
        ]
    );
    for f in &o.files {
        assert_golden(&format!("curl/{}", f.path), &f.bytes);
    }
}

#[test]
fn curl_all_sh_prints_and_never_executes() {
    let o = out();
    let all = text(o.files.iter().find(|f| f.path == "all.sh").unwrap());
    assert!(all.contains("001-get-orders.sh"));
    assert!(all.contains("MUTATING"));
    assert!(!all.contains("curl"), "all.sh must not contain curl itself");
    for line in all.lines().filter(|l| !l.starts_with('#') && !l.starts_with("set ")) {
        assert!(line.starts_with("printf '%s\\n' 'sh "), "all.sh runs something: {line}");
        assert!(!line.contains("$DIR") && !line.contains('`'), "{line}");
    }
    assert!(!all.contains("DIR="), "no directory resolution needed: nothing is executed");
}

#[test]
fn curl_mutation_label_present() {
    let o = out();
    for f in &o.files {
        let t = text(f);
        let mutating = t.contains("-X 'POST'") || t.contains("-X 'DELETE'");
        assert_eq!(t.contains("# MUTATING:"), mutating, "{}", f.path);
    }
    assert!(o.files.iter().any(|f| text(f).contains("# MUTATING:")));
}

#[test]
fn curl_scripts_not_marked_executable() {
    for f in out().files {
        assert_eq!(f.mode & 0o111, 0, "{}", f.path);
    }
}

#[test]
fn curl_no_secret_values() {
    for f in out().files {
        let t = text(&f);
        for needle in ["hunter2", "canary", "abcdefghijklmnopqrstuvwxyz", "Bearer "] {
            assert!(!t.contains(needle), "{} leaked {needle}", f.path);
        }
    }
    // the credential header is a required environment placeholder, never a value
    let o = out();
    let get = text(o.files.iter().find(|f| f.path == "004-get-orders-id.sh").unwrap());
    assert!(get.contains("-H 'Authorization: '\"${XT_HEADER_AUTHORIZATION}\""), "{get}");
    assert!(get.contains(": \"${XT_HEADER_AUTHORIZATION:?set XT_HEADER_AUTHORIZATION}\""));
}

#[test]
fn sh_n_syntax_check() {
    for f in out().files {
        let mut child = Command::new("/bin/sh")
            .args(["-n", "-s"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&f.bytes).unwrap();
        let r = child.wait_with_output().unwrap();
        assert!(r.status.success(), "{}: {}", f.path, String::from_utf8_lossy(&r.stderr));
    }
}

#[test]
fn curl_export_is_order_independent_and_repeatable() {
    let a = out();
    let mut input = spring_orders();
    input.operations.reverse();
    let b = export(&input, &ExportRequest::new(ExportFormat::Curl)).unwrap();
    assert_eq!(a, b);
}

#[test]
fn hostile_names_and_comments_stay_on_one_line() {
    use common::{claim, op, response};
    let mut c = claim("c");
    c.responses = vec![response("200", "ok")];
    let mut input = spring_orders();
    let mut o = op("op\nrm -rf /", "GET", "/x\n; echo pwned", vec![c]);
    o.binding_key = "k".into();
    input.operations = vec![o];
    let out = export(&input, &ExportRequest::new(ExportFormat::Curl)).unwrap();
    let script = text(&out.files[0]);
    // control characters in comment text are neutralised, so each stays on one line
    assert!(script.contains("\n# operation: op?rm -rf /\n"), "{script}");
    assert!(script.contains("\n# route: GET /x?; echo pwned\n"), "{script}");
}
