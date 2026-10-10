//! Version string and not-implemented stub subcommand checks (C0).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "subprocess tests use fixed arguments and checked assertions"
)]

use std::process::Command;

fn xtrace(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtrace")).args(args).output().expect("run xtrace")
}

#[test]
fn version_is_0_0_1() {
    let output = xtrace(&["--version"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(text.lines().next(), Some("xtrace 0.0.1"));
}

#[test]
fn version_prints_schema_version_and_protocol() {
    let output = xtrace(&["--version"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(lines[1], format!("schema-version: {}", xtrace_store::CURRENT_SCHEMA_VERSION));
    assert_eq!(lines[2], "xtp-protocol: 1.0");
}

#[test]
fn unimplemented_command_exits_nine_with_stable_message_for_each() {
    let table: &[(&[&str], &str)] = &[
        (&["exercise", "approve", "--plan-hash", "abc"], "exercise approve"),
        (&["exercise", "run"], "exercise run"),
        (&["exercise", "show"], "exercise show"),
        (&["retention", "preview"], "retention preview"),
        (&["retention", "apply", "--preview-digest", "abc"], "retention apply"),
        (&["store", "backup"], "store backup"),
        (&["store", "verify"], "store verify"),
        (&["store", "restore"], "store restore"),
        (&["store", "migrate", "--dry-run"], "store migrate"),
    ];
    for (args, name) in table {
        let output = xtrace(args);
        assert_eq!(output.status.code(), Some(9), "args {args:?}");
        assert!(output.stdout.is_empty(), "args {args:?} wrote to stdout");
        let doc: serde_json::Value =
            serde_json::from_slice(&output.stderr).expect("error document is JSON");
        assert_eq!(doc["code"], "XTR-CLI-NOT-IMPLEMENTED", "args {args:?}");
        assert_eq!(doc["exit_code"], 9);
        assert_eq!(doc["message"], format!("xtrace {name} is not implemented in this build"));
        assert_eq!(doc["details"]["command"], *name);
    }
}

/// `record`, `stop` and `restart` are implemented: outside an initialized repository they fail with
/// the directory error (exit 3), never the not-implemented error (exit 9). The success paths are
/// covered by `lifecycle_journey.rs`.
#[test]
fn implemented_lifecycle_commands_refuse_an_uninitialized_directory_with_exit_three() {
    let dir = tempfile::tempdir().expect("temp dir");
    let project = dir.path().to_str().expect("utf-8 temp path");
    for name in ["record", "stop", "restart"] {
        let output = xtrace(&[name, "--project-dir", project]);
        assert_eq!(output.status.code(), Some(3), "{name}");
        assert!(output.stdout.is_empty(), "{name} wrote to stdout");
        let doc: serde_json::Value =
            serde_json::from_slice(&output.stderr).expect("error document is JSON");
        assert_eq!(doc["code"], "XTR-CLI-DIRECTORY", "{name}");
        assert_ne!(doc["code"], "XTR-CLI-NOT-IMPLEMENTED", "{name}");
    }
}

/// The `catalog` read commands are implemented: outside an initialized repository they fail with
/// the directory error (exit 3), never the not-implemented error (exit 9). The success paths are
/// covered by `scan_catalog_journey.rs`.
#[test]
fn implemented_catalog_commands_refuse_an_uninitialized_directory_with_exit_three() {
    let dir = tempfile::tempdir().expect("temp dir");
    let project = dir.path().to_str().expect("utf-8 temp path");
    for name in ["list", "history", "diff", "conflicts", "runs"] {
        let output = xtrace(&["catalog", name, "--project-dir", project]);
        assert_eq!(output.status.code(), Some(3), "catalog {name}");
        assert!(output.stdout.is_empty(), "catalog {name} wrote to stdout");
        let doc: serde_json::Value =
            serde_json::from_slice(&output.stderr).expect("error document is JSON");
        assert_eq!(doc["code"], "XTR-CLI-DIRECTORY", "catalog {name}");
    }
}

/// `doctor` is implemented: it prints a `doctor_report` document and exits 1 when a check fails.
#[test]
fn implemented_doctor_prints_a_report_instead_of_the_stub_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let project = dir.path().to_str().expect("utf-8 temp path");
    let output = xtrace(&["doctor", "--project-dir", project]);
    assert_ne!(output.status.code(), Some(9));
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor report is JSON on stdout");
    assert_eq!(doc["kind"], "doctor_report");
}

#[test]
fn partial_error_exit_code_is_ten_and_help_lists_new_entries() {
    let output = xtrace(&["--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    for entry in
        ["scan", "catalog", "record", "stop", "restart", "doctor", "export", "exercise", "tui"]
    {
        assert!(help.contains(entry), "help lacks {entry}");
    }
}
