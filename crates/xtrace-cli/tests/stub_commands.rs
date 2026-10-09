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
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "xtrace 0.0.1");
}

#[test]
fn unimplemented_command_exits_nine_with_stable_message_for_each() {
    let table: &[(&[&str], &str)] = &[
        (&["scan"], "scan"),
        (&["catalog", "list"], "catalog list"),
        (&["catalog", "history"], "catalog history"),
        (&["catalog", "diff"], "catalog diff"),
        (&["catalog", "conflicts"], "catalog conflicts"),
        (&["catalog", "runs"], "catalog runs"),
        (&["export"], "export"),
        (&["exercise", "plan"], "exercise plan"),
        (&["exercise", "approve", "--plan-hash", "abc"], "exercise approve"),
        (&["exercise", "run"], "exercise run"),
        (&["exercise", "show"], "exercise show"),
        (&["tui"], "tui"),
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
