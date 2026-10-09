//! PTY tests: the real binary-side driver (raw mode, key decoding, redraw, resize, restore) on a
//! pseudo-terminal created by `tests/pty_harness.py` (python3 standard library only).

#![allow(clippy::expect_used, clippy::panic, reason = "test helpers fail loudly on setup errors")]

use std::path::PathBuf;
use std::process::Command;

struct Run {
    output: String,
    exit: i64,
    failures: Vec<String>,
}

fn run(size: &str, script: &serde_json::Value, extra: &[&str]) -> Run {
    let harness = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pty_harness.py");
    let mut command = Command::new("python3");
    command
        .arg("-I")
        .arg(harness)
        .arg(size)
        .arg(script.to_string())
        .arg(env!("CARGO_BIN_EXE_xtrace-tui-fixture"))
        .args(extra);
    let output = command.output().expect("python3 is required for the PTY tests");
    assert!(output.status.success(), "harness failed: {}", String::from_utf8_lossy(&output.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).expect("harness JSON");
    Run {
        output: doc["output"].as_str().expect("output").to_owned(),
        exit: doc["exit"].as_i64().expect("exit"),
        failures: doc["failures"]
            .as_array()
            .expect("failures")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect(),
    }
}

#[test]
fn pty_keys_open_navigate_back_and_quit_restores_the_terminal() {
    let script = serde_json::json!([
        ["wait", "018f0000-0000-7000-8000-000000000011", 5],
        ["send", "\r"],
        ["wait", "com.example.Svc1.call", 5],
        ["send", "]"],
        ["wait", "next: moved to frame f2", 5],
        ["send", "\u{1b}[B"],
        ["send", "["],
        ["wait", "previous: moved to frame f2", 5],
        ["send", "u"],
        ["wait", "out: boundary", 5],
        ["send", "?"],
        ["wait", "step into / over / out", 5],
        ["send", "?"],
        ["send", "b"],
        ["wait", "up/down select", 5],
        ["send", "q"],
    ]);
    let result = run("100x30", &script, &[]);
    assert!(result.failures.is_empty(), "{:?}\n{}", result.failures, result.output);
    assert_eq!(result.exit, 0);
    assert!(result.output.contains("\u{1b}[?1049h"), "alternate screen entered");
    assert!(result.output.ends_with("\u{1b}[?25h\u{1b}[?1049l"), "terminal restored last");
}

#[test]
fn pty_resize_redraws_at_the_new_size() {
    let script = serde_json::json!([
        ["wait", "018f0000-0000-7000-8000-000000000011", 5],
        ["resize", 60, 12],
        ["sleep", 0.6],
        ["send", "\r"],
        ["wait", "Svc1", 5],
        ["send", "q"],
    ]);
    let result = run("100x30", &script, &[]);
    assert!(result.failures.is_empty(), "{:?}\n{}", result.failures, result.output);
    assert_eq!(result.exit, 0);
    // After the resize the footer is truncated to 60 columns, so the 100-column footer text for
    // the replay screen must not appear after the open.
    let after = result.output.rsplit("Svc1").next().unwrap_or_default();
    assert!(!after.contains("b back · ? help · q quit"), "stale wide footer: {after:?}");
}

#[test]
fn pty_quits_on_end_of_input_and_ctrl_c_without_a_signal() {
    for key in ["\u{3}", "\u{4}"] {
        let script =
            serde_json::json!(
                [["wait", "018f0000-0000-7000-8000-000000000011", 5], ["send", key],]
            );
        let result = run("80x24", &script, &[]);
        assert_eq!(result.exit, 0, "key {key:?}: {result_output}", result_output = result.output);
        assert!(result.output.ends_with("\u{1b}[?25h\u{1b}[?1049l"));
    }
}

#[test]
fn pty_hostile_recorded_text_never_reaches_the_terminal_as_a_sequence() {
    let script = serde_json::json!([
        ["wait", "018f0000-0000-7000-8000-000000000011", 5],
        ["send", "\r"],
        ["wait", "Svc1", 5],
        ["send", "q"],
    ]);
    let result = run("100x30", &script, &["--hostile"]);
    assert!(result.failures.is_empty(), "{:?}", result.failures);
    assert!(result.output.contains('\u{fffd}'), "control characters were not replaced");
    assert!(!result.output.contains('\u{7}'), "BEL reached the terminal");
    // Every escape in the output must be one of the renderer's own: CSI ... letter.
    let bytes = result.output.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b {
            assert_eq!(bytes.get(index + 1), Some(&b'['), "non-CSI escape at {index}");
            let rest = &bytes[index + 2..];
            let end =
                rest.iter().position(|b| (0x40..=0x7e).contains(b)).expect("unterminated CSI");
            let params = &rest[..end];
            assert!(
                params.iter().all(|b| b.is_ascii_digit() || *b == b';' || *b == b'?'),
                "unexpected CSI parameters {params:?}"
            );
            index += 2 + end;
        }
        index += 1;
    }
}

#[test]
fn plain_mode_prints_text_without_a_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace-tui-fixture"))
        .arg("--plain")
        .output()
        .expect("run fixture");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("com.example.Svc1.call"), "{text}");
    assert!(!text.contains('\u{1b}'), "plain output contains an escape");
}

#[test]
fn interactive_mode_without_a_terminal_refuses_and_says_how_to_continue() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace-tui-fixture"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run fixture");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("use --plain"));
}
