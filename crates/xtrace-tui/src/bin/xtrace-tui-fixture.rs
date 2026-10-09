//! Test fixture, not a product binary: runs the terminal driver over a small built-in client so
//! PTY tests can drive the real key decoding, redraw, resize and restore paths.
//! `xtrace-tui-fixture [--hostile]` runs interactively; `--plain` renders once.

use std::process::ExitCode;

use xtrace_tui::driver::{DEFAULT_SIZE, render_plain, run_interactive};
use xtrace_tui::{
    ClientError, FrameRow, NavAction, NavResult, RecordingRow, ReplayClient, Window,
};

struct Fixture {
    hostile: bool,
}

const REC: &str = "018f0000-0000-7000-8000-000000000011";

impl ReplayClient for Fixture {
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError> {
        Ok(vec![RecordingRow { id: REC.to_owned(), completion: "complete".to_owned(), event_count: 6 }])
    }

    fn window(&self, recording_id: &str, around: Option<&str>) -> Result<Window, ClientError> {
        if recording_id != REC {
            return Err(ClientError("recording not found".to_owned()));
        }
        let frames = (1..=6_u64)
            .map(|n| {
                let nav = |t: u64| {
                    if t == 0 || t > 6 {
                        NavResult::Boundary(None)
                    } else {
                        NavResult::Target(format!("f{t}"))
                    }
                };
                FrameRow {
                    frame_id: Some(format!("f{n}")),
                    sequence: n,
                    kind: "method".to_owned(),
                    symbol: Some(if self.hostile && n == 2 {
                        "evil\u{1b}]52;c;AAAA\u{7}\u{1b}[2Jname".to_owned()
                    } else {
                        format!("com.example.Svc{n}.call")
                    }),
                    depth: Some(0),
                    navigation: [
                        Some(nav(n - 1)),
                        Some(nav(n + 1)),
                        Some(nav(n + 1)),
                        Some(nav(n + 1)),
                        Some(NavResult::Boundary(None)),
                    ],
                }
            })
            .collect();
        Ok(Window {
            recording_id: recording_id.to_owned(),
            frames,
            completion: "complete".to_owned(),
            anchor_frame_id: around.map(str::to_owned),
        })
    }

    fn navigate(&self, _: &str, _: &str, _: NavAction) -> Result<NavResult, ClientError> {
        Err(ClientError("the fixture embeds every navigation answer".to_owned()))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let fixture = Fixture { hostile: args.iter().any(|a| a == "--hostile") };
    if args.iter().any(|a| a == "--plain") {
        return match render_plain(&fixture, DEFAULT_SIZE, Some(REC)) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::FAILURE,
        };
    }
    match run_interactive(&fixture) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
