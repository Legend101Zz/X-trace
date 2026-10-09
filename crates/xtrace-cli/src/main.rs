//! X-trace command line interface.
//!
//! The CLI is the simplest client of the application facade. Each
//! subcommand translates CLI arguments into a
//! [`xtrace_application::Command`] or [`xtrace_application::Query`],
//! invokes the application, and renders the result as
//! machine-readable JSON so downstream automation does not depend on
//! human-readable output formatting.
//!
//! Slice 1A initially shipped three commands:
//!
//! - `xtrace init` — register a new repository and create the local
//!   store;
//! - `xtrace open` — open an existing repository and update its
//!   `last_opened_at`;
//! - `xtrace status` — emit a truthful machine-readable status report
//!   for the local store.
//!
//! The foreground `xtrace daemon` command is supported on Unix and reports
//! durable segment ingress separately from language capture support.
//!
//! The CLI never claims capture or replay support. The `status`
//! subcommand sets `capture_supported` and `replay_supported` to
//! `false` until a future slice wires the corresponding capabilities.
//!
//! ## Storage layout
//!
//! Project state lives under the user-data home directory
//! (`XTRACE_DATA_HOME` or the platform default). Each project owns
//! one `<user_data_home>/projects/<project-id>/metadata.sqlite3`
//! file. The repository holds only a `.xtrace/config.toml` pointer
//! that records the project identifier and the user-data home used
//! at `init` time. Status on an uninitialized repository reports the
//! empty state without opening or creating any database.

#![allow(clippy::module_name_repetitions, reason = "CLI modules are named after their subcommands")]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]

#[cfg(unix)]
mod attach;
mod catalog_cmd;
mod commands;
mod daemon;
#[cfg(unix)]
mod daemon_lock;
mod doctor;
mod error;
mod exercise;
mod export;
mod lifecycle;
mod output;
mod paths;
#[cfg(unix)]
mod pointer_io;
#[cfg(not(unix))]
mod pointer_io {
    use crate::error::CliError;
    use std::fs::File;
    use std::path::Path;
    pub(crate) const POINTER_MAX_BYTES: usize = 8192;
    pub(crate) const PENDING_MAX_BYTES: usize = 8192;
    pub(crate) const MAX_PATH_BYTES: usize = 4096;
    pub(crate) struct RepositoryInitLock;
    impl RepositoryInitLock {
        pub(crate) fn acquire(_: &Path) -> Result<Self, CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
        pub(crate) fn read(&self, _: &str, _: usize) -> Result<Option<Vec<u8>>, CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
        pub(crate) fn publish(&self, _: &str, _: &[u8], _: usize) -> Result<(), CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
        pub(crate) fn remove_owned(&self, _: &str, _: &File) -> Result<(), CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
        pub(crate) fn open_owned(&self, _: &str) -> Result<File, CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
        pub(crate) fn revalidate(&self) -> Result<(), CliError> {
            Err(CliError::StoreUnavailable(
                "safe repository metadata I/O is unsupported on this platform".into(),
            ))
        }
    }
    pub(crate) fn read_unlocked(_: &Path, _: &str, _: usize) -> Result<Option<Vec<u8>>, CliError> {
        Err(CliError::StoreUnavailable(
            "safe repository metadata I/O is unsupported on this platform".into(),
        ))
    }
}
mod run;
mod scan;
mod tui;
mod viewer;

use clap::{Parser, error::ErrorKind};
use commands::XtraceCommand;
use xtrace_domain::{AppError, CorrelationId, ErrorCategory, ErrorCode, RetryAdvice};

pub use error::CliError;

/// Top-level CLI surface parsed by [`clap`].
#[derive(Clone, Debug, Parser)]
#[command(
    name = "xtrace",
    version,
    about = "X-trace: capture, replay, and review for HTTP services.",
    long_about = None,
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: XtraceCommand,
}

#[tokio::main]
async fn main() {
    let exit_code = match parse_cli() {
        Ok(cli) => commands::run(cli.command).await,
        Err(err) => Err(err),
    };
    let exit_code = match exit_code {
        Ok(exit_code) => exit_code,
        Err(err) => {
            // Errors go to stderr as one JSON document so scripts can
            // capture the failure with `2>file.json` without parsing
            // human-readable prose.
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            let _ = output::write_error(&mut handle, &err);
            err.exit_code()
        }
    };
    std::process::exit(exit_code);
}

fn parse_cli() -> Result<Cli, CliError> {
    match Cli::try_parse() {
        Ok(cli) => Ok(cli),
        Err(error) => Err(sanitized_parse_error(error)),
    }
}

fn sanitized_parse_error(error: clap::Error) -> CliError {
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            | ErrorKind::DisplayVersion
    ) {
        error.exit();
    }
    AppError::new(
        ErrorCode::new("XTR-CLI-ARGUMENT"),
        ErrorCategory::Validation,
        "command-line arguments are invalid",
        RetryAdvice::None,
        CorrelationId::new(),
    )
    .into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "CLI parser tests use fixed arguments")]
mod tests {
    use super::*;

    #[test]
    fn daemon_command_accepts_project_path_with_spaces() {
        let cli = Cli::try_parse_from(["xtrace", "daemon", "--project-dir", "/tmp/my repository"])
            .expect("daemon command parses");
        assert!(matches!(cli.command, commands::XtraceCommand::Daemon { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn attach_command_accepts_explicit_pid_pack_and_json_mode() {
        let cli = Cli::try_parse_from([
            "xtrace",
            "attach",
            "--project-dir",
            "/tmp/project with spaces",
            "--pid",
            "4312",
            "--java-pack",
            "/tmp/java pack",
            "--json",
        ])
        .expect("attach command parses");
        assert!(matches!(
            cli.command,
            commands::XtraceCommand::Attach { pid: Some(4312), json: true, .. }
        ));
    }

    #[test]
    fn run_command_preserves_exact_java_arguments_and_requires_a_launcher() {
        let cli = Cli::try_parse_from([
            "xtrace",
            "run",
            "--project-dir",
            "/tmp/project with spaces",
            "--java-agent",
            "/tmp/agent with spaces/xtrace-java-agent.jar",
            "--",
            "java",
            "-jar",
            "app with spaces.jar",
            "--spring.config.location=file:/tmp/config with spaces/",
        ])
        .expect("run command parses");
        assert!(matches!(
            cli.command,
            commands::XtraceCommand::Run { command, .. }
                if command == ["java", "-jar", "app with spaces.jar", "--spring.config.location=file:/tmp/config with spaces/"]
        ));
        assert!(
            Cli::try_parse_from([
                "xtrace",
                "run",
                "--project-dir",
                "/tmp/project",
                "--java-agent",
                "/tmp/agent.jar",
                "--",
            ])
            .is_err()
        );
    }

    #[test]
    fn run_command_requires_explicit_node_mode_and_preserves_node_arguments() {
        let cli = Cli::try_parse_from([
            "xtrace",
            "run",
            "--project-dir",
            "/tmp/project",
            "--node-adapter",
            "/tmp/adapter dist",
            "--node-mode",
            "esm",
            "--",
            "node",
            "--no-warnings",
            "app with spaces.mjs",
            "--flag",
            "value with spaces",
        ])
        .expect("Node run parses");
        assert!(matches!(cli.command, commands::XtraceCommand::Run {
            node_adapter: Some(adapter), node_mode: Some(mode), command, java_agent: None, ..
        } if adapter.as_path() == std::path::Path::new("/tmp/adapter dist") && mode == "esm"
            && command == ["node", "--no-warnings", "app with spaces.mjs", "--flag", "value with spaces"]));
        assert!(
            Cli::try_parse_from([
                "xtrace",
                "run",
                "--project-dir",
                "/tmp/project",
                "--node-adapter",
                "/tmp/dist",
                "--",
                "node",
                "app.cjs"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "xtrace",
                "run",
                "--project-dir",
                "/tmp/project",
                "--java-agent",
                "/tmp/a.jar",
                "--node-adapter",
                "/tmp/dist",
                "--node-mode",
                "cjs",
                "--",
                "node",
                "app.cjs"
            ])
            .is_err()
        );
    }

    #[test]
    fn run_command_accepts_the_finite_observation_opt_in_and_paired_context() {
        let cli = Cli::try_parse_from([
            "xtrace",
            "run",
            "--project-dir",
            "/tmp/project",
            "--java-agent",
            "/tmp/agent.jar",
            "--observed-endpoint-policy",
            "spring-orders-v1",
            "--application-component",
            "spring-fixture",
            "--binding-key",
            "default",
            "--",
            "java",
            "-jar",
            "app.jar",
        ])
        .expect("opt-in parses");
        assert!(matches!(cli.command, commands::XtraceCommand::Run {
            observed_endpoint_policy: Some(policy), application_component: Some(component), binding_key: Some(binding), ..
        } if policy == "spring-orders-v1" && component == "spring-fixture" && binding == "default"));
        assert!(
            Cli::try_parse_from([
                "xtrace",
                "run",
                "--project-dir",
                "/tmp/project",
                "--java-agent",
                "/tmp/agent.jar",
                "--application-component",
                "spring-fixture",
                "--",
                "java",
            ])
            .is_err()
        );
    }

    #[test]
    fn recording_commands_accept_project_selection_and_versioned_show_cursor() {
        let list = Cli::try_parse_from([
            "xtrace",
            "recording",
            "list",
            "--project-dir",
            "/tmp/project",
            "--limit",
            "200",
        ])
        .expect("recording list parses");
        assert!(matches!(
            list.command,
            commands::XtraceCommand::Recording {
                command: commands::RecordingCommand::List { limit: Some(ref limit), .. }
            } if limit == "200"
        ));

        let show = Cli::try_parse_from([
            "xtrace",
            "recording",
            "show",
            "--project-dir",
            "/tmp/project",
            "018f0000-0000-7000-8000-000000000001",
            "--cursor",
            "v1.eHh4",
        ])
        .expect("recording show parses cursor token");
        assert!(matches!(
            show.command,
            commands::XtraceCommand::Recording {
                command: commands::RecordingCommand::Show {
                    cursor: Some(cursor), ..
                }
            } if cursor == "v1.eHh4"
        ));
    }

    #[test]
    fn observed_endpoint_and_unmatched_commands_parse_shared_page_options() {
        let endpoints = Cli::try_parse_from([
            "xtrace",
            "endpoint",
            "list",
            "--project-dir",
            "/tmp/project",
            "--limit",
            "3",
            "--cursor",
            "opaque-token",
        ])
        .expect("endpoint list parses");
        assert!(matches!(
            endpoints.command,
            commands::XtraceCommand::Endpoint {
                command: commands::EndpointCommand::List {
                    limit: Some(limit), cursor: Some(cursor), ..
                }
            } if limit == "3" && cursor == "opaque-token"
        ));

        let linked = Cli::try_parse_from([
            "xtrace",
            "endpoint",
            "recordings",
            "018f0000-0000-7000-8000-000000000001",
            "--project-dir",
            "/tmp/project",
        ])
        .expect("endpoint recordings parses");
        assert!(matches!(
            linked.command,
            commands::XtraceCommand::Endpoint {
                command: commands::EndpointCommand::Recordings { operation_id, .. }
            } if operation_id == "018f0000-0000-7000-8000-000000000001"
        ));

        let unmatched = Cli::try_parse_from([
            "xtrace",
            "recording",
            "list",
            "--project-dir",
            "/tmp/project",
            "--unmatched",
            "--limit",
            "3",
            "--cursor",
            "opaque-token",
        ])
        .expect("unmatched recording list parses");
        assert!(matches!(
            unmatched.command,
            commands::XtraceCommand::Recording {
                command: commands::RecordingCommand::List {
                    unmatched: true, limit: Some(limit), cursor: Some(cursor), ..
                }
            } if limit == "3" && cursor == "opaque-token"
        ));
    }

    #[test]
    fn hyphen_prefixed_query_values_are_preserved_for_safe_validation() {
        let endpoint_list = Cli::try_parse_from([
            "xtrace",
            "endpoint",
            "list",
            "--project-dir",
            "/tmp/project",
            "--limit",
            "-LIMIT_CANARY",
            "--cursor",
            "--CURSOR_CANARY",
        ])
        .expect("hyphen-prefixed endpoint query values parse");
        assert!(matches!(
            endpoint_list.command,
            commands::XtraceCommand::Endpoint {
                command: commands::EndpointCommand::List {
                    limit: Some(limit), cursor: Some(cursor), ..
                }
            } if limit == "-LIMIT_CANARY" && cursor == "--CURSOR_CANARY"
        ));

        let linked = Cli::try_parse_from([
            "xtrace",
            "endpoint",
            "recordings",
            "--OPERATION_CANARY",
            "--project-dir",
            "/tmp/project",
            "--limit",
            "--LIMIT_CANARY",
            "--cursor",
            "-CURSOR_CANARY",
        ])
        .expect("hyphen-prefixed operation query values parse");
        assert!(matches!(
            linked.command,
            commands::XtraceCommand::Endpoint {
                command: commands::EndpointCommand::Recordings {
                    operation_id, limit: Some(limit), cursor: Some(cursor), ..
                }
            } if operation_id == "--OPERATION_CANARY"
                && limit == "--LIMIT_CANARY"
                && cursor == "-CURSOR_CANARY"
        ));

        let legacy = Cli::try_parse_from([
            "xtrace",
            "recording",
            "list",
            "--project-dir",
            "/tmp/project",
            "--after",
            "--RECORDING_CURSOR_CANARY",
        ])
        .expect("hyphen-prefixed legacy cursor parses");
        assert!(matches!(
            legacy.command,
            commands::XtraceCommand::Recording {
                command: commands::RecordingCommand::List { after: Some(after), .. }
            } if after == "--RECORDING_CURSOR_CANARY"
        ));

        let show = Cli::try_parse_from([
            "xtrace",
            "recording",
            "show",
            "--project-dir",
            "/tmp/project",
            "018f0000-0000-7000-8000-000000000001",
            "--cursor",
            "-SHOW_CURSOR_CANARY",
        ])
        .expect("hyphen-prefixed show cursor parses");
        assert!(matches!(
            show.command,
            commands::XtraceCommand::Recording {
                command: commands::RecordingCommand::Show { cursor: Some(cursor), .. }
            } if cursor == "-SHOW_CURSOR_CANARY"
        ));
    }

    #[test]
    fn ambiguous_cursor_option_orders_render_static_errors_without_echoing_values() {
        for options in [
            ["--unmatched", "--after", "--cursor", "AFTER_ORDER_PRIVACY_CANARY"],
            ["--unmatched", "--cursor", "--after", "CURSOR_ORDER_PRIVACY_CANARY"],
        ] {
            let mut args = vec!["xtrace", "recording", "list", "--project-dir", "/missing"];
            args.extend(options);
            let parse_error = Cli::try_parse_from(args).expect_err("ambiguous cursor mode");
            let error = sanitized_parse_error(parse_error);
            let mut rendered = Vec::new();
            output::write_error(&mut rendered, &error).expect("render sanitized parse error");
            let document: serde_json::Value =
                serde_json::from_slice(&rendered).expect("structured parse error");
            assert_eq!(document["code"], "XTR-CLI-ARGUMENT");
            assert_eq!(document["exit_code"], 2);
            assert!(document["details"]["correlation_id"].as_str().is_some());
            let rendered = String::from_utf8(rendered).expect("JSON is UTF-8");
            assert!(!rendered.contains("AFTER_ORDER_PRIVACY_CANARY"));
            assert!(!rendered.contains("CURSOR_ORDER_PRIVACY_CANARY"));
        }
    }
}
