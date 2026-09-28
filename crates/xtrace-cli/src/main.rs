//! X-trace command line interface.
//!
//! The CLI is the simplest client of the application facade. Each
//! subcommand translates CLI arguments into a [`Command`] or
//! [`Query`], invokes the application, and renders the result as
//! machine-readable JSON so downstream automation does not depend on
//! human-readable output formatting.
//!
//! Slice 1A ships exactly three commands:
//!
//! - `xtrace init` — register a new repository and create the local
//!   store;
//! - `xtrace open` — open an existing repository and update its
//!   `last_opened_at`;
//! - `xtrace status` — emit a truthful machine-readable status report
//!   for the local store.
//!
//! The CLI never claims capture or replay support. [`status`] sets
//! `capture_supported` and `replay_supported` to `false` until a
//! future slice wires the corresponding capabilities.

#![allow(clippy::module_name_repetitions, reason = "CLI modules are named after their subcommands")]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]

mod commands;
mod error;
mod output;
mod store_paths;

use clap::Parser;
use commands::XtraceCommand;

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

fn main() {
    let cli = Cli::parse();
    let exit_code = match commands::run(cli.command) {
        Ok(()) => 0,
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
