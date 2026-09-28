//! Application layer: use cases, ports, and the command/query facade.
//!
//! The application crate sits between the IO-free domain and the
//! infrastructure that implements storage and adapters. It owns:
//!
//! - the command and query types that clients (CLI, TUI, web) speak;
//! - the port traits that infrastructure must implement;
//! - the [`Application`] facade that orchestrates a single command or
//!   query and returns typed [`AppError`]s;
//! - the bridge between internal port errors and the public error
//!   contract so domain rules stay in domain, transport stays in
//!   transport, and neither leaks across the boundary.
//!
//! Slice 1A keeps the surface intentionally small. The exact set of
//! commands documented in `03-program-design.md` §3.2 grows in
//! later slices once the ports they need are wired in.

#![allow(
    clippy::module_name_repetitions,
    reason = "application modules are named after their entities"
)]
// Unwrap and expect are forbidden in non-test code so domain errors
// remain typed. Tests deliberately exercise fallible operations on
// fixture data and remain free to use them, hence the test-side allow.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod application;
pub mod commands;
pub mod error;
pub mod ports;
pub mod queries;

pub use application::{Application, RequestContext};
pub use commands::{Command, CommandReceipt, InitializeProject, OpenProject};
pub use error::{PortError, PortErrorKind};
pub use ports::ProjectRepository;
pub use queries::{
    CapabilityReport, GetProject, GetStoreStatus, ProjectStatus, Query, QueryResult,
    StoreStatusReport,
};
