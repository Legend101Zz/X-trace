//! Application-owned policies for starting and supervising instrumented runtimes.
//!
//! Runtime launch behavior belongs here rather than in the CLI so multiple
//! application entry points can share validation, injection, and process
//! lifecycle rules without introducing a generic launcher framework.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "runtime policy must not panic")
)]

#[cfg(unix)]
pub mod java;

#[cfg(unix)]
pub mod java_attach;

#[cfg(unix)]
pub mod private_storage;

#[cfg(not(unix))]
#[path = "private_storage_unsupported.rs"]
pub mod private_storage;
