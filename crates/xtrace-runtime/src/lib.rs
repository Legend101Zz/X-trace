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

/// Strict signed language-pack manifest parsing and cryptographic primitives.
pub mod signed_pack;

/// Descriptor-relative inspection of untrusted public pack directories.
#[cfg(unix)]
pub mod pack_inventory;

#[cfg(unix)]
pub mod node;
