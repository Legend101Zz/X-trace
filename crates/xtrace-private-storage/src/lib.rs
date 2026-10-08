//! Owner-enforced private directory admission for local X-trace state.
//!
//! This is a leaf crate: it depends on no other X-trace crate so the store, the
//! runtime, the daemon and the CLI can all share one implementation of the
//! private-storage policy (ownership, mode, ACL, filesystem type, and path
//! identity) without depending on each other.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "storage policy must not panic")
)]

#[cfg(unix)]
mod admission;
#[cfg(unix)]
pub use admission::{AdmittedPrivateRoot, PrivateStorageError, validate_child_name};

#[cfg(not(unix))]
mod unsupported;
#[cfg(not(unix))]
pub use unsupported::{AdmittedPrivateRoot, PrivateStorageError, validate_child_name};

// Temporary: removed once the Java attach ancestor walk uses the shared admission.
#[cfg(target_os = "linux")]
pub use admission::linux_directory_admits_traversal;
