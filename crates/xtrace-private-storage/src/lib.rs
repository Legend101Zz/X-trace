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
mod policy;
#[cfg(unix)]
mod probe;
#[cfg(unix)]
pub use admission::{
    AdmittedPrivateRoot, PrivateStorageError, admit_sealed_directories,
    admit_sealed_directories_with_profile, open_private_directory_descriptor,
    open_private_directory_descriptor_with_profile, validate_child_name,
};
#[cfg(unix)]
pub use policy::FilesystemProfile;

#[cfg(not(unix))]
mod unsupported;
#[cfg(not(unix))]
pub use unsupported::{AdmittedPrivateRoot, PrivateStorageError, validate_child_name};
