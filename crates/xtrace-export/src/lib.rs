//! Export formats and bundles (lane W).
//!
//! The crate turns a plain, already-read catalog view ([`ExportInput`]) into
//! deterministic artifacts: an OpenAPI 3.1 document, a set of POSIX `sh`
//! cURL recipes, and (later) a Postman collection and a bundle. It performs no
//! I/O of its own: it never opens a network connection, never reads the
//! store and never executes anything it generates.
//!
//! Guarantees enforced by tests in this crate:
//!
//! - the output depends only on the *set* of input operations, never on their
//!   order, and is byte-identical across runs;
//! - secret-shaped keys and values are never emitted; every dropped example is
//!   listed in the export's omissions;
//! - generated shell recipes round-trip hostile input through a real `sh`.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]

pub mod canonical;
pub mod curl;
pub mod input_json;
pub mod openapi;
pub mod projection;
pub mod request;
pub mod sanitize;
pub mod validate;

pub use request::{
    ClaimInput, EffectiveState, ExampleInput, ExampleOrigin, ExportError, ExportFile, ExportFormat,
    ExportInput, ExportOutput, ExportRequest, HandlerInput, Omission, OperationInput, ParamInput,
    ResponseInput, RevisionInput,
};

/// Runs an export. Pure: same input and request give byte-identical output.
///
/// # Errors
///
/// Returns [`ExportError`] when the format is not implemented yet, the
/// selection matches nothing in a way the format cannot represent, or the
/// sanitizer gate finds a secret-shaped value in the finished document.
pub fn export(input: &ExportInput, request: &ExportRequest) -> Result<ExportOutput, ExportError> {
    let prepared = projection::prepare(input, request);
    match request.format {
        ExportFormat::OpenApi => openapi::render(&prepared),
        ExportFormat::Curl => curl::render(&prepared),
        ExportFormat::Postman | ExportFormat::Bundle => {
            Err(ExportError::FormatNotImplemented { format: request.format.name() })
        }
    }
}

/// Sorts files, computes the content hash and assembles the output.
pub(crate) fn finish(mut files: Vec<ExportFile>, omissions: Vec<Omission>) -> ExportOutput {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut omissions = omissions;
    omissions.sort();
    omissions.dedup();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.export.v1\0");
    for file in &files {
        hasher.update(&(file.path.len() as u64).to_le_bytes());
        hasher.update(file.path.as_bytes());
        hasher.update(&file.mode.to_le_bytes());
        hasher.update(&(file.bytes.len() as u64).to_le_bytes());
        hasher.update(&file.bytes);
    }
    ExportOutput { files, omissions, content_hash: hasher.finalize().to_hex().to_string() }
}
