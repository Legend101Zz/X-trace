//! CLI output formatting.
//!
//! Every CLI command writes a single machine-readable JSON document
//! to stdout on success and a single JSON document to stderr on
//! failure. The CLI never relies on terminal coloring or human-readable
//! prose so scripts can parse the result with `jq` or
//! `python -c "json.load(sys.stdin)"`.

use std::io::{self, Write};

use serde::Serialize;
use xtrace_domain::AppError;
use xtrace_domain::SafeScalar;

use crate::error::CliError;

/// Render the supplied serializable value to stdout as pretty JSON.
///
/// # Errors
///
/// Returns [`io::Error`] when the underlying writer fails.
pub fn write_success<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    writer.write_all(body.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Writes one compact JSON document followed by a newline.
///
/// Long-running commands use this form so readiness can be consumed as one
/// complete line while the process remains active.
pub fn write_success_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Render the supplied CLI error as a single JSON document on stderr.
///
/// # Errors
///
/// Returns [`io::Error`] when the underlying writer fails. The error
/// is intentionally silent: a CLI that cannot print an error simply
/// exits with a non-zero status.
pub fn write_error<W: Write>(writer: &mut W, error: &CliError) -> io::Result<()> {
    let body = ErrorDocument::from_error(error);
    let text = serde_json::to_string_pretty(&body)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    writer.write_all(text.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Stable JSON shape of a CLI error document.
#[derive(Debug, Serialize)]
pub struct ErrorDocument {
    /// Always `"error"` so clients can branch on a single field.
    pub kind: &'static str,
    /// Stable error code from the application error.
    pub code: String,
    /// Coarse category from the application error.
    pub category: String,
    /// User-safe message.
    pub message: String,
    /// Optional remediation hints.
    pub remediation: Vec<RemediationDocument>,
    /// Sanitized scalar details.
    pub details: BTreeMapString,
    /// CLI exit code associated with the error.
    pub exit_code: i32,
}

/// Stable JSON shape of a remediation hint.
#[derive(Debug, Serialize)]
pub struct RemediationDocument {
    pub kind: String,
    pub label: String,
    pub command_ref: Option<String>,
}

/// Newtype wrapper to keep `serde_json::Value` out of the public API
/// while still rendering nested JSON scalars deterministically.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct BTreeMapString(pub std::collections::BTreeMap<String, serde_json::Value>);

impl ErrorDocument {
    fn from_error(error: &CliError) -> Self {
        match error {
            CliError::App(err) => from_app_error(err),
            CliError::InvalidArgument(message) => Self {
                kind: "error",
                code: "XTR-CLI-ARGUMENT".to_string(),
                category: "validation".to_string(),
                message: message.clone(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::ProjectDirectoryMissing(path) => Self {
                kind: "error",
                code: "XTR-CLI-DIRECTORY".to_string(),
                category: "not_found".to_string(),
                message: format!("project directory not found: {path}"),
                remediation: Vec::new(),
                details: BTreeMapString(
                    std::iter::once(("path".to_string(), serde_json::Value::String(path.clone())))
                        .collect(),
                ),
                exit_code: error.exit_code(),
            },
            CliError::StoreSchemaNewer(message) => Self {
                kind: "error",
                code: "XTR-CLI-STORE-NEWER".to_string(),
                category: "compatibility".to_string(),
                message: message.clone(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::StoreSchemaOlder(message) => Self {
                kind: "error",
                code: "XTR-CLI-STORE-OLDER".to_string(),
                category: "compatibility".to_string(),
                message: message.clone(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::StoreCorrupted(message) => Self {
                kind: "error",
                code: "XTR-CLI-STORE-CORRUPTED".to_string(),
                category: "corruption".to_string(),
                message: message.clone(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::StoreUnavailable(message) => Self {
                kind: "error",
                code: "XTR-CLI-STORE-UNAVAILABLE".to_string(),
                category: "transport".to_string(),
                message: message.clone(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::DaemonAlreadyRunning => Self {
                kind: "error",
                code: "XTR-CLI-DAEMON-LOCKED".to_string(),
                category: "resource".to_string(),
                message: "a daemon is already running for this project".to_string(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::DaemonUnsupportedPlatform => Self {
                kind: "error",
                code: "XTR-CLI-DAEMON-UNSUPPORTED".to_string(),
                category: "compatibility".to_string(),
                message: "durable recording daemon is unsupported on this platform".to_string(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
            CliError::DaemonFailure(code) => Self {
                kind: "error",
                code: code.as_str().to_string(),
                category: "daemon".to_string(),
                message: "daemon operation failed".to_string(),
                remediation: Vec::new(),
                details: BTreeMapString(
                    std::iter::once((
                        "daemon_code".to_string(),
                        serde_json::Value::String(code.as_str().to_string()),
                    ))
                    .collect(),
                ),
                exit_code: error.exit_code(),
            },
            #[cfg(unix)]
            CliError::Run(run_error) => Self {
                kind: "error",
                code: run_error.code().to_string(),
                category: match run_error.kind() {
                    xtrace_runtime::java::LaunchErrorKind::Validation => "validation",
                    xtrace_runtime::java::LaunchErrorKind::Unsupported => "compatibility",
                    xtrace_runtime::java::LaunchErrorKind::Process => "process",
                }
                .to_string(),
                message: run_error.to_string(),
                remediation: Vec::new(),
                details: BTreeMapString(std::collections::BTreeMap::new()),
                exit_code: error.exit_code(),
            },
        }
    }
}

fn from_app_error(err: &AppError) -> ErrorDocument {
    let remediation = err
        .remediation
        .iter()
        .map(|hint| RemediationDocument {
            kind: hint.kind.clone(),
            label: hint.label.clone(),
            command_ref: hint.command_ref.clone(),
        })
        .collect();
    let mut details: std::collections::BTreeMap<String, serde_json::Value> =
        err.details.iter().map(|(key, value)| (key.clone(), scalar_to_json(value))).collect();
    details.insert(
        "correlation_id".to_string(),
        serde_json::Value::String(err.correlation_id.to_string()),
    );
    ErrorDocument {
        kind: "error",
        code: err.code.as_str().to_string(),
        category: err.category.as_str().to_string(),
        message: err.message.clone(),
        remediation,
        details: BTreeMapString(details),
        exit_code: exit_code_for_app_error(err),
    }
}

fn exit_code_for_app_error(err: &AppError) -> i32 {
    crate::error::exit_code_for_category(err.category).max(1)
}

fn scalar_to_json(scalar: &SafeScalar) -> serde_json::Value {
    match scalar {
        SafeScalar::Bool(value) => serde_json::Value::Bool(*value),
        SafeScalar::Integer(value) => serde_json::Value::Number((*value).into()),
        SafeScalar::Float(value) => serde_json::Number::from_f64(*value)
            .map_or_else(|| serde_json::Value::Null, serde_json::Value::Number),
        SafeScalar::String(value) => serde_json::Value::String(value.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "the test serializes a fixed safe error document")]
mod tests {
    use super::*;

    #[test]
    fn daemon_errors_keep_the_stable_code_without_rendering_source_detail() {
        let error = CliError::DaemonFailure(xtrace_daemon::ProtocolErrorCode::Bind);
        let document = ErrorDocument::from_error(&error);
        assert_eq!(document.code, "XTR-DAEMON-BIND");
        assert_eq!(document.details.0["daemon_code"], "XTR-DAEMON-BIND");
        assert_eq!(document.message, "daemon operation failed");
    }

    #[test]
    fn unsupported_daemon_platform_has_a_stable_cli_code() {
        let error = CliError::DaemonUnsupportedPlatform;
        let document = ErrorDocument::from_error(&error);
        assert_eq!(document.code, "XTR-CLI-DAEMON-UNSUPPORTED");
        assert_eq!(document.category, "compatibility");
    }

    #[test]
    fn application_errors_preserve_the_request_correlation_id_in_json_details() {
        let correlation_id =
            "018f0000-0000-7000-8000-000000000001".parse().expect("fixed correlation ID");
        let error = CliError::App(AppError::new(
            xtrace_domain::ErrorCode::new("XTR-VALIDATION-ENDPOINT-CURSOR"),
            xtrace_domain::ErrorCategory::Validation,
            "observed endpoint cursor is malformed or belongs to a different query",
            xtrace_domain::RetryAdvice::None,
            correlation_id,
        ));
        let document = ErrorDocument::from_error(&error);
        assert_eq!(document.details.0["correlation_id"], correlation_id.to_string());
        let rendered = serde_json::to_string(&document).expect("serialized CLI error");
        assert!(rendered.contains("\"correlation_id\":\"018f0000-0000-7000-8000-000000000001\""));
    }

    #[test]
    #[cfg(unix)]
    fn runtime_process_failures_are_not_misclassified_as_store_failures() {
        let error = CliError::Run(xtrace_runtime::java::LaunchError::Process);
        let document = ErrorDocument::from_error(&error);
        assert_eq!(document.code, "XTR-RUN-PROCESS");
        assert_eq!(document.category, "process");
        assert_eq!(document.exit_code, 9);
        assert_eq!(error.exit_code(), 9);
    }

    #[test]
    #[cfg(unix)]
    fn runtime_validation_has_a_stable_launch_category() {
        let error = CliError::Run(xtrace_runtime::java::LaunchError::Validation("invalid"));
        let document = ErrorDocument::from_error(&error);
        assert_eq!(document.code, "XTR-RUN-INVALID-LAUNCH");
        assert_eq!(document.category, "validation");
        assert_eq!(document.exit_code, 2);
    }
}
