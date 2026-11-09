//! `xtrace export`: deterministic OpenAPI, Postman and cURL artifacts from the persisted catalog.
//!
//! The command reads one catalog revision through the same read service `xtrace catalog` uses,
//! hands a plain view of it to `xtrace-export` (a pure crate) and writes the finished files under
//! an explicit output directory. It never opens a network connection and never executes anything
//! it generates. `--preview` renders everything and writes nothing.
//!
//! The persisted catalog holds static and runtime claims (provenance, handler, source line,
//! confidence, limitation codes). It holds no parameter, response or body claims, so the exports
//! declare path parameters from the route template and say so; no body or value was observed.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use xtrace_application::CatalogChangeKind;
use xtrace_application::catalog_discovery::history::{
    CatalogHistoryPort, CatalogHistoryService, HistoryError, OperationView, RevisionEntry,
};
use xtrace_domain::{
    AppError, CatalogRevisionId, CorrelationId, ErrorCategory, ErrorCode, ProjectId, RetryAdvice,
};
use xtrace_export::{
    CatalogSummaryInput, EffectiveState, ExportError, ExportFormat, ExportInput, ExportOutput,
    ExportRequest, HandlerInput, OperationInput, RevisionInput,
};

use crate::error::CliError;
use crate::export::ExportArgs;
use crate::output::write_success;

fn invalid(message: impl Into<String>) -> CliError {
    CliError::InvalidArgument(message.into())
}

fn not_found(message: impl Into<String>) -> CliError {
    CliError::App(AppError::new(
        ErrorCode::new("XTR-EXPORT-NOT-FOUND"),
        ErrorCategory::NotFound,
        message.into(),
        RetryAdvice::None,
        CorrelationId::new(),
    ))
}

fn map_history(error: HistoryError) -> CliError {
    match error {
        HistoryError::RevisionNotFound | HistoryError::NoRevisions => not_found(error.to_string()),
        HistoryError::ScopeMismatch => invalid(error.to_string()),
        HistoryError::Port(_) => CliError::StoreUnavailable(error.to_string()),
    }
}

fn map_export(error: &ExportError, format: ExportFormat) -> CliError {
    match error {
        // The offending path is not repeated: object keys can be the secret-shaped text.
        ExportError::SecretShaped { .. } => CliError::App(AppError::new(
            ErrorCode::new("XTR-EXPORT-SECRET-SHAPED"),
            ErrorCategory::Policy,
            format!(
                "refusing to emit a secret-shaped value in the {} export; nothing was written",
                format.name()
            ),
            RetryAdvice::None,
            CorrelationId::new(),
        )),
        ExportError::InvalidDocument { problems } => CliError::App(AppError::new(
            ErrorCode::new("XTR-EXPORT-INVALID-DOCUMENT"),
            ErrorCategory::Internal,
            format!(
                "the generated {} document failed its own validation ({} problems)",
                format.name(),
                problems.len()
            ),
            RetryAdvice::None,
            CorrelationId::new(),
        )),
    }
}

#[cfg(unix)]
type Store = xtrace_store::catalog_history_store::SqliteCatalogHistoryStore;

#[cfg(unix)]
fn open(project_dir: &Path) -> Result<(Store, ProjectId), CliError> {
    let env_reader = crate::paths::read_env_path;
    let preflight = crate::daemon::preflight_project(project_dir, &env_reader)?;
    let validated = crate::daemon::open_validated_project(preflight)?;
    Ok((Store::new(validated.store), validated.project_id))
}

type OperationIdentity = (String, String, String, String);

fn state_of(view: &OperationView, confirmed: &BTreeSet<OperationIdentity>) -> EffectiveState {
    if view.change_kind == CatalogChangeKind::Unknown {
        return EffectiveState::Unknown;
    }
    if confirmed.contains(&(
        view.application_component.clone(),
        view.binding_key.clone(),
        view.method.clone(),
        view.route_template.clone(),
    )) {
        return EffectiveState::Observed;
    }
    if view.provenance.iter().all(|p| p == "static_inferred") {
        EffectiveState::StaticOnly
    } else {
        EffectiveState::Registered
    }
}

/// The read port exposes aggregates, not individual claims. Keep that boundary explicit:
/// neither the first source nor the maximum confidence belongs to an arbitrary handler.
fn operation_input(
    view: &OperationView,
    confirmed: &BTreeSet<OperationIdentity>,
) -> OperationInput {
    let operation_id = serde_json::to_value(view.operation_id)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    OperationInput {
        operation_id,
        method: view.method.clone(),
        route_template: view.route_template.clone(),
        application_component: view.application_component.clone(),
        binding_key: view.binding_key.clone(),
        effective_state: state_of(view, confirmed),
        claims_available: false,
        claims: Vec::new(),
        catalog_summary: Some(CatalogSummaryInput {
            claim_count: view.claim_count,
            handler_symbols: view.handlers.clone(),
            handler_conflict: view.handler_conflict,
            single_claim_handler: match (
                view.claim_count,
                view.handlers.as_slice(),
                &view.source_path,
                view.source_line,
            ) {
                (1, [symbol], Some(path), Some(line)) if !view.handler_conflict => {
                    Some(HandlerInput {
                        symbol: symbol.clone(),
                        path: path.clone(),
                        line_start: line,
                        line_end: None,
                    })
                }
                _ => None,
            },
            highest_confidence_basis_points: view.confidence_basis_points,
            provenance: view.provenance.clone(),
            limitation_codes: view.limitation_codes.clone(),
        }),
    }
}

fn export_input(
    entry: &RevisionEntry,
    views: &[OperationView],
    confirmed: &BTreeSet<OperationIdentity>,
) -> ExportInput {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.export.catalog.v1\0");
    let mut identities: Vec<String> = views
        .iter()
        .map(|v| {
            format!(
                "{}\0{}\0{}\0{}\0{}",
                v.method,
                v.route_template,
                v.application_component,
                v.binding_key,
                v.operation_version_id
            )
        })
        .collect();
    identities.sort();
    for identity in &identities {
        hasher.update(identity.as_bytes());
        hasher.update(b"\n");
    }
    let components: BTreeSet<&str> =
        views.iter().map(|v| v.application_component.as_str()).collect();
    let application_name = match components.iter().collect::<Vec<_>>().as_slice() {
        [one] => (**one).to_owned(),
        _ => String::new(),
    };
    ExportInput {
        revision: RevisionInput {
            revision_id: entry.revision_id.to_string(),
            ordinal: entry.ordinal,
            catalog_hash: hasher.finalize().to_hex().to_string(),
            policy_digest: String::new(),
            application_name,
        },
        operations: views.iter().map(|v| operation_input(v, confirmed)).collect(),
        truncated: false,
    }
}

/// Validates a file path produced by the export crate: relative, no `..`, no separators tricks.
fn checked_relative(path: &str) -> Result<PathBuf, CliError> {
    let candidate = Path::new(path);
    let ok = !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && candidate.components().all(|c| matches!(c, Component::Normal(_)));
    if ok {
        Ok(candidate.to_path_buf())
    } else {
        Err(invalid("the export produced an unsafe file path"))
    }
}

#[cfg(unix)]
fn ensure_private_dir(path: &Path, create_parents: bool) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_dir() {
                return Err(invalid("the output path exists and is not a directory"));
            }
            if meta.uid() != rustix::process::getuid().as_raw()
                || meta.permissions().mode() & 0o777 != 0o700
            {
                return Err(invalid(
                    "the output directory must be owned by you and private (mode 0700)",
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).recursive(create_parents);
            builder.create(path).map_err(|_| {
                invalid("could not create the output directory; its parent must exist")
            })
        }
        Err(error) => Err(CliError::from(error)),
    }
}

#[cfg(unix)]
fn write_files(dir: &Path, output: &ExportOutput) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    // Validate every path before the first byte is written.
    let relative: Vec<PathBuf> =
        output.files.iter().map(|f| checked_relative(&f.path)).collect::<Result<_, _>>()?;
    check_destination(dir)?;
    let parent = dir.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(invalid("the output directory's parent must exist"));
    }
    let staging = parent.join(format!(".xtrace-export-{}.tmp", uuid::Uuid::now_v7()));
    // One fresh sibling holds the entire format. The destination changes only at rename.
    // On Unix rename cannot replace a non-empty directory, even if it appeared mid-write.
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result = (|| -> Result<(), CliError> {
        for (file, rel) in output.files.iter().zip(&relative) {
            let target = staging.join(rel);
            if let Some(parent) = target.parent() {
                let mut walk = staging.to_path_buf();
                for part in parent.strip_prefix(&staging).unwrap_or(Path::new("")).components() {
                    walk.push(part);
                    ensure_private_dir(&walk, false)?;
                }
            }
            let mut handle = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)?;
            handle.write_all(&file.bytes)?;
            handle.sync_all()?;
        }
        check_destination(dir)?;
        std::fs::rename(&staging, dir)?;
        Ok(())
    })();
    if result.is_err() {
        std::fs::remove_dir_all(&staging)?;
    }
    result
}

#[cfg(unix)]
fn check_destination(dir: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {
            ensure_private_dir(dir, false)?;
            if std::fs::read_dir(dir)?.next().transpose()?.is_some() {
                return Err(invalid(
                    "the output directory must be empty; choose a fresh directory",
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileDoc {
    path: String,
    bytes: usize,
    blake3: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OmissionDoc {
    operation_id: String,
    what: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportDoc {
    format: &'static str,
    preview: bool,
    written: bool,
    revision_id: String,
    revision_ordinal: u32,
    operation_count: usize,
    content_hash: String,
    output_dir: Option<String>,
    files: Vec<FileDoc>,
    omissions: Vec<OmissionDoc>,
    note: &'static str,
}

/// Runs `xtrace export`.
#[cfg(unix)]
pub async fn run(args: ExportArgs) -> Result<i32, CliError> {
    let format_name = args
        .format
        .as_deref()
        .ok_or_else(|| invalid("--format is required: openapi, postman, curl or bundle"))?;
    let format = ExportFormat::parse(format_name)
        .ok_or_else(|| invalid("--format must be openapi, postman, curl or bundle"))?;
    if args.yaml && format != ExportFormat::OpenApi {
        return Err(invalid("--yaml applies to --format openapi only"));
    }
    if !args.preview && args.output.is_none() {
        return Err(invalid("--output <DIR> is required unless --preview is given"));
    }
    let revision = args
        .revision
        .as_deref()
        .map(|text| {
            uuid::Uuid::parse_str(text)
                .map(CatalogRevisionId::from_uuid)
                .map_err(|_| invalid("a revision id is a UUID"))
        })
        .transpose()?;
    let (port, project) = open(&args.project_dir)?;
    // Read the full identities directly: reconciliation rows lose scope after joining routes.
    let confirmed: BTreeSet<OperationIdentity> = port
        .observed_operations(project)
        .map_err(|error| map_history(HistoryError::Port(error)))?
        .into_iter()
        .filter(|row| row.recording_count > 0)
        .map(|row| (row.application_component, row.binding_key, row.method, row.route_template))
        .collect();
    let service = CatalogHistoryService::new(port);
    let (entry, views) = service.operations(project, revision).map_err(map_history)?;
    let input = export_input(&entry, &views, &confirmed);

    let selection = if args.operations.is_empty() {
        None
    } else {
        let known: BTreeSet<&str> =
            input.operations.iter().map(|o| o.operation_id.as_str()).collect();
        if let Some(missing) = args.operations.iter().find(|id| !known.contains(id.as_str())) {
            return Err(not_found(format!(
                "operation {missing} is not in catalog revision {}",
                entry.revision_id
            )));
        }
        Some(args.operations.clone())
    };
    let mut request = ExportRequest::new(format);
    request.operation_ids = selection;
    request.yaml = args.yaml;
    let output = xtrace_export::export(&input, &request).map_err(|e| map_export(&e, format))?;

    let written = if args.preview {
        false
    } else if let Some(dir) = &args.output {
        write_files(dir, &output)?;
        true
    } else {
        false
    };
    let doc = ExportDoc {
        format: format.name(),
        preview: args.preview,
        written,
        revision_id: entry.revision_id.to_string(),
        revision_ordinal: entry.ordinal,
        operation_count: output.operation_count,
        content_hash: output.content_hash.clone(),
        output_dir: if written {
            args.output.as_ref().map(|p| p.display().to_string())
        } else {
            None
        },
        files: output
            .files
            .iter()
            .map(|f| FileDoc {
                path: f.path.clone(),
                bytes: f.bytes.len(),
                blake3: blake3::hash(&f.bytes).to_hex().to_string(),
            })
            .collect(),
        omissions: output
            .omissions
            .iter()
            .map(|o| OmissionDoc {
                operation_id: o.operation_id.clone(),
                what: o.what.clone(),
                reason: o.reason.clone(),
            })
            .collect(),
        note: "built from catalog summaries and linked endpoint observations; missing source \
               extents and per-claim confidence are explicit; no request or response body was \
               observed or retained, and nothing was sent anywhere",
    };
    let mut stdout = std::io::stdout().lock();
    if args.json {
        write_success(&mut stdout, &doc).map_err(|_| invalid("could not write output"))?;
    } else {
        use std::io::Write as _;
        let text = (|| -> std::io::Result<()> {
            writeln!(
                stdout,
                "{} export of catalog revision {} (#{}): {} operations, {} files, {}",
                doc.format,
                doc.revision_id,
                doc.revision_ordinal,
                doc.operation_count,
                doc.files.len(),
                if written { "written" } else { "preview, nothing written" }
            )?;
            for file in &doc.files {
                writeln!(stdout, "  {}  {} bytes", file.path, file.bytes)?;
            }
            for omission in &doc.omissions {
                writeln!(
                    stdout,
                    "  omitted {} {} ({})",
                    omission.operation_id, omission.what, omission.reason
                )?;
            }
            Ok(())
        })();
        text.map_err(|_| invalid("could not write output"))?;
    }
    Ok(0)
}

/// Runs `xtrace export` (non-Unix builds have no private-storage layer).
#[cfg(not(unix))]
pub async fn run(_args: ExportArgs) -> Result<i32, CliError> {
    Err(CliError::StoreUnavailable("export needs the Unix private-storage layer".to_owned()))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, reason = "fixed file-write failure fixtures")]
mod tests {
    use super::*;

    #[test]
    fn a_staging_failure_publishes_nothing_and_removes_partial_files() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("output");
        // The second file collides with the first after one successful write.
        let file = xtrace_export::ExportFile {
            path: "same.json".to_owned(),
            mode: 0o644,
            bytes: b"partial".to_vec(),
        };
        let output = ExportOutput {
            operation_count: 1,
            files: vec![file.clone(), file],
            omissions: Vec::new(),
            content_hash: String::new(),
        };
        assert!(write_files(&dir, &output).is_err());
        assert!(!dir.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        ensure_private_dir(&dir, false).unwrap();
        assert!(write_files(&dir, &output).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
