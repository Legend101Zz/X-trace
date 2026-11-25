//! Safe preview metadata and byte binding for an already-admitted catalog export.
//!
//! The caller owns authentication, project binding, bounded reads and revision resolution. This
//! module never opens files, reads storage, sends requests or executes generated recipes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use blake3::{Hash, Hasher};
use xtrace_application::catalog_discovery::history::{
    CatalogExportRevision, CatalogExportScope, CatalogExportSnapshot,
};
use xtrace_domain::{CatalogRevisionId, HttpMethod, ids::Id};

use crate::catalog::{self, CatalogExportError};
use crate::{ExportError, ExportFile, ExportFormat, ExportOutput, ExportRequest, Omission};

const MAX_OPERATIONS: usize = 4_096;
const MAX_FILES: usize = MAX_OPERATIONS + 5;
const MAX_RENDERED_BYTES: usize = 16 * 1024 * 1024;
const MAX_OMISSIONS: usize = 32_768;

/// Choices that a preview binds for the later Save action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewerExportRequest {
    /// Revision-selection policy.
    pub revision: CatalogExportRevision,
    /// Operation selection.
    pub scope: CatalogExportScope,
    /// Output format.
    pub format: ExportFormat,
    /// Choose YAML for standalone OpenAPI. The bundle always includes OpenAPI YAML.
    pub yaml: bool,
}

/// A recipe path may contain catalog text even when it passes the renderer's file checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviewFilename {
    /// Actual relative path that matches a renderer-controlled name.
    Available(String),
    /// The actual path includes a dynamic slug. Show only the recipe's ordinal in preview.
    WithheldRecipe {
        /// One-based recipe number assigned by the renderer.
        ordinal: usize,
    },
}

/// Metadata for one actual file, without its contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewFile {
    /// Actual safe path or explicit filename-withheld state.
    pub name: PreviewFilename,
    /// Logical non-executable file mode.
    pub mode: u32,
    /// Number of bytes in the file.
    pub bytes: usize,
    /// BLAKE3 digest of the exact file bytes.
    pub hash: Hash,
}

/// A group of renderer omissions. The counts cover exporter entries, including distinct
/// format-specific entries for a bundle. Names of omitted parameters and examples stay private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewOmission {
    /// Fixed format name when the omission applies to a format, or `None` when export-wide.
    pub format: Option<&'static str>,
    /// Fixed category for what was omitted, without its input-derived label.
    pub kind: &'static str,
    /// Fixed reason code. Unknown codes are represented by `other`.
    pub reason: &'static str,
    /// Number of exporter omissions in this group.
    pub count: usize,
}

/// Metadata for the exact logical artifacts that the viewer can offer for Save.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerExportPreview {
    /// Choices used to compute this preview.
    pub request: ViewerExportRequest,
    /// Revision actually read.
    pub revision_id: CatalogRevisionId,
    /// Ordinal of the resolved revision.
    pub revision_ordinal: u32,
    /// Number of selected catalog operations.
    pub selected_operations: usize,
    /// Exporter's reported operation count. For OpenAPI this is the native method/path count.
    pub emitted_operations: usize,
    /// Safe metadata for every file, in the exporter's path order.
    pub files: Vec<PreviewFile>,
    /// Grouped omission reasons and counts, without raw catalog labels.
    pub omissions: Vec<PreviewOmission>,
    /// Total bytes in all logical files, before transport framing.
    pub total_bytes: usize,
    /// Existing exporter digest over actual paths (including withheld paths), modes and bytes.
    pub content_hash: Hash,
}

/// The comparison value Save receives. It binds content and metadata, but grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewerExportApproval {
    /// Revision shown by the approved preview.
    pub revision_id: CatalogRevisionId,
    /// Versioned digest of the complete safe preview and the logical payload identity.
    pub digest: Hash,
}

impl ViewerExportPreview {
    /// Builds the exact comparison value to return alongside preview metadata.
    #[must_use]
    pub fn approval(&self) -> ViewerExportApproval {
        let mut hash = Hasher::new();
        hash.update(b"xtrace.viewer.export.approval.v1\0");
        match self.request.revision {
            CatalogExportRevision::Latest => {
                hash.update(&[0]);
            }
            CatalogExportRevision::Historical(id) => {
                hash.update(&[1]);
                hash.update(id.as_uuid().as_bytes());
            }
        }
        match self.request.scope {
            CatalogExportScope::All => {
                hash.update(&[0]);
            }
            CatalogExportScope::Operation(id) => {
                hash.update(&[1]);
                hash.update(id.as_uuid().as_bytes());
            }
        }
        hash_text(&mut hash, self.request.format.name());
        hash.update(&[u8::from(self.request.yaml)]);
        hash.update(self.revision_id.as_uuid().as_bytes());
        hash.update(&self.revision_ordinal.to_le_bytes());
        hash_count(&mut hash, self.selected_operations);
        hash_count(&mut hash, self.emitted_operations);
        hash_count(&mut hash, self.total_bytes);
        hash.update(self.content_hash.as_bytes());
        hash_count(&mut hash, self.files.len());
        for file in &self.files {
            match &file.name {
                PreviewFilename::Available(path) => {
                    hash.update(&[0]);
                    hash_text(&mut hash, path);
                }
                PreviewFilename::WithheldRecipe { ordinal } => {
                    hash.update(&[1]);
                    hash_count(&mut hash, *ordinal);
                }
            }
            hash.update(&file.mode.to_le_bytes());
            hash_count(&mut hash, file.bytes);
            hash.update(file.hash.as_bytes());
        }
        hash_count(&mut hash, self.omissions.len());
        for omission in &self.omissions {
            hash_text(&mut hash, omission.format.unwrap_or_default());
            hash_text(&mut hash, omission.kind);
            hash_text(&mut hash, omission.reason);
            hash_count(&mut hash, omission.count);
        }
        ViewerExportApproval { revision_id: self.revision_id, digest: hash.finalize() }
    }
}

fn hash_text(hash: &mut Hasher, text: &str) {
    hash_count(hash, text.len());
    hash.update(text.as_bytes());
}

fn hash_count(hash: &mut Hasher, count: usize) {
    hash.update(&(count as u64).to_le_bytes());
}

/// Which bound prevented the preview from being generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerExportLimit {
    /// Catalog rows supplied to this seam.
    Operations,
    /// Number of rendered files.
    Files,
    /// Sum of rendered logical file sizes.
    Bytes,
    /// Number of raw renderer omissions, before grouping.
    Omissions,
}

/// Safe refusal for either preview or Save. Diagnostics contain only fixed labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerExportError {
    /// The format and options do not form a supported viewer request.
    InvalidOptions,
    /// The explicitly requested revision was not resolved.
    RevisionUnavailable,
    /// The selected operation is absent from the resolved catalog revision.
    OperationUnavailable,
    /// The supplied catalog view is truncated or has invalid or duplicate identities.
    IncompleteCatalog,
    /// The approved choices, revision, metadata or artifact bytes no longer match.
    StalePreview,
    /// The existing renderer refused to emit secret-shaped content.
    SanitizerRefused,
    /// The renderer or its file inventory failed validation.
    InvalidArtifact,
    /// A complete preview would exceed the indicated bound.
    LimitExceeded(ViewerExportLimit),
}

impl fmt::Display for ViewerExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOptions => "invalid export options",
            Self::RevisionUnavailable => "catalog revision is unavailable",
            Self::OperationUnavailable => "operation is unavailable in this catalog revision",
            Self::IncompleteCatalog => "catalog view is incomplete or invalid",
            Self::StalePreview => "the approved export preview is stale",
            Self::SanitizerRefused => "the export sanitizer refused this artifact",
            Self::InvalidArtifact => "the export artifact failed validation",
            Self::LimitExceeded(ViewerExportLimit::Operations) => {
                "export exceeds the operation limit"
            }
            Self::LimitExceeded(ViewerExportLimit::Files) => "export exceeds the file limit",
            Self::LimitExceeded(ViewerExportLimit::Bytes) => "export exceeds the byte limit",
            Self::LimitExceeded(ViewerExportLimit::Omissions) => {
                "export exceeds the omission limit"
            }
        })
    }
}

impl std::error::Error for ViewerExportError {}

/// Files released by a successful Save comparison. They are the same render used for the check.
pub struct VerifiedViewerExport(Vec<ExportFile>);

impl VerifiedViewerExport {
    /// Takes the exact logical paths, modes and bytes for the download adapter.
    #[must_use]
    pub fn into_files(self) -> Vec<ExportFile> {
        self.0
    }
}

/// Renders metadata from a resolved, already-admitted catalog snapshot. The result contains
/// digests, not file contents. Rendered-byte and omission limits are checked after rendering.
/// They bound releasable output and metadata, not transient renderer allocation.
///
/// # Errors
/// Returns a safe refusal for invalid options, a mismatched snapshot or an invalid artifact.
pub fn preview(
    snapshot: &CatalogExportSnapshot,
    request: ViewerExportRequest,
) -> Result<ViewerExportPreview, ViewerExportError> {
    validate_resolution(snapshot, request)?;
    render(snapshot, request).map(|(metadata, _)| metadata)
}

/// Renders again from a fresh snapshot of the same admitted project, then checks the preview.
/// For Latest, resolve latest again. For Historical, read the explicitly requested revision.
/// In both cases the new snapshot must also resolve current linked observations.
///
/// # Errors
/// Returns a safe refusal for invalid or unsafe artifacts, limits or stale approval. No payload
/// is returned until both the approved revision and the metadata/content digest match.
pub fn save(
    snapshot: &CatalogExportSnapshot,
    request: ViewerExportRequest,
    approval: ViewerExportApproval,
) -> Result<VerifiedViewerExport, ViewerExportError> {
    validate_resolution(snapshot, request)?;
    if snapshot.revision.revision_id != approval.revision_id {
        return Err(ViewerExportError::StalePreview);
    }
    let (metadata, files) = render(snapshot, request)?;
    if metadata.approval() != approval {
        return Err(ViewerExportError::StalePreview);
    }
    Ok(VerifiedViewerExport(files))
}

fn validate_resolution(
    snapshot: &CatalogExportSnapshot,
    request: ViewerExportRequest,
) -> Result<(), ViewerExportError> {
    if request.yaml && request.format != ExportFormat::OpenApi {
        return Err(ViewerExportError::InvalidOptions);
    }
    if matches!(request.revision, CatalogExportRevision::Historical(expected) if expected != snapshot.revision.revision_id)
    {
        return Err(ViewerExportError::RevisionUnavailable);
    }
    Ok(())
}

fn render(
    snapshot: &CatalogExportSnapshot,
    request: ViewerExportRequest,
) -> Result<(ViewerExportPreview, Vec<ExportFile>), ViewerExportError> {
    use ViewerExportError::{IncompleteCatalog, InvalidArtifact, LimitExceeded};

    let revision_count = snapshot.catalog_identities.len();
    let selected_operations = snapshot.operations.len();
    if revision_count > MAX_OPERATIONS || selected_operations > MAX_OPERATIONS {
        return Err(LimitExceeded(ViewerExportLimit::Operations));
    }
    if u32::try_from(revision_count).ok() != Some(snapshot.revision.operation_count)
        || selected_operations > revision_count
    {
        return Err(IncompleteCatalog);
    }
    let ids: BTreeSet<_> = snapshot.operations.iter().map(|view| view.operation_id).collect();
    if selected_operations != ids.len() || !snapshot.linked_operation_ids.is_subset(&ids) {
        return Err(IncompleteCatalog);
    }
    let operation_ids = match request.scope {
        CatalogExportScope::All if selected_operations == revision_count => None,
        CatalogExportScope::All => return Err(IncompleteCatalog),
        CatalogExportScope::Operation(id) if !ids.contains(&id) => {
            return Err(ViewerExportError::OperationUnavailable);
        }
        CatalogExportScope::Operation(id) if selected_operations == 1 => Some(vec![id.to_string()]),
        CatalogExportScope::Operation(_) => return Err(IncompleteCatalog),
    };
    let input = catalog::prepare_snapshot(snapshot);
    let request_for_renderer =
        ExportRequest { format: request.format, operation_ids, yaml: request.yaml };
    let output = catalog::render(&input, &request_for_renderer).map_err(|error| match error {
        CatalogExportError::OperationNotFound { .. } => ViewerExportError::OperationUnavailable,
        CatalogExportError::Render(ExportError::SecretShaped { .. }) => {
            ViewerExportError::SanitizerRefused
        }
        CatalogExportError::Render(ExportError::InvalidDocument { .. }) => InvalidArtifact,
    })?;
    summarize(snapshot, request, output)
}

fn summarize(
    snapshot: &CatalogExportSnapshot,
    request: ViewerExportRequest,
    output: ExportOutput,
) -> Result<(ViewerExportPreview, Vec<ExportFile>), ViewerExportError> {
    let selected_operations = snapshot.operations.len();
    if output.operation_count > selected_operations
        || (request.format != ExportFormat::OpenApi
            && output.operation_count != selected_operations)
    {
        return Err(ViewerExportError::InvalidArtifact);
    }
    let omissions = summarize_omissions(&output.omissions, request.format)?;
    let (files, total_bytes) = summarize_files(&output.files, request, selected_operations)?;
    let metadata = ViewerExportPreview {
        request,
        revision_id: snapshot.revision.revision_id,
        revision_ordinal: snapshot.revision.ordinal,
        selected_operations,
        emitted_operations: output.operation_count,
        files,
        omissions,
        total_bytes,
        content_hash: Hash::from_hex(&output.content_hash)
            .map_err(|_| ViewerExportError::InvalidArtifact)?,
    };
    Ok((metadata, output.files))
}

fn summarize_files(
    files: &[ExportFile],
    request: ViewerExportRequest,
    selected_operations: usize,
) -> Result<(Vec<PreviewFile>, usize), ViewerExportError> {
    use ViewerExportError::{InvalidArtifact, LimitExceeded};

    if files.len() > MAX_FILES {
        return Err(LimitExceeded(ViewerExportLimit::Files));
    }
    let expected_count = match request.format {
        ExportFormat::OpenApi | ExportFormat::Postman => 1,
        ExportFormat::Curl => selected_operations + 1,
        ExportFormat::Bundle => selected_operations + 5,
    };
    if files.len() != expected_count || files.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(InvalidArtifact);
    }
    let mut manifest = Vec::with_capacity(files.len());
    let mut total_bytes = 0usize;
    let mut recipe_ordinals = BTreeSet::new();
    for file in files {
        total_bytes = total_bytes
            .checked_add(file.bytes.len())
            .filter(|sum| *sum <= MAX_RENDERED_BYTES)
            .ok_or(LimitExceeded(ViewerExportLimit::Bytes))?;
        let (name, ordinal) =
            preview_filename(&file.path, request, selected_operations).ok_or(InvalidArtifact)?;
        if file.mode != 0o644 || ordinal.is_some_and(|number| !recipe_ordinals.insert(number)) {
            return Err(InvalidArtifact);
        }
        manifest.push(PreviewFile {
            name,
            mode: file.mode,
            bytes: file.bytes.len(),
            hash: blake3::hash(&file.bytes),
        });
    }
    if matches!(request.format, ExportFormat::Curl | ExportFormat::Bundle)
        && recipe_ordinals.len() != selected_operations
    {
        return Err(InvalidArtifact);
    }
    Ok((manifest, total_bytes))
}

fn preview_filename(
    path: &str,
    request: ViewerExportRequest,
    selected_operations: usize,
) -> Option<(PreviewFilename, Option<usize>)> {
    let fixed = match request.format {
        ExportFormat::OpenApi if request.yaml => path == "openapi.yaml",
        ExportFormat::OpenApi => path == "openapi.json",
        ExportFormat::Postman => path == "collection.postman.json",
        ExportFormat::Curl => path == "all.sh",
        ExportFormat::Bundle => matches!(
            path,
            "README.md"
                | "manifest.json"
                | "openapi.yaml"
                | "collection.postman.json"
                | "curl/all.sh"
        ),
    };
    if fixed {
        return Some((PreviewFilename::Available(path.to_owned()), None));
    }
    let recipe = match request.format {
        ExportFormat::Curl => path,
        ExportFormat::Bundle => path.strip_prefix("curl/")?,
        _ => return None,
    };
    let (index, suffix) = recipe.strip_suffix(".sh")?.split_once('-')?;
    let (method, slug) = suffix.split_once('-')?;
    let ordinal = index.parse::<usize>().ok()?;
    if ordinal == 0
        || ordinal > selected_operations
        || index != format!("{ordinal:03}")
        || method.len() > 7
        || method.bytes().any(|byte| !byte.is_ascii_lowercase())
        || HttpMethod::parse(method).is_none()
        || slug.is_empty()
        || slug.len() > 40
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    // A root recipe's name uses only the ordinal, a recognized HTTP method and the fixed slug.
    // Other slugs encode caller-provided route text even when made filename-safe by the renderer.
    let name = if slug == "root" {
        PreviewFilename::Available(path.to_owned())
    } else {
        PreviewFilename::WithheldRecipe { ordinal }
    };
    Some((name, Some(ordinal)))
}

fn summarize_omissions(
    omissions: &[Omission],
    format: ExportFormat,
) -> Result<Vec<PreviewOmission>, ViewerExportError> {
    if omissions.len() > MAX_OMISSIONS {
        return Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Omissions));
    }
    let mut counts = BTreeMap::new();
    for omission in omissions {
        let (format, what) = omission_target(omission, format);
        *counts
            .entry((format, omission_kind(what), omission_reason(&omission.reason)))
            .or_insert(0) += 1;
    }
    Ok(counts
        .into_iter()
        .map(|((format, kind, reason), count)| PreviewOmission { format, kind, reason, count })
        .collect())
}

fn omission_target(omission: &Omission, format: ExportFormat) -> (Option<&'static str>, &str) {
    match (format, omission.what.split_once(':')) {
        (ExportFormat::Bundle, Some(("openapi", what))) => (Some("openapi"), what),
        (ExportFormat::Bundle, Some(("postman", what))) => (Some("postman"), what),
        (ExportFormat::Bundle, Some(("curl", what))) => (Some("curl"), what),
        _ => ((!omission.operation_id.is_empty()).then_some(format.name()), &omission.what),
    }
}

fn omission_kind(what: &str) -> &'static str {
    match what.split(':').next() {
        Some("claims") => "claims",
        Some("confidence") => "confidence",
        Some("example" | "examples") => "examples",
        Some("handler") => "handler",
        Some("operation" | "operations") => "operations",
        Some("param") => "parameters",
        Some("path_literal") => "path_literal",
        Some("policy_digest") => "policy_digest",
        Some("request_body") => "request_body",
        Some("source") => "source",
        _ => "other",
    }
}

fn omission_reason(reason: &str) -> &'static str {
    const CODES: &[&str] = &[
        "claim_count_mismatch",
        "claim_summary_mismatch",
        "claims_projection_partial",
        "claims_projection_unavailable",
        "contains_nul",
        "credential_not_embedded",
        "handler_conflict_unresolved",
        "handler_path_not_repo_relative",
        "handler_symbol_invalid",
        "header_value_has_line_break",
        "invalid_header_name",
        "no_body_example",
        "no_scenario_or_claim_example",
        "not_available_in_catalog_view",
        "optional_without_example",
        "path_param_not_in_template",
        "per_claim_confidence_unavailable",
        "per_claim_locations_unavailable",
        "secret_shaped",
        "source_end_line_unavailable",
        "source_path_not_repo_relative",
        "unknown_param_location",
    ];
    if reason.starts_with("duplicate_method_path_of:") {
        return "duplicate_method_path";
    }
    CODES.iter().copied().find(|code| *code == reason).unwrap_or("other")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(path: &str, bytes: Vec<u8>) -> ExportFile {
        ExportFile { path: path.to_owned(), mode: 0o644, bytes }
    }

    #[test]
    fn manifest_refuses_output_overflow_and_unexpected_paths_or_modes() {
        use ViewerExportError::{InvalidArtifact, LimitExceeded};

        let request = ViewerExportRequest {
            revision: CatalogExportRevision::Latest,
            scope: CatalogExportScope::All,
            format: ExportFormat::OpenApi,
            yaml: false,
        };
        assert_eq!(
            summarize_files(&vec![artifact("openapi.json", vec![]); MAX_FILES + 1], request, 0),
            Err(LimitExceeded(ViewerExportLimit::Files)),
        );
        assert_eq!(
            summarize_files(
                &[artifact("openapi.json", vec![0; MAX_RENDERED_BYTES + 1])],
                request,
                0
            ),
            Err(LimitExceeded(ViewerExportLimit::Bytes)),
        );
        assert_eq!(
            summarize_files(&[artifact("../openapi.json", vec![])], request, 0),
            Err(InvalidArtifact)
        );
        let runnable = ExportFile { mode: 0o755, ..artifact("openapi.json", vec![]) };
        assert_eq!(summarize_files(&[runnable], request, 0), Err(InvalidArtifact));
        let curl = ViewerExportRequest { format: ExportFormat::Curl, ..request };
        let duplicate_recipe_ordinal = [
            artifact("001-get-other.sh", vec![]),
            artifact("001-get-root.sh", vec![]),
            artifact("all.sh", vec![]),
        ];
        assert_eq!(summarize_files(&duplicate_recipe_ordinal, curl, 2), Err(InvalidArtifact));
    }

    #[test]
    fn omission_summary_counts_complete_groups_without_exposing_input_text() {
        let raw = Omission {
            what: "curl:param:query:client_secret".to_owned(),
            reason: "credential_not_embedded".to_owned(),
            operation_id: "operation-fixture-private-id".to_owned(),
        };
        let future =
            Omission { reason: "unrecognized fixture-private-text".to_owned(), ..raw.clone() };
        let summary = summarize_omissions(&[raw.clone(), future], ExportFormat::Bundle).unwrap();
        assert_eq!(
            summary,
            [
                PreviewOmission {
                    format: Some("curl"),
                    kind: "parameters",
                    reason: "credential_not_embedded",
                    count: 1
                },
                PreviewOmission {
                    format: Some("curl"),
                    kind: "parameters",
                    reason: "other",
                    count: 1
                },
            ]
        );
        assert_eq!(
            summarize_omissions(&vec![raw; MAX_OMISSIONS + 1], ExportFormat::Bundle),
            Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Omissions)),
        );
    }
}
