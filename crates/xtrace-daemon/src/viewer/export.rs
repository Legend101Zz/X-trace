//! Authenticated catalog-only preview and attachments. No filesystem writes or remote delivery.

use std::io::{self, Write};
use std::sync::atomic::AtomicBool;

use xtrace_application::catalog_discovery::history::{
    CatalogExportReadError as ReadError, CatalogExportRevision, CatalogExportScope,
    CatalogExportSnapshot,
};
use xtrace_domain::CatalogRevisionId;
use xtrace_export::viewer::{
    PreviewFilename, ViewerExportApproval, ViewerExportError, ViewerExportPreview,
    ViewerExportRequest,
};
use xtrace_export::{ExportFile, ExportFormat};

use super::*;

pub(super) const MAX_EXPORT_CONCURRENCY: usize = 2;

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;
// Leaves time for a fixed problem response inside the connection's existing 15-second limit.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(14);

pub(super) type CatalogExportReader = dyn Fn(
        ProjectId,
        CatalogExportRevision,
        CatalogExportScope,
        CatalogExportCancellation,
    ) -> Result<CatalogExportSnapshot, ReadError>
    + Send
    + Sync;

/// Cooperative cancellation shared by a viewer request and its admitted catalog read.
/// Dropping the request future or reaching its deadline cancels work. Blocking workers retain
/// their query permit until they actually finish. No payload is retained for another request.
#[derive(Clone)]
pub struct CatalogExportCancellation {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl CatalogExportCancellation {
    /// Whether the HTTP request ended or its computation deadline expired.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }

    fn check(&self) -> Result<(), Failure> {
        if self.is_cancelled() { Err(Failure::Deadline) } else { Ok(()) }
    }
}

struct CancelOnDrop(CatalogExportCancellation);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approval {
    revision_id: CatalogRevisionId,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewBody {
    format: String,
    yaml: bool,
    revision: String,
    scope: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SaveBody {
    format: String,
    yaml: bool,
    revision: String,
    scope: String,
    approval: Approval,
}

struct ExportBody {
    format: String,
    yaml: bool,
    revision: String,
    scope: String,
    approval: Option<Approval>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Choices {
    format: &'static str,
    yaml: bool,
    revision: String,
    scope: String,
}

impl ExportBody {
    fn resolve(
        &self,
        save: bool,
    ) -> Result<(ViewerExportRequest, Option<ViewerExportApproval>), Failure> {
        let format = ExportFormat::parse(&self.format).ok_or(Failure::Invalid)?;
        if self.yaml && format != ExportFormat::OpenApi {
            return Err(Failure::Invalid);
        }
        let revision = if self.revision == "latest" {
            CatalogExportRevision::Latest
        } else {
            CatalogExportRevision::Historical(self.revision.parse().map_err(|_| Failure::Invalid)?)
        };
        let scope = if self.scope == "all" {
            CatalogExportScope::All
        } else if let Some(id) = self.scope.strip_prefix("observed:") {
            let operation_id: xtrace_domain::OperationId =
                id.parse().map_err(|_| Failure::Invalid)?;
            // UUID parsing also accepts spellings outside the selector's canonical grammar.
            if operation_id.to_string() != id {
                return Err(Failure::Invalid);
            }
            CatalogExportScope::ObservedOperation(operation_id)
        } else {
            CatalogExportScope::Operation(self.scope.parse().map_err(|_| Failure::Invalid)?)
        };
        let approval = match (&self.approval, save) {
            (None, false) => None,
            (Some(approval), true)
                if approval.digest.len() == 64
                    && approval
                        .digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                let digest =
                    blake3::Hash::from_hex(&approval.digest).map_err(|_| Failure::Invalid)?;
                Some(ViewerExportApproval { revision_id: approval.revision_id, digest })
            }
            _ => return Err(Failure::Invalid),
        };
        Ok((ViewerExportRequest { revision, scope, format, yaml: self.yaml }, approval))
    }
}

fn choices(request: ViewerExportRequest) -> Choices {
    Choices {
        format: request.format.name(),
        yaml: request.yaml,
        revision: match request.revision {
            CatalogExportRevision::Latest => "latest".to_owned(),
            CatalogExportRevision::Historical(id) => id.to_string(),
        },
        scope: match request.scope {
            CatalogExportScope::All => "all".to_owned(),
            CatalogExportScope::Operation(id) => id.to_string(),
            CatalogExportScope::ObservedOperation(id) => format!("observed:{id}"),
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileMetadata {
    name: Option<String>,
    recipe_ordinal: Option<usize>,
    mode: u32,
    bytes: usize,
    blake3: String,
}

#[derive(Serialize)]
struct OmissionMetadata {
    format: Option<&'static str>,
    kind: &'static str,
    reason: &'static str,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadMetadata {
    filename: &'static str,
    media_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewMetadata {
    schema_version: u32,
    request_id: CorrelationId,
    project_id: ProjectId,
    request: Choices,
    catalog_operation_id: Option<OperationId>,
    revision_id: CatalogRevisionId,
    revision_ordinal: u32,
    selected_operations: usize,
    emitted_operations: usize,
    files: Vec<FileMetadata>,
    omissions: Vec<OmissionMetadata>,
    total_bytes: usize,
    content_hash: String,
    approval: Approval,
    download: DownloadMetadata,
}

fn download_metadata(request: ViewerExportRequest) -> DownloadMetadata {
    let (filename, media_type) = match request.format {
        ExportFormat::OpenApi if request.yaml => ("openapi.yaml", "application/yaml"),
        ExportFormat::OpenApi => ("openapi.json", "application/json"),
        ExportFormat::Postman => ("collection.postman.json", "application/json"),
        ExportFormat::Curl => ("xtrace-curl.zip", "application/zip"),
        ExportFormat::Bundle => ("xtrace-bundle.zip", "application/zip"),
    };
    DownloadMetadata { filename, media_type }
}

fn metadata(
    preview: ViewerExportPreview,
    project_id: ProjectId,
    request_id: CorrelationId,
) -> PreviewMetadata {
    let approval = preview.approval();
    PreviewMetadata {
        schema_version: 1,
        request_id,
        project_id,
        request: choices(preview.request),
        catalog_operation_id: preview.catalog_operation_id,
        revision_id: preview.revision_id,
        revision_ordinal: preview.revision_ordinal,
        selected_operations: preview.selected_operations,
        emitted_operations: preview.emitted_operations,
        files: preview
            .files
            .into_iter()
            .map(|file| {
                let (name, recipe_ordinal) = match file.name {
                    PreviewFilename::Available(name) => (Some(name), None),
                    PreviewFilename::WithheldRecipe { ordinal } => (None, Some(ordinal)),
                };
                FileMetadata {
                    name,
                    recipe_ordinal,
                    mode: file.mode,
                    bytes: file.bytes,
                    blake3: file.hash.to_hex().to_string(),
                }
            })
            .collect(),
        omissions: preview
            .omissions
            .into_iter()
            .map(|omission| OmissionMetadata {
                format: omission.format,
                kind: omission.kind,
                reason: omission.reason,
                count: omission.count,
            })
            .collect(),
        total_bytes: preview.total_bytes,
        content_hash: preview.content_hash.to_hex().to_string(),
        approval: Approval {
            revision_id: approval.revision_id,
            digest: approval.digest.to_hex().to_string(),
        },
        download: download_metadata(preview.request),
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Invalid,
    Read(ReadError),
    Render(ViewerExportError),
    Limit,
    Deadline,
    Unavailable,
}

impl Failure {
    fn response(self, request_id: CorrelationId) -> Response {
        use ReadError as R;
        use ViewerExportError as E;
        let (status, code, message) = match self {
            Self::Invalid | Self::Render(E::InvalidOptions) => {
                (StatusCode::BAD_REQUEST, "XTR-EXPORT-INVALID", "Export selection is invalid")
            }
            Self::Read(R::NoCatalog) => {
                (StatusCode::NOT_FOUND, "XTR-EXPORT-NO-CATALOG", "No catalog revision is available")
            }
            Self::Read(R::RevisionNotFound) | Self::Render(E::RevisionUnavailable) => {
                (StatusCode::NOT_FOUND, "XTR-EXPORT-REVISION", "Catalog revision is unavailable")
            }
            Self::Read(R::OperationNotFound) | Self::Render(E::OperationUnavailable) => (
                StatusCode::NOT_FOUND,
                "XTR-EXPORT-OPERATION",
                "Operation is unavailable in this catalog revision",
            ),
            Self::Render(E::StalePreview) => (
                StatusCode::CONFLICT,
                "XTR-EXPORT-STALE",
                "Export preview changed; refresh preview before saving",
            ),
            Self::Render(E::SanitizerRefused) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "XTR-EXPORT-SANITIZER",
                "Export sanitizer refused this artifact",
            ),
            Self::Read(R::Corrupt) | Self::Render(E::IncompleteCatalog | E::InvalidArtifact) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "XTR-EXPORT-EVIDENCE",
                "Catalog export evidence could not be verified",
            ),
            Self::Read(R::LimitExceeded) | Self::Render(E::LimitExceeded(_)) | Self::Limit => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "XTR-EXPORT-LIMIT",
                "Export exceeds its resource limit",
            ),
            Self::Read(R::Busy) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "XTR-EXPORT-BUSY",
                "Catalog export capacity is unavailable",
            ),
            Self::Read(R::Cancelled) | Self::Deadline => (
                StatusCode::GATEWAY_TIMEOUT,
                "XTR-EXPORT-DEADLINE",
                "Catalog export computation expired",
            ),
            Self::Read(R::Unavailable) | Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "XTR-EXPORT-UNAVAILABLE",
                "Catalog export is unavailable",
            ),
        };
        problem_with_id(status, code, message, request_id)
    }
}

pub(super) async fn preview_route<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    route(state, headers, query, body, false).await
}

pub(super) async fn save_route<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    route(state, headers, query, body, true).await
}

async fn route<P>(
    state: Arc<ViewerState<P>>,
    headers: HeaderMap,
    query: Option<String>,
    body: Result<Bytes, BytesRejection>,
    save: bool,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    if !valid_request_origin(&headers, &state.host, &state.origin, false) {
        return problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-ORIGIN",
            "Request origin is not accepted",
            request_id,
        );
    }
    if !one_header_equals(&headers, HeaderName::from_static("x-xtrace-client"), "viewer-v1") {
        return problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-CLIENT",
            "Viewer request is not accepted",
            request_id,
        );
    }
    if !authorized(&headers, &state).await {
        return problem_with_id(
            StatusCode::UNAUTHORIZED,
            "XTR-VIEWER-SESSION",
            "Viewer session is missing or expired",
            request_id,
        );
    }
    if !is_json(&headers) || query.is_some() {
        return Failure::Invalid.response(request_id);
    }
    let body = match body {
        Ok(body) if body.len() <= MAX_AUTH_BODY_BYTES => body,
        _ => return Failure::Limit.response(request_id),
    };
    let parsed = if save {
        serde_json::from_slice::<SaveBody>(&body).map(|body| ExportBody {
            format: body.format,
            yaml: body.yaml,
            revision: body.revision,
            scope: body.scope,
            approval: Some(body.approval),
        })
    } else {
        serde_json::from_slice::<PreviewBody>(&body).map(|body| ExportBody {
            format: body.format,
            yaml: body.yaml,
            revision: body.revision,
            scope: body.scope,
            approval: None,
        })
    };
    let request = match parsed.ok().and_then(|body| body.resolve(save).ok()) {
        Some(request) => request,
        None => return Failure::Invalid.response(request_id),
    };
    let Some(reader) = state.catalog_exports.clone() else {
        return Failure::Unavailable.response(request_id);
    };
    // This independent slot covers the read/render and the complete payload lifetime,
    // including Bytes clones that the HTTP transport retains after polling the body.
    let slot = match state.export_slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return Failure::Read(ReadError::Busy).response(request_id),
    };
    let cancellation = CatalogExportCancellation {
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + EXPORT_TIMEOUT,
    };
    let _cancel = CancelOnDrop(cancellation.clone());
    let project_id = state.project_id;
    let result = timeout(
        EXPORT_TIMEOUT,
        state.query_lane.run(move || {
            compute(reader.as_ref(), project_id, request_id, request, cancellation)
                .map(|output| (output, slot))
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok((output, slot)))) => output.response(request_id, slot),
        Ok(Ok(Err(error))) => error.response(request_id),
        Ok(Err(QueryLaneError::Busy | QueryLaneError::Closed)) => {
            Failure::Read(ReadError::Busy).response(request_id)
        }
        Ok(Err(QueryLaneError::Join)) => Failure::Unavailable.response(request_id),
        Err(_) => Failure::Deadline.response(request_id),
    }
}

enum Output {
    Preview(Vec<u8>),
    Attachment { bytes: Vec<u8>, metadata: DownloadMetadata },
}

// A Bytes owner is shared by every slice/clone handed to the transport. Holding the
// semaphore here, rather than in a body wrapper, follows the backing allocation after
// Body::poll_frame transfers the data. Boxing removes spare Vec capacity from retention.
struct RetainedPayload {
    bytes: Box<[u8]>,
    _slot: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for RetainedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Output {
    fn response(self, request_id: CorrelationId, slot: OwnedSemaphorePermit) -> Response {
        let (bytes, media, filename) = match self {
            Self::Preview(bytes) => (bytes, "application/json", None),
            Self::Attachment { bytes, metadata } => {
                (bytes, metadata.media_type, Some(metadata.filename))
            }
        };
        let payload =
            Bytes::from_owner(RetainedPayload { bytes: bytes.into_boxed_slice(), _slot: slot });
        let mut response = Response::new(Body::from(payload));
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
        if let Some(filename) = filename {
            if let Ok(value) =
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            {
                response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
            }
        }
        if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
            response.headers_mut().insert(HeaderName::from_static("x-xtrace-request-id"), value);
        }
        add_security_headers(response.headers_mut());
        response
    }
}

fn compute(
    reader: &CatalogExportReader,
    project_id: ProjectId,
    request_id: CorrelationId,
    (request, approval): (ViewerExportRequest, Option<ViewerExportApproval>),
    cancellation: CatalogExportCancellation,
) -> Result<Output, Failure> {
    cancellation.check()?;
    let snapshot = reader(project_id, request.revision, request.scope, cancellation.clone())
        .map_err(Failure::Read)?;
    cancellation.check()?;
    xtrace_export::viewer::admit_http_render(&snapshot).map_err(Failure::Render)?;
    cancellation.check()?;
    if let Some(approval) = approval {
        let files = xtrace_export::viewer::save(&snapshot, request, approval)
            .map_err(Failure::Render)?
            .into_files();
        cancellation.check()?;
        let bytes = match request.format {
            ExportFormat::OpenApi | ExportFormat::Postman => {
                let mut files = files;
                if files.len() != 1 {
                    return Err(Failure::Render(ViewerExportError::InvalidArtifact));
                }
                files.remove(0).bytes
            }
            ExportFormat::Curl | ExportFormat::Bundle => zip(files, &cancellation)?,
        };
        cancellation.check()?;
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(Failure::Limit);
        }
        Ok(Output::Attachment { bytes, metadata: download_metadata(request) })
    } else {
        let preview =
            xtrace_export::viewer::preview(&snapshot, request).map_err(Failure::Render)?;
        cancellation.check()?;
        let metadata = metadata(preview, project_id, request_id);
        let mut writer = CappedWriter::new(MAX_METADATA_BYTES);
        serde_json::to_writer(&mut writer, &metadata).map_err(|_| Failure::Limit)?;
        cancellation.check()?;
        Ok(Output::Preview(writer.bytes))
    }
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl CappedWriter {
    fn new(limit: usize) -> Self {
        Self { bytes: Vec::new(), limit }
    }
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("export encoding limit"));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            // Geometric growth keeps serialization copying linear, while each requested
            // capacity stays inside the admitted response budget.
            let capacity =
                self.bytes.capacity().saturating_mul(2).max(1024).min(self.limit).max(needed);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| io::Error::other("export allocation limit"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Minimal ZIP32 STORE encoder: no compressor state, extras, comments or data descriptors.
/// The only entries are already-verified renderer paths and exact bytes; ZIP never adds files.
fn zip(
    mut files: Vec<ExportFile>,
    cancellation: &CatalogExportCancellation,
) -> Result<Vec<u8>, Failure> {
    cancellation.check()?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let size = files
        .iter()
        .try_fold(22_usize, |total, file| {
            if file.path.len() > u16::MAX as usize || file.mode != 0o644 {
                return None;
            }
            total.checked_add(file.bytes.len())?.checked_add(76 + 2 * file.path.len())
        })
        .filter(|size| *size <= MAX_ATTACHMENT_BYTES)
        .ok_or(Failure::Limit)?;
    let count = u16::try_from(files.len()).map_err(|_| Failure::Limit)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| Failure::Limit)?;
    let mut central = Vec::with_capacity(files.len());
    for file in files {
        cancellation.check()?;
        let offset = out.len() as u32;
        let crc = crc32(&file.bytes, cancellation)?;
        let len = file.bytes.len() as u32;
        put32(&mut out, 0x0403_4b50);
        put16(&mut out, 20);
        put16(&mut out, 0x0800);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0x0021);
        put32(&mut out, crc);
        put32(&mut out, len);
        put32(&mut out, len);
        put16(&mut out, file.path.len() as u16);
        put16(&mut out, 0);
        out.extend_from_slice(file.path.as_bytes());
        out.extend_from_slice(&file.bytes);
        central.push((file.path, len, crc, offset));
    }
    let central_start = out.len() as u32;
    for (path, len, crc, offset) in central {
        cancellation.check()?;
        put32(&mut out, 0x0201_4b50);
        put16(&mut out, 0x0314);
        put16(&mut out, 20);
        put16(&mut out, 0x0800);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0x0021);
        put32(&mut out, crc);
        put32(&mut out, len);
        put32(&mut out, len);
        put16(&mut out, path.len() as u16);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put32(&mut out, 0o100644 << 16);
        put32(&mut out, offset);
        out.extend_from_slice(path.as_bytes());
    }
    let central_size = out.len() as u32 - central_start;
    put32(&mut out, 0x0605_4b50);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, count);
    put16(&mut out, count);
    put32(&mut out, central_size);
    put32(&mut out, central_start);
    put16(&mut out, 0);
    if out.len() != size {
        return Err(Failure::Render(ViewerExportError::InvalidArtifact));
    }
    Ok(out)
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8], cancellation: &CatalogExportCancellation) -> Result<u32, Failure> {
    let mut crc = !0_u32;
    for chunk in bytes.chunks(4096) {
        cancellation.check()?;
        for byte in chunk {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
        }
    }
    Ok(!crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cancellation() -> CatalogExportCancellation {
        CatalogExportCancellation {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    #[test]
    fn encoding_rejects_before_crossing_cap_and_grows_geometrically() {
        let mut writer = CappedWriter::new(8192);
        let mut capacities = Vec::new();
        for _ in 0..8192 {
            writer.write_all(b"x").unwrap();
            if capacities.last() != Some(&writer.bytes.capacity()) {
                capacities.push(writer.bytes.capacity());
            }
            assert!(writer.bytes.capacity() <= 8192);
        }
        assert!(capacities.len() <= 4, "bounded geometric capacity growth");
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes.len(), 8192);
    }

    #[test]
    fn cancelled_and_expired_work_cannot_render_or_encode_payload() {
        let cancelled = cancellation();
        let guard = CancelOnDrop(cancelled.clone());
        drop(guard);
        assert!(matches!(cancelled.check(), Err(Failure::Deadline)));
        assert!(matches!(zip(Vec::new(), &cancelled), Err(Failure::Deadline)));
        let expired = CatalogExportCancellation { deadline: Instant::now(), ..cancellation() };
        assert!(expired.is_cancelled());
        let reads = Arc::new(AtomicUsize::new(0));
        let calls = reads.clone();
        let reader = move |_, _, _, _| -> Result<CatalogExportSnapshot, ReadError> {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(ReadError::Unavailable)
        };
        let request = ViewerExportRequest {
            revision: CatalogExportRevision::Latest,
            scope: CatalogExportScope::All,
            format: ExportFormat::Bundle,
            yaml: false,
        };
        assert!(matches!(
            compute(&reader, ProjectId::new(), CorrelationId::new(), (request, None), expired),
            Err(Failure::Deadline)
        ));
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn zip_rejects_over_budget_before_allocation_and_crc_matches_known_standard_vector() {
        assert_eq!(crc32(b"123456789", &cancellation()).unwrap(), 0xcbf4_3926);
        let file = ExportFile {
            path: "all.sh".to_owned(),
            mode: 0o644,
            bytes: vec![0; MAX_ATTACHMENT_BYTES],
        };
        assert!(matches!(zip(vec![file], &cancellation()), Err(Failure::Limit)));
    }
}
