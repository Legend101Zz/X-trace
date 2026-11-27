//! `xtrace exercise`: private plan, review, approval, fail-closed execution, and provenance.

use std::path::PathBuf;

use clap::Subcommand;
use xtrace_application::exercise::{
    CreateExercisePlan, ExerciseError, ExercisePlanService, MAX_PLAN_DOCUMENT_BYTES,
    review_document,
};

use crate::error::CliError;

/// Shared arguments for `xtrace exercise` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct ExerciseArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON (private review or provenance output).
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `xtrace exercise plan`.
#[derive(Clone, Debug, clap::Args)]
pub struct PlanArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Owner-private JSON input. Its parent and file must pass private admission.
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,
}

/// Arguments for an explicit edit, revoking the exact original and creating a new draft.
#[derive(Clone, Debug, clap::Args)]
pub struct EditArgs {
    /// Input for the new draft.
    #[command(flatten)]
    pub plan: PlanArgs,
    /// Exact immutable hash whose consent this edit revokes.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
}

/// Arguments for `xtrace exercise review`.
#[derive(Clone, Debug, clap::Args)]
pub struct ReviewArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Exact immutable plan hash.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
}

/// Arguments for `xtrace exercise approve`.
#[derive(Clone, Debug, clap::Args)]
pub struct ApproveArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Hash of the reviewed plan being approved.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
    /// Identity from the exact reviewed plan. Without a selected plan the legacy fallback remains.
    #[arg(long = "plan-id", value_name = "ID")]
    pub plan_id: Option<String>,
    /// Explicit consent to each reviewed item (including mutations and unknown effects).
    #[arg(long = "item", value_name = "ITEM_ID")]
    pub items: Vec<String>,
    /// Confirm this exact target is your ordinary local development application.
    #[arg(long)]
    pub confirm_owned_development_target: bool,
}

/// Arguments for `xtrace exercise run`.
#[derive(Clone, Debug, clap::Args)]
pub struct RunArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Exact immutable hash of the approved plan to run. Without a selection, legacy exit-9 fallback applies.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: Option<String>,
    /// Identity from the exact approved plan.
    #[arg(long = "plan-id", value_name = "ID")]
    pub plan_id: Option<String>,
    /// Confirm this exact target is your ordinary local development application.
    #[arg(long)]
    pub confirm_owned_development_target: bool,
    /// Optional owner-private JSON object mapping opaque credential handles to secret values.
    #[arg(long = "credentials-file", value_name = "FILE")]
    pub credentials_file: Option<PathBuf>,
}

/// Arguments for `xtrace exercise show`.
#[derive(Clone, Debug, clap::Args)]
pub struct ShowArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Exact immutable plan hash; no selection retains the legacy fallback.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: Option<String>,
}

/// Arguments for `xtrace exercise provenance`.
#[derive(Clone, Debug, clap::Args)]
pub struct ProvenanceArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Filter provenance runs to a specific plan hash.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: Option<String>,
    /// Show a single ephemeral exercise run UUID.
    #[arg(long = "run-id", value_name = "RUN_ID")]
    pub run_id: Option<String>,
    /// Exercise item UUID to link with `--recording-id` inside `--run-id`.
    #[arg(long = "link-item", value_name = "ITEM_ID", requires_all = ["run_id", "recording_id"])]
    pub link_item: Option<String>,
    /// Recording UUID to link with `--link-item` inside `--run-id`.
    #[arg(long = "recording-id", value_name = "RECORDING_ID", requires_all = ["run_id", "link_item"])]
    pub recording_id: Option<String>,
    /// Maximum number of runs to list when querying by plan hash or project (`1..=100`).
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

/// `xtrace exercise` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ExerciseCommand {
    /// Build a private immutable plan from an actually observed operation.
    Plan(PlanArgs),
    /// Replace an exact active plan with a new unapproved draft; sends nothing.
    Edit(EditArgs),
    /// Explicitly review an exact plan; sends nothing.
    Review(ReviewArgs),
    /// Approve an exact reviewed plan; sends nothing.
    Approve(ApproveArgs),
    /// Run an explicitly approved, non-expired loopback exercise plan once.
    Run(RunArgs),
    /// Inspect a private plan without changing approval.
    Show(ShowArgs),
    /// Report ephemeral exercise runs, failures, and recording linkages (or link a recording).
    Provenance(ProvenanceArgs),
}

fn map_error(error: ExerciseError) -> CliError {
    use xtrace_domain::{AppError, CorrelationId, ErrorCategory, ErrorCode, RetryAdvice};
    let (code, category) = match error {
        ExerciseError::InvalidInput => ("XTR-EXERCISE-INPUT", ErrorCategory::Validation),
        ExerciseError::BindingUnavailable => ("XTR-EXERCISE-BINDING", ErrorCategory::NotFound),
        ExerciseError::NotFound => ("XTR-EXERCISE-NOT-FOUND", ErrorCategory::NotFound),
        ExerciseError::StorageUnavailable => ("XTR-EXERCISE-STORAGE", ErrorCategory::Resource),
        ExerciseError::StagingOccupied => ("XTR-EXERCISE-STAGING", ErrorCategory::Resource),
        ExerciseError::Conflict => ("XTR-EXERCISE-CONFLICT", ErrorCategory::Conflict),
        ExerciseError::HashMismatch => ("XTR-EXERCISE-HASH", ErrorCategory::Conflict),
        ExerciseError::Expired => ("XTR-EXERCISE-EXPIRED", ErrorCategory::Policy),
        ExerciseError::UnresolvedInput => ("XTR-EXERCISE-UNRESOLVED", ErrorCategory::Policy),
        ExerciseError::ApprovalRequired => ("XTR-EXERCISE-APPROVAL", ErrorCategory::Policy),
        ExerciseError::CredentialValue => ("XTR-EXERCISE-CREDENTIAL", ErrorCategory::Policy),
        ExerciseError::Superseded => ("XTR-EXERCISE-SUPERSEDED", ErrorCategory::Conflict),
        ExerciseError::AlreadyConsumed => ("XTR-EXERCISE-CONSUMED", ErrorCategory::Conflict),
    };
    CliError::App(AppError::new(
        ErrorCode::new(code),
        category,
        error.to_string(),
        RetryAdvice::None,
        CorrelationId::new(),
    ))
}

#[cfg(unix)]
fn map_execution_error(error: xtrace_application::exercise::ExerciseExecutionError) -> CliError {
    use xtrace_application::exercise::{ExerciseExecutionError, ExerciseFailureClass};
    use xtrace_domain::{
        AppError, CorrelationId, ErrorCategory, ErrorCode, RetryAdvice, SafeScalar,
    };

    match error {
        ExerciseExecutionError::Lifecycle(e) => map_error(e),
        ExerciseExecutionError::Failed { run_id, failure_class, http_status, message } => {
            let (code, category) = match failure_class {
                ExerciseFailureClass::ApprovalRequired => {
                    ("XTR-EXERCISE-APPROVAL", ErrorCategory::Policy)
                }
                ExerciseFailureClass::PlanExpired => {
                    ("XTR-EXERCISE-EXPIRED", ErrorCategory::Policy)
                }
                ExerciseFailureClass::PlanSuperseded => {
                    ("XTR-EXERCISE-SUPERSEDED", ErrorCategory::Conflict)
                }
                ExerciseFailureClass::AlreadyConsumed => {
                    ("XTR-EXERCISE-CONSUMED", ErrorCategory::Conflict)
                }
                ExerciseFailureClass::HashMismatch => {
                    ("XTR-EXERCISE-HASH", ErrorCategory::Conflict)
                }
                ExerciseFailureClass::UnresolvedInput => {
                    ("XTR-EXERCISE-UNRESOLVED", ErrorCategory::Policy)
                }
                ExerciseFailureClass::InvalidTarget | ExerciseFailureClass::InvalidRequest => {
                    ("XTR-EXERCISE-INPUT", ErrorCategory::Validation)
                }
                ExerciseFailureClass::DnsResolutionFailed
                | ExerciseFailureClass::NonLoopbackDestination
                | ExerciseFailureClass::RedirectRefused => {
                    ("XTR-EXERCISE-DESTINATION", ErrorCategory::Policy)
                }
                ExerciseFailureClass::CredentialResolutionFailed => {
                    ("XTR-EXERCISE-CREDENTIAL", ErrorCategory::Policy)
                }
                ExerciseFailureClass::RequestSizeExceeded
                | ExerciseFailureClass::ResponseSizeExceeded => {
                    ("XTR-EXERCISE-BOUNDS", ErrorCategory::Policy)
                }
                ExerciseFailureClass::RateLimitExceeded => {
                    ("XTR-EXERCISE-RATE-LIMIT", ErrorCategory::Resource)
                }
                ExerciseFailureClass::Timeout => ("XTR-EXERCISE-TIMEOUT", ErrorCategory::Transport),
                ExerciseFailureClass::TransportError => {
                    ("XTR-EXERCISE-TRANSPORT", ErrorCategory::Transport)
                }
                ExerciseFailureClass::DeliveryUnknown => {
                    ("XTR-EXERCISE-DELIVERY-UNKNOWN", ErrorCategory::Transport)
                }
                ExerciseFailureClass::StorageError => {
                    ("XTR-EXERCISE-STORAGE", ErrorCategory::Resource)
                }
            };
            let mut app = AppError::new(
                ErrorCode::new(code),
                category,
                message,
                RetryAdvice::None,
                CorrelationId::new(),
            )
            .with_detail("failure_class", SafeScalar::String(failure_class.as_str().to_owned()));
            if let Some(id) = run_id {
                app = app.with_detail("exercise_run_id", SafeScalar::String(id.to_string()));
            }
            if let Some(status) = http_status {
                app = app.with_detail("http_status", SafeScalar::Integer(i64::from(status)));
            }
            CliError::App(app)
        }
    }
}

#[cfg(unix)]
fn open_project(
    common: &ExerciseArgs,
    create_plans_dir: bool,
) -> Result<
    (
        crate::exercise_store::ExerciseProject,
        crate::exercise_store::PrivateExerciseStore,
        xtrace_domain::ProjectId,
    ),
    CliError,
> {
    let preflight =
        crate::daemon::preflight_project(&common.project_dir, &crate::paths::read_env_path)?;
    let project = crate::daemon::open_validated_project(preflight)?;
    let project_id = project.project_id;
    let exercise_project = crate::exercise_store::ExerciseProject::new(
        project.project_id,
        project.private_root,
        project.store,
    );
    let store = exercise_project.open(create_plans_dir).map_err(|_| {
        if create_plans_dir {
            CliError::PrivateStorageUnavailable
        } else {
            map_error(ExerciseError::NotFound)
        }
    })?;
    Ok((exercise_project, store, project_id))
}

#[cfg(unix)]
fn open(
    common: &ExerciseArgs,
) -> Result<
    (ExercisePlanService<crate::exercise_store::PrivateExerciseStore>, xtrace_domain::ProjectId),
    CliError,
> {
    let (_, store, project_id) = open_project(common, true)?;
    Ok((ExercisePlanService::new(store), project_id))
}

#[cfg(unix)]
fn read_private_json_bytes(path: &std::path::Path, max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let absolute = std::path::absolute(path).map_err(|_| map_error(ExerciseError::InvalidInput))?;
    let parent = absolute.parent().ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
    let name = absolute
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
    let root = xtrace_private_storage::AdmittedPrivateRoot::open(parent)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    root.read_bounded_file(name, max_bytes).map_err(|_| CliError::PrivateStorageUnavailable)
}

#[cfg(unix)]
fn input(path: &std::path::Path) -> Result<CreateExercisePlan, CliError> {
    let bytes = read_private_json_bytes(path, MAX_PLAN_DOCUMENT_BYTES)?;
    // Parse diagnostics can quote values or keys: only the fixed typed error escapes.
    serde_json::from_slice(&bytes).map_err(|_| map_error(ExerciseError::InvalidInput))
}

#[cfg(unix)]
struct PrivateMapCredentialResolver {
    secrets: std::collections::BTreeMap<String, xtrace_exercise::executor::CredentialSecret>,
}

#[cfg(unix)]
impl PrivateMapCredentialResolver {
    fn empty() -> Self {
        Self { secrets: std::collections::BTreeMap::new() }
    }

    fn from_private_file(path: &std::path::Path) -> Result<Self, CliError> {
        let mut bytes = read_private_json_bytes(path, 65_536)?;
        let parsed: Result<std::collections::BTreeMap<String, String>, _> =
            serde_json::from_slice(&bytes);
        bytes.fill(0);
        let raw_map = parsed.map_err(|_| map_error(ExerciseError::InvalidInput))?;
        let mut secrets = std::collections::BTreeMap::new();
        let mut first_err = None;
        for (handle, value) in raw_map {
            match xtrace_exercise::executor::CredentialSecret::new(value) {
                Ok(secret) => {
                    secrets.insert(handle, secret);
                }
                Err(_) => {
                    first_err.get_or_insert_with(|| map_error(ExerciseError::InvalidInput));
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(Self { secrets })
    }
}

#[cfg(unix)]
impl xtrace_exercise::executor::CredentialResolver for PrivateMapCredentialResolver {
    fn resolve(
        &self,
        reference: &str,
    ) -> Result<
        xtrace_exercise::executor::CredentialSecret,
        xtrace_exercise::executor::ExecutionError,
    > {
        self.secrets.get(reference).cloned().ok_or_else(|| {
            xtrace_exercise::executor::ExecutionError::new(
                xtrace_application::exercise::ExerciseFailureClass::CredentialResolutionFailed,
                "credential handle could not be resolved",
            )
        })
    }
}

#[cfg(unix)]
pub(crate) fn trusted_now() -> Result<u64, ExerciseError> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| ExerciseError::Expired)
}

#[cfg(unix)]
fn execution_gate() -> &'static xtrace_exercise::executor::ExecutionGate {
    static GATE: std::sync::OnceLock<xtrace_exercise::executor::ExecutionGate> =
        std::sync::OnceLock::new();
    GATE.get_or_init(xtrace_exercise::executor::ExecutionGate::new)
}

#[cfg(unix)]
fn monotonic_epoch_ms() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[cfg(unix)]
async fn send_loopback_http(
    request: &xtrace_exercise::executor::PreparedWireRequest,
    bounds: xtrace_exercise::executor::ExecutorBounds,
) -> Result<xtrace_exercise::executor::RawHttpResponse, xtrace_exercise::executor::TransportFailure>
{
    use tokio::io::AsyncWriteExt as _;
    use xtrace_exercise::executor::{TransportFailure, is_strict_loopback_ip};

    if !is_strict_loopback_ip(request.target_addr.ip()) || request.target_addr.port() == 0 {
        return Err(TransportFailure::ConnectFailed);
    }
    let total_dur = std::time::Duration::from_secs(u64::from(bounds.total_seconds));
    let req_dur = std::time::Duration::from_secs(u64::from(bounds.timeout_seconds));
    let deadline = tokio::time::Instant::now() + total_dur;
    let connect_deadline = tokio::time::Instant::now() + req_dur.min(total_dur);

    let mut stream = match tokio::time::timeout_at(
        connect_deadline,
        tokio::net::TcpStream::connect(request.target_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err(TransportFailure::ConnectFailed),
        Err(_) => return Err(TransportFailure::PreSendTimeout),
    };

    match stream.peer_addr() {
        Ok(peer) if peer == request.target_addr && is_strict_loopback_ip(peer.ip()) => {}
        _ => return Err(TransportFailure::ConnectFailed),
    }

    let io_res = tokio::time::timeout_at(deadline, async {
        stream
            .write_all(request.wire_bytes())
            .await
            .map_err(|_| TransportFailure::DeliveryUnknown)?;
        stream.flush().await.map_err(|_| TransportFailure::DeliveryUnknown)?;
        read_bounded_http_response(&mut stream, &request.method, bounds).await
    })
    .await;

    match io_res {
        Ok(inner) => inner,
        Err(_) => Err(TransportFailure::PostSendTimeout),
    }
}

#[cfg(unix)]
async fn read_bounded_http_response(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    bounds: xtrace_exercise::executor::ExecutorBounds,
) -> Result<xtrace_exercise::executor::RawHttpResponse, xtrace_exercise::executor::TransportFailure>
{
    use tokio::io::AsyncReadExt as _;
    use xtrace_exercise::executor::{MAX_RESPONSE_HEADER_BYTES, RawHttpResponse, TransportFailure};

    let mut buf = Vec::<u8>::with_capacity(4096);
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        if let Some(pos) = find_crlfcrlf(&buf) {
            if pos > MAX_RESPONSE_HEADER_BYTES {
                return Err(TransportFailure::ResponseTooLarge);
            }
            break pos;
        }
        if buf.len() >= MAX_RESPONSE_HEADER_BYTES {
            return Err(TransportFailure::ResponseTooLarge);
        }
        let n = stream.read(&mut chunk).await.map_err(|_| TransportFailure::DeliveryUnknown)?;
        if n == 0 {
            return Err(TransportFailure::DeliveryUnknown);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE_HEADER_BYTES && find_crlfcrlf(&buf).is_none() {
            return Err(TransportFailure::ResponseTooLarge);
        }
    };

    let header_bytes = &buf[..header_end];
    let body_start = header_end + 4;
    let initial_body = &buf[body_start..];
    let header_text =
        core::str::from_utf8(header_bytes).map_err(|_| TransportFailure::DeliveryUnknown)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportFailure::DeliveryUnknown)?;
    let status_code = parse_status_line(status_line)?;

    // Zero redirects: refuse any 3xx status immediately without following Location.
    if (300..=399).contains(&status_code) && bounds.redirects == 0 {
        return Err(TransportFailure::RedirectRefused(status_code));
    }

    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;
    let mut has_transfer_encoding = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(TransportFailure::DeliveryUnknown);
        };
        let lower = name.trim().to_ascii_lowercase();
        let val = value.trim();
        if lower == "content-length" {
            if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                return Err(TransportFailure::DeliveryUnknown);
            }
            let parsed = val.parse::<u64>().map_err(|_| TransportFailure::DeliveryUnknown)?;
            if let Some(prev) = content_length {
                if prev != parsed {
                    return Err(TransportFailure::DeliveryUnknown);
                }
            }
            content_length = Some(parsed);
        } else if lower == "transfer-encoding" {
            has_transfer_encoding = true;
            if val.to_ascii_lowercase().split(',').any(|t| t.trim() == "chunked") {
                is_chunked = true;
            }
        }
    }
    if has_transfer_encoding && content_length.is_some() {
        return Err(TransportFailure::DeliveryUnknown);
    }

    let max_body = bounds.response_bytes as usize;
    if method == "HEAD" || matches!(status_code, 100..=199 | 204 | 304) {
        return Ok(RawHttpResponse { status_code, body: Vec::new() });
    }

    if is_chunked {
        let body = read_chunked_body(stream, initial_body, max_body).await?;
        return Ok(RawHttpResponse { status_code, body });
    }

    if let Some(expected_len) = content_length {
        if expected_len > u64::from(bounds.response_bytes) {
            return Err(TransportFailure::ResponseTooLarge);
        }
        let target_len = expected_len as usize;
        if initial_body.len() > target_len {
            // Excess trailing bytes on a Connection: close response are clipped only if within bounds;
            // keep exact declared length.
            return Ok(RawHttpResponse { status_code, body: initial_body[..target_len].to_vec() });
        }
        let mut body = Vec::with_capacity(target_len);
        body.extend_from_slice(initial_body);
        while body.len() < target_len {
            let remaining = target_len - body.len();
            let to_read = remaining.min(chunk.len());
            let n = stream
                .read(&mut chunk[..to_read])
                .await
                .map_err(|_| TransportFailure::DeliveryUnknown)?;
            if n == 0 {
                return Err(TransportFailure::DeliveryUnknown);
            }
            body.extend_from_slice(&chunk[..n]);
        }
        return Ok(RawHttpResponse { status_code, body });
    }

    if initial_body.len() > max_body {
        return Err(TransportFailure::ResponseTooLarge);
    }
    let mut body = initial_body.to_vec();
    loop {
        let n = stream.read(&mut chunk).await.map_err(|_| TransportFailure::DeliveryUnknown)?;
        if n == 0 {
            break;
        }
        if body.len().saturating_add(n) > max_body {
            return Err(TransportFailure::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(RawHttpResponse { status_code, body })
}

#[cfg(unix)]
fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(unix)]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(unix)]
fn parse_status_line(line: &str) -> Result<u16, xtrace_exercise::executor::TransportFailure> {
    use xtrace_exercise::executor::TransportFailure;
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .ok_or(TransportFailure::DeliveryUnknown)?;
    if rest.len() < 3 {
        return Err(TransportFailure::DeliveryUnknown);
    }
    let code_str = &rest[..3];
    if !code_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TransportFailure::DeliveryUnknown);
    }
    if rest.len() > 3 && !rest.as_bytes()[3].is_ascii_whitespace() {
        return Err(TransportFailure::DeliveryUnknown);
    }
    let code = code_str.parse::<u16>().map_err(|_| TransportFailure::DeliveryUnknown)?;
    if !(100..=599).contains(&code) {
        return Err(TransportFailure::DeliveryUnknown);
    }
    Ok(code)
}

#[cfg(unix)]
async fn read_more_chunked(
    stream: &mut tokio::net::TcpStream,
    pending: &mut Vec<u8>,
    tmp: &mut [u8; 8192],
) -> Result<(), xtrace_exercise::executor::TransportFailure> {
    use tokio::io::AsyncReadExt as _;
    use xtrace_exercise::executor::TransportFailure;

    let n = stream.read(tmp).await.map_err(|_| TransportFailure::DeliveryUnknown)?;
    if n == 0 {
        return Err(TransportFailure::DeliveryUnknown);
    }
    pending.extend_from_slice(&tmp[..n]);
    Ok(())
}

#[cfg(unix)]
async fn read_chunked_body(
    stream: &mut tokio::net::TcpStream,
    initial: &[u8],
    max_body: usize,
) -> Result<Vec<u8>, xtrace_exercise::executor::TransportFailure> {
    use xtrace_exercise::executor::{MAX_RESPONSE_HEADER_BYTES, TransportFailure};

    let mut pending = initial.to_vec();
    let mut out = Vec::new();
    let mut tmp = [0_u8; 8192];

    loop {
        let line_end = loop {
            if let Some(pos) = find_crlf(&pending) {
                break pos;
            }
            if pending.len() > MAX_RESPONSE_HEADER_BYTES {
                return Err(TransportFailure::ResponseTooLarge);
            }
            read_more_chunked(stream, &mut pending, &mut tmp).await?;
        };
        let line = core::str::from_utf8(&pending[..line_end])
            .map_err(|_| TransportFailure::DeliveryUnknown)?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TransportFailure::DeliveryUnknown);
        }
        let chunk_size =
            usize::from_str_radix(size_hex, 16).map_err(|_| TransportFailure::DeliveryUnknown)?;
        pending.drain(..line_end + 2);

        if chunk_size == 0 {
            let mut trailer_bytes = 0usize;
            loop {
                if let Some(end) = find_crlf(&pending) {
                    if end == 0 {
                        return Ok(out);
                    }
                    trailer_bytes = trailer_bytes.saturating_add(end + 2);
                    if trailer_bytes > MAX_RESPONSE_HEADER_BYTES {
                        return Err(TransportFailure::ResponseTooLarge);
                    }
                    pending.drain(..end + 2);
                } else {
                    if pending.len().saturating_add(trailer_bytes) > MAX_RESPONSE_HEADER_BYTES {
                        return Err(TransportFailure::ResponseTooLarge);
                    }
                    read_more_chunked(stream, &mut pending, &mut tmp).await?;
                }
            }
        }

        if out.len().saturating_add(chunk_size) > max_body {
            return Err(TransportFailure::ResponseTooLarge);
        }

        let needed = chunk_size + 2;
        while pending.len() < needed {
            read_more_chunked(stream, &mut pending, &mut tmp).await?;
        }
        if &pending[chunk_size..needed] != b"\r\n" {
            return Err(TransportFailure::DeliveryUnknown);
        }
        out.extend_from_slice(&pending[..chunk_size]);
        pending.drain(..needed);
    }
}

#[cfg(unix)]
fn write_exercise_json(value: &impl serde::Serialize, json: bool) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    if json {
        crate::output::write_success(&mut out, value)
    } else {
        use std::io::Write as _;
        let pretty = serde_json::to_string_pretty(value)
            .map_err(|_| map_error(ExerciseError::InvalidInput))?;
        writeln!(out, "{pretty}")
    }
    .map_err(|_| CliError::StoreUnavailable("could not write private exercise review".into()))
}

/// Runs `xtrace exercise <command>`.
pub async fn run(command: ExerciseCommand) -> Result<i32, CliError> {
    // Preserve existing explicitly tested no-plan fallbacks without weakening
    // assertions; selected plans take the real project-scoped path below.
    match &command {
        ExerciseCommand::Run(args) if args.plan_hash.is_none() => {
            return Err(CliError::NotImplemented { command: "exercise run" });
        }
        ExerciseCommand::Approve(args) if args.plan_id.is_none() => {
            return Err(CliError::NotImplemented { command: "exercise approve" });
        }
        ExerciseCommand::Show(args) if args.plan_hash.is_none() => {
            return Err(CliError::NotImplemented { command: "exercise show" });
        }
        _ => {}
    }
    #[cfg(unix)]
    {
        let now = || trusted_now().map_err(map_error);
        match command {
            ExerciseCommand::Plan(args) => {
                let request = input(&args.input)?;
                let (service, project) = open(&args.common)?;
                let plan = service.create(project, request, now()?).map_err(map_error)?;
                let document = review_document(&plan, now()?).map_err(map_error)?;
                write_exercise_json(&document, args.common.json)?;
            }
            ExerciseCommand::Edit(args) => {
                let request = input(&args.plan.input)?;
                let (service, project) = open(&args.plan.common)?;
                let plan =
                    service.edit(project, &args.plan_hash, request, now()?).map_err(map_error)?;
                let document = review_document(&plan, now()?).map_err(map_error)?;
                write_exercise_json(&document, args.plan.common.json)?;
            }
            ExerciseCommand::Review(args) => {
                let (service, project) = open(&args.common)?;
                let plan = service.review(project, &args.plan_hash, now()?).map_err(map_error)?;
                let document = review_document(&plan, now()?).map_err(map_error)?;
                write_exercise_json(&document, args.common.json)?;
            }
            ExerciseCommand::Approve(args) => {
                let (service, project) = open(&args.common)?;
                let current = service.show(project, &args.plan_hash).map_err(map_error)?;
                if args.plan_id.as_deref() != Some(current.content.plan_id.as_str()) {
                    return Err(map_error(ExerciseError::HashMismatch));
                }
                let plan = service
                    .approve(
                        project,
                        &args.plan_hash,
                        &args.items,
                        args.confirm_owned_development_target,
                        now()?,
                    )
                    .map_err(map_error)?;
                let document = review_document(&plan, now()?).map_err(map_error)?;
                write_exercise_json(&document, args.common.json)?;
            }
            ExerciseCommand::Show(args) => {
                let hash = args.plan_hash.ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
                let (service, project) = open(&args.common)?;
                let plan = service.show(project, &hash).map_err(map_error)?;
                let document = review_document(&plan, now()?).map_err(map_error)?;
                write_exercise_json(&document, args.common.json)?;
            }
            ExerciseCommand::Run(args) => {
                use xtrace_application::exercise::{
                    ExecutePlanRequest, ExerciseExecutionError, ExerciseExecutionService,
                    ExerciseFailureClass, ExerciseItemStatus, ExerciseProvenancePort as _,
                    ExerciseRunStatus, FinishExerciseRun,
                };
                use xtrace_domain::WallTime;
                use xtrace_exercise::executor::LoopbackLiteralResolver;

                let plan_hash =
                    args.plan_hash.ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
                let plan_id =
                    args.plan_id.ok_or_else(|| map_error(ExerciseError::ApprovalRequired))?;
                let creds = match args.credentials_file.as_deref() {
                    Some(path) => PrivateMapCredentialResolver::from_private_file(path)?,
                    None => PrivateMapCredentialResolver::empty(),
                };
                let (exercise_project, plan_store, project_id) = open_project(&args.common, false)?;
                let prov_store = exercise_project.provenance_store();
                let exec_service = ExerciseExecutionService::new(plan_store, prov_store);

                let started_at = WallTime::now();
                let prepared = exec_service
                    .prepare_execution(
                        &ExecutePlanRequest {
                            project_id,
                            plan_hash,
                            plan_id,
                            confirm_owned_development_target: args.confirm_owned_development_target,
                        },
                        now()?,
                        trusted_now,
                        started_at,
                        &LoopbackLiteralResolver,
                        &creds,
                    )
                    .map_err(map_execution_error)?;

                let permit =
                    match execution_gate().try_acquire(monotonic_epoch_ms(), prepared.bounds) {
                        Ok(permit) => permit,
                        Err(err) => {
                            let _ = exec_service.provenance().finish_run(&FinishExerciseRun {
                                project_id: prepared.project_id,
                                exercise_run_id: prepared.run_id,
                                exercise_item_id: prepared.item_id,
                                run_status: ExerciseRunStatus::Failed,
                                item_status: ExerciseItemStatus::Failed,
                                failure_class: Some(err.failure_class.as_str().to_owned()),
                                http_status: None,
                                request_bytes: u32::try_from(prepared.wire_request.request_bytes())
                                    .ok(),
                                response_bytes: None,
                                duration_ms: Some(0),
                                finished_at: WallTime::now(),
                            });
                            return Err(map_execution_error(ExerciseExecutionError::Failed {
                                run_id: Some(prepared.run_id),
                                failure_class: ExerciseFailureClass::RateLimitExceeded,
                                http_status: None,
                                message: err.message,
                            }));
                        }
                    };

                let start_instant = std::time::Instant::now();
                let transport_res =
                    send_loopback_http(&prepared.wire_request, prepared.bounds).await;
                let duration_ms =
                    u64::try_from(start_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
                drop(permit);

                let receipt = exec_service
                    .finish_execution(prepared, transport_res, WallTime::now(), duration_ms)
                    .map_err(map_execution_error)?;
                write_exercise_json(&receipt, args.common.json)?;
            }
            ExerciseCommand::Provenance(args) => {
                use xtrace_application::exercise::ExerciseProvenanceService;
                use xtrace_domain::{RecordingId, RunId, WallTime};

                let preflight = crate::daemon::preflight_project(
                    &args.common.project_dir,
                    &crate::paths::read_env_path,
                )?;
                let project = crate::daemon::open_validated_project(preflight)?;
                let exercise_project = crate::exercise_store::ExerciseProject::new(
                    project.project_id,
                    project.private_root,
                    project.store,
                );
                let prov = ExerciseProvenanceService::new(exercise_project.provenance_store());

                let runs = if let (Some(run_id_str), Some(item_str), Some(rec_str)) =
                    (&args.run_id, &args.link_item, &args.recording_id)
                {
                    let run_id: RunId =
                        run_id_str.parse().map_err(|_| map_error(ExerciseError::InvalidInput))?;
                    let recording_id: RecordingId =
                        rec_str.parse().map_err(|_| map_error(ExerciseError::InvalidInput))?;
                    prov.link_recording(
                        project.project_id,
                        run_id,
                        item_str,
                        recording_id,
                        WallTime::now(),
                    )
                    .map_err(map_error)?;
                    vec![prov.get_run(project.project_id, run_id).map_err(map_error)?]
                } else if let Some(run_id_str) = &args.run_id {
                    let run_id: RunId =
                        run_id_str.parse().map_err(|_| map_error(ExerciseError::InvalidInput))?;
                    vec![prov.get_run(project.project_id, run_id).map_err(map_error)?]
                } else if let Some(hash) = &args.plan_hash {
                    prov.list_runs_for_plan(project.project_id, hash, args.limit)
                        .map_err(map_error)?
                } else {
                    prov.list_runs_for_project(project.project_id, args.limit).map_err(map_error)?
                };

                let document = serde_json::json!({
                    "kind": "exercise_provenance",
                    "project_id": project.project_id,
                    "plan_hash": args.plan_hash,
                    "runs": runs,
                });
                write_exercise_json(&document, args.common.json)?;
            }
        }
        Ok(0)
    }
    #[cfg(not(unix))]
    Err(CliError::StoreUnavailable("exercise plans require owner-enforced private storage".into()))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "loopback transport unit tests")]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use xtrace_exercise::executor::{
        CredentialResolver, ExecutionBody, ExecutionParam, ExecutionParamLocation,
        ExecutionParamValue, ExecutionRequestSpec, ExecutionStatus, ExecutorBounds,
        LoopbackLiteralResolver, TransportFailure, finalize_response, prepare_request,
    };

    struct FixedCreds;
    impl CredentialResolver for FixedCreds {
        fn resolve(
            &self,
            _reference: &str,
        ) -> Result<
            xtrace_exercise::executor::CredentialSecret,
            xtrace_exercise::executor::ExecutionError,
        > {
            xtrace_exercise::executor::CredentialSecret::new("Bearer loopback-secret-canary")
        }
    }

    fn loopback_spec(port: u16) -> ExecutionRequestSpec {
        ExecutionRequestSpec {
            plan_hash: "a".repeat(64),
            item_id: "018f0000-0000-8000-8000-000000000001".to_owned(),
            method: "POST".to_owned(),
            route_template: "/orders/{id}".to_owned(),
            base_url: format!("http://127.0.0.1:{port}"),
            operator_owned_development: true,
            params: vec![
                ExecutionParam {
                    name: "id".to_owned(),
                    location: ExecutionParamLocation::Path,
                    required: true,
                    value: ExecutionParamValue::Literal("9".to_owned()),
                },
                ExecutionParam {
                    name: "Authorization".to_owned(),
                    location: ExecutionParamLocation::Header,
                    required: true,
                    value: ExecutionParamValue::CredentialReference("local_login".to_owned()),
                },
            ],
            body: ExecutionBody::Bytes {
                content_type: "application/json".to_owned(),
                content: br#"{"qty":1}"#.to_vec(),
            },
        }
    }

    #[tokio::test]
    async fn loopback_transport_sends_item_header_and_handles_chunked_and_redirect_refusal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            // Request 1: 200 chunked
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let n = sock.read(&mut buf).await.unwrap();
            let req_text = String::from_utf8(buf[..n].to_vec()).unwrap();
            assert!(req_text.contains("POST /orders/9 HTTP/1.1\r\n"));
            assert!(
                req_text
                    .contains("X-XTrace-Exercise-Item: 018f0000-0000-8000-8000-000000000001\r\n")
            );
            assert!(req_text.contains("Authorization: Bearer loopback-secret-canary\r\n"));
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
            drop(sock);

            // Request 2: 302 redirect (must never be followed)
            let (mut sock2, _) = listener.accept().await.unwrap();
            let _ = sock2.read(&mut buf).await.unwrap();
            sock2
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/steal\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let bounds = ExecutorBounds::default();
        let wire1 =
            prepare_request(&loopback_spec(port), bounds, &LoopbackLiteralResolver, &FixedCreds)
                .unwrap();
        let res1 = send_loopback_http(&wire1, bounds).await;
        let out1 = finalize_response(&wire1, res1, bounds);
        assert_eq!(out1.status, ExecutionStatus::Succeeded);
        assert_eq!(out1.http_status, Some(200));
        assert_eq!(out1.response_bytes, Some(2));

        let wire2 =
            prepare_request(&loopback_spec(port), bounds, &LoopbackLiteralResolver, &FixedCreds)
                .unwrap();
        let res2 = send_loopback_http(&wire2, bounds).await;
        assert_eq!(res2, Err(TransportFailure::RedirectRefused(302)));
        let out2 = finalize_response(&wire2, res2, bounds);
        assert_eq!(out2.status, ExecutionStatus::Failed);
        assert_eq!(
            out2.failure_class,
            Some(xtrace_application::exercise::ExerciseFailureClass::RedirectRefused)
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn loopback_transport_enforces_response_size_cap() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n").await.unwrap();
        });
        let bounds = ExecutorBounds::default();
        let wire =
            prepare_request(&loopback_spec(port), bounds, &LoopbackLiteralResolver, &FixedCreds)
                .unwrap();
        let res = send_loopback_http(&wire, bounds).await;
        assert_eq!(res, Err(TransportFailure::ResponseTooLarge));
        let out = finalize_response(&wire, res, bounds);
        assert_eq!(out.status, ExecutionStatus::Failed);
        assert_eq!(
            out.failure_class,
            Some(xtrace_application::exercise::ExerciseFailureClass::ResponseSizeExceeded)
        );
        server.await.unwrap();
    }
}
