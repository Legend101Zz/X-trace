//! Pure fail-closed exercise execution boundary.
//!
//! This module validates approved execution inputs, enforces loopback-only
//! connect-time IP revalidation via [`DnsResolver`], resolves opaque
//! credential handles via [`CredentialResolver`], encodes bounded HTTP/1.1
//! wire requests with `X-XTrace-Exercise-Item`, enforces [`ExecutorBounds`]
//! (concurrency 1, 1 rps, 10s timeouts, 131,072-byte request cap, 1,048,576-byte
//! response cap, zero redirects), and validates responses without embedding
//! any runtime socket or networking crate dependency.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::collections::BTreeSet;
use std::sync::Mutex;

use crate::candidate::{HostClass, classify_target_host, validate_target};

/// Authoritative request header linking an executed request to its exercise item UUID.
pub const EXERCISE_ITEM_HEADER: &str = "X-XTrace-Exercise-Item";

/// Default maximum concurrent requests.
pub const DEFAULT_CONCURRENCY: u8 = 1;
/// Default maximum request starts per second.
pub const DEFAULT_REQUESTS_PER_SECOND: u8 = 1;
/// Default per-request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u8 = 10;
/// Default total run timeout in seconds.
pub const DEFAULT_TOTAL_SECONDS: u8 = 10;
/// Default maximum encoded HTTP wire request size in bytes.
pub const DEFAULT_MAX_REQUEST_BYTES: u32 = 131_072;
/// Default maximum accepted HTTP response body size in bytes.
pub const DEFAULT_MAX_RESPONSE_BYTES: u32 = 1_048_576;
/// Default maximum redirect hops (redirects are forbidden).
pub const DEFAULT_MAX_REDIRECTS: u8 = 0;
/// Maximum operator-supplied body size in bytes.
pub const MAX_BODY_BYTES: usize = 65_536;
/// Maximum accepted HTTP response header section size in bytes.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 65_536;

/// Hard execution bounds pinned in the approved plan and enforced at execution time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorBounds {
    /// Maximum concurrent requests (`1`).
    pub concurrency: u8,
    /// Maximum request starts per second (`1`).
    pub requests_per_second: u8,
    /// Maximum seconds per request (`1..=10`).
    pub timeout_seconds: u8,
    /// Maximum seconds for the entire run (`1..=10`).
    pub total_seconds: u8,
    /// Maximum encoded HTTP wire request bytes (`1..=131_072`).
    pub request_bytes: u32,
    /// Maximum accepted HTTP response body bytes (`1..=1_048_576`).
    pub response_bytes: u32,
    /// Redirects are forbidden (`0`).
    pub redirects: u8,
}

impl Default for ExecutorBounds {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            requests_per_second: DEFAULT_REQUESTS_PER_SECOND,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            total_seconds: DEFAULT_TOTAL_SECONDS,
            request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            redirects: DEFAULT_MAX_REDIRECTS,
        }
    }
}

impl ExecutorBounds {
    /// Verifies that bounds stay within strict fail-closed slice ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] if any bound exceeds slice limits or weakens
    /// concurrency, rate, or redirect protection.
    pub fn validate(&self) -> Result<(), ExecutionError> {
        if self.concurrency != DEFAULT_CONCURRENCY
            || self.requests_per_second != DEFAULT_REQUESTS_PER_SECOND
            || self.timeout_seconds == 0
            || self.timeout_seconds > DEFAULT_TIMEOUT_SECONDS
            || self.total_seconds == 0
            || self.total_seconds > DEFAULT_TOTAL_SECONDS
            || self.timeout_seconds > self.total_seconds
            || self.request_bytes == 0
            || self.request_bytes > DEFAULT_MAX_REQUEST_BYTES
            || self.response_bytes == 0
            || self.response_bytes > DEFAULT_MAX_RESPONSE_BYTES
            || self.redirects != DEFAULT_MAX_REDIRECTS
        {
            return Err(ExecutionError::new(
                ExerciseFailureClass::InvalidRequest,
                "execution bounds exceed allowed safety ceilings",
            ));
        }
        Ok(())
    }
}

/// Closed vocabulary of typed exercise execution failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExerciseFailureClass {
    /// Missing explicit review, item approval, or ownership confirmation.
    ApprovalRequired,
    /// Plan expired or clock moved behind creation/transition timestamp.
    PlanExpired,
    /// Plan was superseded by an explicit edit.
    PlanSuperseded,
    /// Plan approval was already consumed.
    AlreadyConsumed,
    /// Plan hash, plan ID, or integrity verification failed.
    HashMismatch,
    /// Required parameter or explicit body decision was unresolved.
    UnresolvedInput,
    /// Target origin failed strict loopback/ownership syntax validation.
    InvalidTarget,
    /// Request parameters, method, headers, or bounds were invalid.
    InvalidRequest,
    /// Connect-time DNS resolution failed or returned no addresses.
    DnsResolutionFailed,
    /// Connect-time address validation rejected a non-loopback or mixed IP set.
    NonLoopbackDestination,
    /// Target returned a `3xx` redirect, which is never followed.
    RedirectRefused,
    /// Opaque credential reference could not be resolved safely.
    CredentialResolutionFailed,
    /// Encoded request exceeded `bounds.request_bytes`.
    RequestSizeExceeded,
    /// Response body or headers exceeded `bounds.response_bytes`.
    ResponseSizeExceeded,
    /// Per-request or total timeout elapsed.
    Timeout,
    /// Execution exceeded concurrency `1` or rate `1 rps`.
    RateLimitExceeded,
    /// Connection failed before any request bytes were written.
    TransportError,
    /// Outcome is unknown after write start (mid-flight error/disconnect/malformed response).
    DeliveryUnknown,
    /// Ephemeral provenance storage failed.
    StorageError,
}

impl ExerciseFailureClass {
    /// Stable lowercase identifier persisted in provenance storage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApprovalRequired => "approval_required",
            Self::PlanExpired => "plan_expired",
            Self::PlanSuperseded => "plan_superseded",
            Self::AlreadyConsumed => "already_consumed",
            Self::HashMismatch => "hash_mismatch",
            Self::UnresolvedInput => "unresolved_input",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidRequest => "invalid_request",
            Self::DnsResolutionFailed => "dns_resolution_failed",
            Self::NonLoopbackDestination => "non_loopback_destination",
            Self::RedirectRefused => "redirect_refused",
            Self::CredentialResolutionFailed => "credential_resolution_failed",
            Self::RequestSizeExceeded => "request_size_exceeded",
            Self::ResponseSizeExceeded => "response_size_exceeded",
            Self::Timeout => "timeout",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::TransportError => "transport_error",
            Self::DeliveryUnknown => "delivery_unknown",
            Self::StorageError => "storage_error",
        }
    }

    /// Parses a persisted failure class identifier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approval_required" => Some(Self::ApprovalRequired),
            "plan_expired" => Some(Self::PlanExpired),
            "plan_superseded" => Some(Self::PlanSuperseded),
            "already_consumed" => Some(Self::AlreadyConsumed),
            "hash_mismatch" => Some(Self::HashMismatch),
            "unresolved_input" => Some(Self::UnresolvedInput),
            "invalid_target" => Some(Self::InvalidTarget),
            "invalid_request" => Some(Self::InvalidRequest),
            "dns_resolution_failed" => Some(Self::DnsResolutionFailed),
            "non_loopback_destination" => Some(Self::NonLoopbackDestination),
            "redirect_refused" => Some(Self::RedirectRefused),
            "credential_resolution_failed" => Some(Self::CredentialResolutionFailed),
            "request_size_exceeded" => Some(Self::RequestSizeExceeded),
            "response_size_exceeded" => Some(Self::ResponseSizeExceeded),
            "timeout" => Some(Self::Timeout),
            "rate_limit_exceeded" => Some(Self::RateLimitExceeded),
            "transport_error" => Some(Self::TransportError),
            "delivery_unknown" => Some(Self::DeliveryUnknown),
            "storage_error" => Some(Self::StorageError),
            _ => None,
        }
    }
}

/// Sanitized execution error. Never interpolates secret values, headers, or URLs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionError {
    /// Typed failure class.
    pub failure_class: ExerciseFailureClass,
    /// Fixed user-safe error summary.
    pub message: &'static str,
}

impl ExecutionError {
    /// Constructs a sanitized execution error.
    #[must_use]
    pub const fn new(failure_class: ExerciseFailureClass, message: &'static str) -> Self {
        Self { failure_class, message }
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for ExecutionError {}

/// Resolved credential value with redacted `Debug` and zero-on-drop memory erasure.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSecret(Vec<u8>);

impl CredentialSecret {
    /// Validates and wraps a resolved credential value.
    ///
    /// Rejects empty values, values above 4,096 bytes, and any ASCII control
    /// characters so resolved credentials cannot inject HTTP headers.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] with [`ExerciseFailureClass::CredentialResolutionFailed`].
    pub fn new(value: impl Into<String>) -> Result<Self, ExecutionError> {
        let mut bytes = value.into().into_bytes();
        if bytes.is_empty() || bytes.len() > 4096 || bytes.iter().any(|b| *b < 0x20 || *b == 0x7f) {
            bytes.fill(0);
            bytes.clear();
            return Err(ExecutionError::new(
                ExerciseFailureClass::CredentialResolutionFailed,
                "resolved credential value is invalid",
            ));
        }
        Ok(Self(bytes))
    }

    fn as_str(&self) -> Result<&str, ExecutionError> {
        core::str::from_utf8(&self.0).map_err(|_| {
            ExecutionError::new(
                ExerciseFailureClass::CredentialResolutionFailed,
                "resolved credential value is not valid UTF-8",
            )
        })
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-secret>")
    }
}

impl Drop for CredentialSecret {
    fn drop(&mut self) {
        self.0.fill(0);
        self.0.clear();
    }
}

/// Injectable credential resolver for opaque `CredentialReference` handles.
pub trait CredentialResolver {
    /// Resolves an opaque handle just in time before request serialization.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] on missing, disallowed, or malformed secrets.
    fn resolve(&self, reference: &str) -> Result<CredentialSecret, ExecutionError>;
}

/// Default credential resolver that refuses all credential references.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllCredentialResolver;

impl CredentialResolver for DenyAllCredentialResolver {
    fn resolve(&self, _reference: &str) -> Result<CredentialSecret, ExecutionError> {
        Err(ExecutionError::new(
            ExerciseFailureClass::CredentialResolutionFailed,
            "no credential resolver is configured for referenced credentials",
        ))
    }
}

/// Injectable connect-time DNS / address resolver.
pub trait DnsResolver {
    /// Resolves `(host, port)` to concrete socket addresses immediately prior to connect.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] when resolution fails.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ExecutionError>;
}

/// Default resolver that admits canonical literal `127.0.0.1` and `::1` addresses only.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackLiteralResolver;

impl DnsResolver for LoopbackLiteralResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ExecutionError> {
        let ip = match host {
            "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::NonLoopbackDestination,
                    "only canonical loopback IP literals are admitted",
                ));
            }
        };
        Ok(vec![SocketAddr::new(ip, port)])
    }
}

/// Validated loopback execution destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionTarget {
    /// Canonical origin (`http://127.0.0.1:<port>` or `http://[::1]:<port>`).
    pub origin: String,
    /// Host header value (`127.0.0.1:<port>` or `[::1]:<port>`).
    pub authority: String,
    /// Connect-time validated loopback socket address.
    pub addr: SocketAddr,
}

/// Returns `true` strictly for `127.0.0.1` or `::1` (rejecting all other ranges and IPv4-mapped IPv6).
#[must_use]
pub const fn is_strict_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.octets()[0] == 127
                && v4.octets()[1] == 0
                && v4.octets()[2] == 0
                && v4.octets()[3] == 1
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0
                && s[1] == 0
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0
                && s[6] == 0
                && s[7] == 1
        }
    }
}

/// Validates target origin syntax, ownership assertion, and connect-time resolved IPs.
///
/// Fails closed on empty, errored, wrong-port, non-loopback, or mixed address sets.
///
/// # Errors
///
/// Returns [`ExecutionError`] when target validation or connect-time IP checks fail.
pub fn resolve_loopback_target(
    base_url: &str,
    operator_owned_development: bool,
    dns: &dyn DnsResolver,
) -> Result<ExecutionTarget, ExecutionError> {
    if !operator_owned_development || base_url.len() > 128 || !base_url.starts_with("http://") {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidTarget,
            "target must be an operator-owned plain HTTP loopback origin",
        ));
    }
    if validate_target(base_url).is_err()
        || !matches!(classify_target_host(base_url), Ok(HostClass::Loopback))
    {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidTarget,
            "target failed canonical loopback origin validation",
        ));
    }
    let authority = base_url.strip_prefix("http://").ok_or_else(|| {
        ExecutionError::new(ExerciseFailureClass::InvalidTarget, "missing http scheme")
    })?;
    if authority.contains('/') {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidTarget,
            "target origin must not include a path",
        ));
    }
    let (host_part, port_str) = authority.rsplit_once(':').ok_or_else(|| {
        ExecutionError::new(
            ExerciseFailureClass::InvalidTarget,
            "target origin requires an explicit port",
        )
    })?;
    let port =
        port_str.parse::<u16>().ok().filter(|p| *p != 0 && p.to_string() == port_str).ok_or_else(
            || {
                ExecutionError::new(
                    ExerciseFailureClass::InvalidTarget,
                    "target origin port is invalid",
                )
            },
        )?;
    let expected_ip = match host_part {
        "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => {
            return Err(ExecutionError::new(
                ExerciseFailureClass::InvalidTarget,
                "target host must be literal 127.0.0.1 or [::1]",
            ));
        }
    };
    let host_for_dns = match host_part {
        "[::1]" => "::1",
        other => other,
    };
    let resolved = dns.resolve(host_for_dns, port).map_err(|err| {
        if err.failure_class == ExerciseFailureClass::NonLoopbackDestination {
            err
        } else {
            ExecutionError::new(
                ExerciseFailureClass::DnsResolutionFailed,
                "connect-time address resolution failed",
            )
        }
    })?;
    if resolved.is_empty() {
        return Err(ExecutionError::new(
            ExerciseFailureClass::DnsResolutionFailed,
            "connect-time address resolution returned no addresses",
        ));
    }
    for addr in &resolved {
        if !is_strict_loopback_ip(addr.ip()) || addr.ip() != expected_ip || addr.port() != port {
            return Err(ExecutionError::new(
                ExerciseFailureClass::NonLoopbackDestination,
                "connect-time address resolution included a disallowed or mismatched address",
            ));
        }
    }
    Ok(ExecutionTarget {
        origin: base_url.to_owned(),
        authority: authority.to_owned(),
        addr: resolved[0],
    })
}

/// Parameter location supported during execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionParamLocation {
    /// Path placeholder interpolated as a single percent-encoded segment.
    Path,
    /// URL query parameter.
    Query,
    /// HTTP request header (excluding transport-control headers).
    Header,
    /// HTTP cookie entry (requires a credential reference).
    Cookie,
}

/// Value source passed to the executor after plan approval/consumption.
#[derive(Clone, PartialEq, Eq)]
pub enum ExecutionParamValue {
    /// Explicit private operator-supplied scalar value.
    Literal(String),
    /// Opaque handle resolved via [`CredentialResolver`].
    CredentialReference(String),
}

impl fmt::Debug for ExecutionParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(_) => f.write_str("Literal(<private>)"),
            Self::CredentialReference(_) => f.write_str("CredentialReference(<private>)"),
        }
    }
}

/// One validated parameter for request construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionParam {
    /// Parameter name.
    pub name: String,
    /// Parameter location.
    pub location: ExecutionParamLocation,
    /// Required flag.
    pub required: bool,
    /// Parameter value or credential handle.
    pub value: ExecutionParamValue,
}

/// Approved request body specification.
#[derive(Clone, PartialEq, Eq)]
pub enum ExecutionBody {
    /// Operator explicitly chose an empty body.
    Empty,
    /// Operator supplied bounded UTF-8 body bytes (`application/json` or `text/plain`).
    Bytes {
        /// Content-Type header value.
        content_type: String,
        /// Raw body bytes.
        content: Vec<u8>,
    },
}

impl fmt::Debug for ExecutionBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Bytes { content_type, content } => {
                write!(f, "Bytes(content_type={content_type:?}, len={})", content.len())
            }
        }
    }
}

/// Complete approved execution request specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRequestSpec {
    /// Lifecycle plan hash (`64` lowercase hex chars).
    pub plan_hash: String,
    /// Lifecycle-rebased UUIDv8 item ID.
    pub item_id: String,
    /// Uppercase HTTP method (`GET`, `POST`, ...).
    pub method: String,
    /// Catalog route template (e.g. `/orders/{id}`).
    pub route_template: String,
    /// Approved loopback target origin.
    pub base_url: String,
    /// Explicit operator ownership assertion.
    pub operator_owned_development: bool,
    /// Explicit parameters.
    pub params: Vec<ExecutionParam>,
    /// Approved request body.
    pub body: ExecutionBody,
}

/// Bounded HTTP/1.1 wire request ready for direct socket transmission.
///
/// Wire bytes are redacted in `Debug` and zeroized on drop so resolved
/// credential values cannot linger in diagnostics or heap memory.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedWireRequest {
    /// Connect-time validated loopback socket address.
    pub target_addr: SocketAddr,
    /// Sanitized loopback origin (`http://127.0.0.1:<port>` or `http://[::1]:<port>`).
    pub target_origin: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// Origin-form request target (`/path?query`).
    pub request_target: String,
    wire_bytes: Vec<u8>,
}

impl PreparedWireRequest {
    /// Returns the exact HTTP/1.1 wire request bytes to transmit directly to `target_addr`.
    #[must_use]
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// Returns the encoded wire request size in bytes.
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        self.wire_bytes.len()
    }
}

impl fmt::Debug for PreparedWireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedWireRequest")
            .field("target_addr", &self.target_addr)
            .field("target_origin", &self.target_origin)
            .field("method", &self.method)
            .field("request_bytes", &self.wire_bytes.len())
            .finish_non_exhaustive()
    }
}

impl Drop for PreparedWireRequest {
    fn drop(&mut self) {
        self.wire_bytes.fill(0);
        self.wire_bytes.clear();
    }
}

/// Raw bounded HTTP response returned by a transport implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawHttpResponse {
    /// Parsed HTTP status code (`100..=599`).
    pub status_code: u16,
    /// Response body bytes read up to `bounds.response_bytes`.
    pub body: Vec<u8>,
}

/// Failure reported by an HTTP transport attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    /// Socket connection failed before any request bytes were sent.
    ConnectFailed,
    /// Timeout elapsed before request transmission began.
    PreSendTimeout,
    /// Response exceeded `bounds.response_bytes` or `MAX_RESPONSE_HEADER_BYTES`.
    ResponseTooLarge,
    /// Server returned a `3xx` redirect response; aborted without following.
    RedirectRefused(u16),
    /// Timeout elapsed after request bytes started leaving the socket.
    PostSendTimeout,
    /// Socket/I/O error or malformed HTTP response after request transmission started.
    DeliveryUnknown,
}

/// Injectable synchronous HTTP transport for unit tests and sync callers.
pub trait HttpTransport {
    /// Sends `request` directly to `request.target_addr` with zero proxies or redirects.
    ///
    /// # Errors
    ///
    /// Returns [`TransportFailure`] categorizing pre-send, size, redirect, or delivery-unknown failures.
    fn send(
        &self,
        request: &PreparedWireRequest,
        bounds: ExecutorBounds,
    ) -> Result<RawHttpResponse, TransportFailure>;
}

/// High-level outcome status of an exercise execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Request transmitted and non-redirect HTTP response received within all caps.
    Succeeded,
    /// Refused pre-send or failed deterministically by policy/bounds (`3xx`, size cap, connect error).
    Failed,
    /// Request transmission started, then failed/timed out/malformed before a valid outcome.
    DeliveryUnknown,
}

/// Sanitized execution outcome metadata (never includes secrets or response bodies).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    /// Terminal execution status.
    pub status: ExecutionStatus,
    /// Typed failure class when `status != Succeeded`.
    pub failure_class: Option<ExerciseFailureClass>,
    /// HTTP status code if a status line was received.
    pub http_status: Option<u16>,
    /// Encoded HTTP wire request size in bytes.
    pub request_bytes: usize,
    /// Response body size in bytes when read cleanly.
    pub response_bytes: Option<usize>,
    /// Sanitized loopback origin.
    pub target_origin: String,
}

/// In-process concurrency (`1`) and start-rate (`1 rps`) limiter.
#[derive(Debug, Default)]
pub struct ExecutionGate {
    state: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    in_flight: bool,
    last_start_ms: Option<u64>,
}

/// RAII permit releasing the single-concurrency execution slot on drop.
pub struct ExecutionPermit<'a> {
    gate: &'a ExecutionGate,
}

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.gate.state.lock() {
            guard.in_flight = false;
        }
    }
}

impl ExecutionGate {
    /// Creates an idle execution gate.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: Mutex::new(GateState { in_flight: false, last_start_ms: None }) }
    }

    /// Acquires the single concurrency slot and checks the `1 rps` minimum start interval.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] with [`ExerciseFailureClass::RateLimitExceeded`] if another
    /// request is active or less than `1000 / bounds.requests_per_second` ms have elapsed.
    pub fn try_acquire(
        &self,
        now_ms: u64,
        bounds: ExecutorBounds,
    ) -> Result<ExecutionPermit<'_>, ExecutionError> {
        bounds.validate()?;
        let mut guard = self.state.lock().map_err(|_| {
            ExecutionError::new(
                ExerciseFailureClass::RateLimitExceeded,
                "execution concurrency lock is unavailable",
            )
        })?;
        if guard.in_flight {
            return Err(ExecutionError::new(
                ExerciseFailureClass::RateLimitExceeded,
                "concurrent exercise execution exceeds concurrency limit of 1",
            ));
        }
        let min_interval_ms = 1_000_u64 / u64::from(bounds.requests_per_second);
        if let Some(last) = guard.last_start_ms {
            if now_ms < last || now_ms.saturating_sub(last) < min_interval_ms {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::RateLimitExceeded,
                    "exercise execution rate exceeds 1 request per second",
                ));
            }
        }
        guard.in_flight = true;
        guard.last_start_ms = Some(now_ms);
        Ok(ExecutionPermit { gate: self })
    }
}

fn is_valid_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_valid_uuid_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, b) in bytes.iter().enumerate() {
        let hyphen = matches!(idx, 8 | 13 | 18 | 23);
        if hyphen {
            if *b != b'-' {
                return false;
            }
        } else if !(b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
            return false;
        }
    }
    true
}

fn is_forbidden_transport_header(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-connection"
            | "trailer"
            | "te"
            | "expect"
            | "content-type"
            | "cookie"
            | "x-xtrace-exercise-item"
            | "x-xtrace-exercise-item-id"
            | "x-xtrace-exercise-plan-hash"
    )
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.!#$%&'*+^`|~".contains(&b))
}

fn has_control_or_crlf(value: &str) -> bool {
    value.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn percent_encode_unreserved(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            use core::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn build_request_target(
    route_template: &str,
    params: &[ExecutionParam],
) -> Result<String, ExecutionError> {
    if route_template.is_empty()
        || route_template.len() > 2048
        || !route_template.starts_with('/')
        || route_template.starts_with("//")
        || route_template.contains(['\\', '?', '#'])
        || route_template.chars().any(char::is_control)
    {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidRequest,
            "route template is malformed",
        ));
    }
    let mut path_values = std::collections::BTreeMap::<&str, &str>::new();
    let mut query_pairs = Vec::<(&str, &str)>::new();
    for param in params {
        match param.location {
            ExecutionParamLocation::Path => {
                if !param.required {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::UnresolvedInput,
                        "path parameters must be explicitly required",
                    ));
                }
                let ExecutionParamValue::Literal(val) = &param.value else {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "path parameters cannot use credential references",
                    ));
                };
                if val.is_empty()
                    || val == "."
                    || val == ".."
                    || val.len() > 4096
                    || val.chars().any(char::is_control)
                {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "path parameter value is invalid",
                    ));
                }
                if path_values.insert(param.name.as_str(), val.as_str()).is_some() {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "duplicate path parameter",
                    ));
                }
            }
            ExecutionParamLocation::Query => {
                if param.name.is_empty()
                    || param.name.len() > 128
                    || has_control_or_crlf(&param.name)
                {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "query parameter name is invalid",
                    ));
                }
                let ExecutionParamValue::Literal(val) = &param.value else {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "query parameters cannot use credential references",
                    ));
                };
                if val.len() > 4096 || val.chars().any(char::is_control) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "query parameter value is invalid",
                    ));
                }
                query_pairs.push((param.name.as_str(), val.as_str()));
            }
            ExecutionParamLocation::Header | ExecutionParamLocation::Cookie => {}
        }
    }
    let mut seen_placeholders = BTreeSet::new();
    let mut segments = Vec::new();
    for segment in route_template.split('/').skip(1) {
        if segment.contains(['{', '}']) {
            let name =
                segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')).ok_or_else(|| {
                    ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "route placeholder syntax is invalid",
                    )
                })?;
            if name.is_empty() || !seen_placeholders.insert(name) {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::InvalidRequest,
                    "duplicate or empty route placeholder",
                ));
            }
            let value = path_values.get(name).ok_or_else(|| {
                ExecutionError::new(
                    ExerciseFailureClass::UnresolvedInput,
                    "missing value for required route placeholder",
                )
            })?;
            segments.push(percent_encode_unreserved(value));
        } else {
            if segment == "." || segment == ".." {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::InvalidRequest,
                    "route template cannot contain dot segments",
                ));
            }
            segments.push(segment.to_owned());
        }
    }
    if seen_placeholders.len() != path_values.len() {
        return Err(ExecutionError::new(
            ExerciseFailureClass::UnresolvedInput,
            "path inputs do not match route placeholders",
        ));
    }
    let mut target =
        if segments.is_empty() { "/".to_owned() } else { format!("/{}", segments.join("/")) };
    if !query_pairs.is_empty() {
        target.push('?');
        for (idx, (k, v)) in query_pairs.into_iter().enumerate() {
            if idx > 0 {
                target.push('&');
            }
            target.push_str(&percent_encode_unreserved(k));
            target.push('=');
            target.push_str(&percent_encode_unreserved(v));
        }
    }
    Ok(target)
}

/// Validates target, connect-time resolved IPs, bounds, inputs, credentials,
/// and encodes the bounded HTTP/1.1 wire request.
///
/// DNS/IP validation runs **before** credential resolution so a disallowed
/// destination never triggers credential resolution.
///
/// # Errors
///
/// Returns [`ExecutionError`] if any validation, DNS, credential, or size check fails.
pub fn prepare_request(
    spec: &ExecutionRequestSpec,
    bounds: ExecutorBounds,
    dns: &dyn DnsResolver,
    creds: &dyn CredentialResolver,
) -> Result<PreparedWireRequest, ExecutionError> {
    bounds.validate()?;
    if !is_valid_hex_64(&spec.plan_hash) || !is_valid_uuid_text(&spec.item_id) {
        return Err(ExecutionError::new(
            ExerciseFailureClass::HashMismatch,
            "exercise plan hash or item ID is invalid",
        ));
    }
    if spec.method.is_empty()
        || spec.method.len() > 16
        || !spec.method.bytes().all(|b| b.is_ascii_uppercase())
    {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidRequest,
            "HTTP method is invalid",
        ));
    }
    if spec.params.len() > 64 {
        return Err(ExecutionError::new(
            ExerciseFailureClass::InvalidRequest,
            "parameter count exceeds limit",
        ));
    }

    // Step 1: validate origin & connect-time resolved IPs BEFORE resolving any credentials.
    let target = resolve_loopback_target(&spec.base_url, spec.operator_owned_development, dns)?;
    let request_target = build_request_target(&spec.route_template, &spec.params)?;

    // Step 2: validate headers/cookies & resolve credential handles just in time.
    let mut seen_keys = BTreeSet::new();
    let mut header_lines = Vec::<(String, CredentialSecret)>::new();
    let mut cookie_pairs = Vec::<(String, CredentialSecret)>::new();
    for param in &spec.params {
        match param.location {
            ExecutionParamLocation::Path | ExecutionParamLocation::Query => {
                let loc = match param.location {
                    ExecutionParamLocation::Path => "path",
                    ExecutionParamLocation::Query => "query",
                    _ => unreachable!(),
                };
                if !seen_keys.insert((loc, param.name.to_ascii_lowercase())) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "duplicate parameter name",
                    ));
                }
            }
            ExecutionParamLocation::Header => {
                if !is_http_token(&param.name) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "header name is invalid",
                    ));
                }
                let lower = param.name.to_ascii_lowercase();
                if is_forbidden_transport_header(&lower) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "transport-control headers are forbidden",
                    ));
                }
                if !seen_keys.insert(("header", lower)) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "duplicate header name",
                    ));
                }
                let secret = match &param.value {
                    ExecutionParamValue::Literal(v) => {
                        if v.len() > 4096 || has_control_or_crlf(v) {
                            return Err(ExecutionError::new(
                                ExerciseFailureClass::InvalidRequest,
                                "header value contains invalid characters or exceeds length",
                            ));
                        }
                        CredentialSecret::new(v.clone()).map_err(|_| {
                            ExecutionError::new(
                                ExerciseFailureClass::InvalidRequest,
                                "header value is empty or invalid",
                            )
                        })?
                    }
                    ExecutionParamValue::CredentialReference(reference) => {
                        creds.resolve(reference)?
                    }
                };
                header_lines.push((param.name.clone(), secret));
            }
            ExecutionParamLocation::Cookie => {
                if !is_http_token(&param.name) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "cookie name is invalid",
                    ));
                }
                if !seen_keys.insert(("cookie", param.name.to_ascii_lowercase())) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::InvalidRequest,
                        "duplicate cookie name",
                    ));
                }
                let ExecutionParamValue::CredentialReference(reference) = &param.value else {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::CredentialResolutionFailed,
                        "cookies require opaque credential references",
                    ));
                };
                let secret = creds.resolve(reference)?;
                let secret_str = secret.as_str()?;
                if secret_str.contains([';', ',']) {
                    return Err(ExecutionError::new(
                        ExerciseFailureClass::CredentialResolutionFailed,
                        "resolved cookie value contains forbidden delimiters",
                    ));
                }
                cookie_pairs.push((param.name.clone(), secret));
            }
        }
    }

    // Step 3: validate body and serialize HTTP/1.1 wire bytes.
    let (body_content_type, body_bytes): (Option<&str>, &[u8]) = match &spec.body {
        ExecutionBody::Empty => (None, &[]),
        ExecutionBody::Bytes { content_type, content } => {
            if !matches!(content_type.as_str(), "application/json" | "text/plain")
                || content.len() > MAX_BODY_BYTES
            {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::RequestSizeExceeded,
                    "request body type or size exceeds execution bounds",
                ));
            }
            (Some(content_type.as_str()), content.as_slice())
        }
    };

    let mut wire = Vec::<u8>::with_capacity(512 + body_bytes.len());
    wire.extend_from_slice(spec.method.as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(request_target.as_bytes());
    wire.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    wire.extend_from_slice(target.authority.as_bytes());
    wire.extend_from_slice(b"\r\nConnection: close\r\nUser-Agent: xtrace-exercise/1\r\n");
    wire.extend_from_slice(EXERCISE_ITEM_HEADER.as_bytes());
    wire.extend_from_slice(b": ");
    wire.extend_from_slice(spec.item_id.as_bytes());
    wire.extend_from_slice(b"\r\n");

    for (name, val) in &header_lines {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(val.as_str()?.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !cookie_pairs.is_empty() {
        wire.extend_from_slice(b"Cookie: ");
        for (idx, (name, val)) in cookie_pairs.iter().enumerate() {
            if idx > 0 {
                wire.extend_from_slice(b"; ");
            }
            wire.extend_from_slice(name.as_bytes());
            wire.push(b'=');
            wire.extend_from_slice(val.as_str()?.as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
    }
    if let Some(ct) = body_content_type {
        wire.extend_from_slice(b"Content-Type: ");
        wire.extend_from_slice(ct.as_bytes());
        wire.extend_from_slice(b"\r\nContent-Length: ");
        wire.extend_from_slice(body_bytes.len().to_string().as_bytes());
        wire.extend_from_slice(b"\r\n");
    } else if matches!(spec.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        wire.extend_from_slice(b"Content-Length: 0\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(body_bytes);

    if wire.len() > bounds.request_bytes as usize {
        wire.fill(0);
        return Err(ExecutionError::new(
            ExerciseFailureClass::RequestSizeExceeded,
            "encoded HTTP request exceeds maximum request byte ceiling",
        ));
    }

    Ok(PreparedWireRequest {
        target_addr: target.addr,
        target_origin: target.origin,
        method: spec.method.clone(),
        request_target,
        wire_bytes: wire,
    })
}

/// Validates a raw transport response against redirect and response-size caps.
#[must_use]
pub fn finalize_response(
    prepared: &PreparedWireRequest,
    result: Result<RawHttpResponse, TransportFailure>,
    bounds: ExecutorBounds,
) -> ExecutionOutcome {
    let request_bytes = prepared.request_bytes();
    let target_origin = prepared.target_origin.clone();
    match result {
        Ok(resp) => {
            if !(100..=599).contains(&resp.status_code) {
                return ExecutionOutcome {
                    status: ExecutionStatus::DeliveryUnknown,
                    failure_class: Some(ExerciseFailureClass::DeliveryUnknown),
                    http_status: None,
                    request_bytes,
                    response_bytes: None,
                    target_origin,
                };
            }
            if (300..=399).contains(&resp.status_code) && bounds.redirects == 0 {
                return ExecutionOutcome {
                    status: ExecutionStatus::Failed,
                    failure_class: Some(ExerciseFailureClass::RedirectRefused),
                    http_status: Some(resp.status_code),
                    request_bytes,
                    response_bytes: None,
                    target_origin,
                };
            }
            if resp.body.len() > bounds.response_bytes as usize {
                return ExecutionOutcome {
                    status: ExecutionStatus::Failed,
                    failure_class: Some(ExerciseFailureClass::ResponseSizeExceeded),
                    http_status: Some(resp.status_code),
                    request_bytes,
                    response_bytes: None,
                    target_origin,
                };
            }
            ExecutionOutcome {
                status: ExecutionStatus::Succeeded,
                failure_class: None,
                http_status: Some(resp.status_code),
                request_bytes,
                response_bytes: Some(resp.body.len()),
                target_origin,
            }
        }
        Err(TransportFailure::ConnectFailed) => ExecutionOutcome {
            status: ExecutionStatus::Failed,
            failure_class: Some(ExerciseFailureClass::TransportError),
            http_status: None,
            request_bytes,
            response_bytes: None,
            target_origin,
        },
        Err(TransportFailure::PreSendTimeout) => ExecutionOutcome {
            status: ExecutionStatus::Failed,
            failure_class: Some(ExerciseFailureClass::Timeout),
            http_status: None,
            request_bytes,
            response_bytes: None,
            target_origin,
        },
        Err(TransportFailure::ResponseTooLarge) => ExecutionOutcome {
            status: ExecutionStatus::Failed,
            failure_class: Some(ExerciseFailureClass::ResponseSizeExceeded),
            http_status: None,
            request_bytes,
            response_bytes: None,
            target_origin,
        },
        Err(TransportFailure::RedirectRefused(status)) => ExecutionOutcome {
            status: ExecutionStatus::Failed,
            failure_class: Some(ExerciseFailureClass::RedirectRefused),
            http_status: (100..=599).contains(&status).then_some(status),
            request_bytes,
            response_bytes: None,
            target_origin,
        },
        Err(TransportFailure::PostSendTimeout) => ExecutionOutcome {
            status: ExecutionStatus::DeliveryUnknown,
            failure_class: Some(ExerciseFailureClass::Timeout),
            http_status: None,
            request_bytes,
            response_bytes: None,
            target_origin,
        },
        Err(TransportFailure::DeliveryUnknown) => ExecutionOutcome {
            status: ExecutionStatus::DeliveryUnknown,
            failure_class: Some(ExerciseFailureClass::DeliveryUnknown),
            http_status: None,
            request_bytes,
            response_bytes: None,
            target_origin,
        },
    }
}

/// Runs prepare, concurrency/rate gate acquisition, transport send, and response validation.
pub fn execute_with_transport(
    spec: &ExecutionRequestSpec,
    bounds: ExecutorBounds,
    gate: &ExecutionGate,
    now_ms: u64,
    dns: &dyn DnsResolver,
    creds: &dyn CredentialResolver,
    transport: &dyn HttpTransport,
) -> Result<ExecutionOutcome, ExecutionError> {
    let prepared = prepare_request(spec, bounds, dns, creds)?;
    let _permit = gate.try_acquire(now_ms, bounds)?;
    let raw = transport.send(&prepared, bounds);
    Ok(finalize_response(&prepared, raw, bounds))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "executor unit tests use fixed fixtures"
)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use std::cell::Cell;
    use std::collections::BTreeMap;

    struct MockDns(Result<Vec<SocketAddr>, ExecutionError>);
    impl DnsResolver for MockDns {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ExecutionError> {
            self.0.clone()
        }
    }

    struct MockCreds {
        secrets: BTreeMap<String, String>,
        calls: Cell<usize>,
    }
    impl CredentialResolver for MockCreds {
        fn resolve(&self, reference: &str) -> Result<CredentialSecret, ExecutionError> {
            self.calls.set(self.calls.get() + 1);
            let value = self.secrets.get(reference).ok_or_else(|| {
                ExecutionError::new(
                    ExerciseFailureClass::CredentialResolutionFailed,
                    "credential handle not found",
                )
            })?;
            CredentialSecret::new(value.clone())
        }
    }

    struct MockTransport {
        result: Result<RawHttpResponse, TransportFailure>,
        calls: Cell<usize>,
    }
    impl HttpTransport for MockTransport {
        fn send(
            &self,
            _request: &PreparedWireRequest,
            _bounds: ExecutorBounds,
        ) -> Result<RawHttpResponse, TransportFailure> {
            self.calls.set(self.calls.get() + 1);
            self.result.clone()
        }
    }

    fn base_spec() -> ExecutionRequestSpec {
        ExecutionRequestSpec {
            plan_hash: "a".repeat(64),
            item_id: "018f0000-0000-8000-8000-000000000001".to_owned(),
            method: "POST".to_owned(),
            route_template: "/orders/{id}".to_owned(),
            base_url: "http://127.0.0.1:8080".to_owned(),
            operator_owned_development: true,
            params: vec![
                ExecutionParam {
                    name: "id".to_owned(),
                    location: ExecutionParamLocation::Path,
                    required: true,
                    value: ExecutionParamValue::Literal("42".to_owned()),
                },
                ExecutionParam {
                    name: "Authorization".to_owned(),
                    location: ExecutionParamLocation::Header,
                    required: true,
                    value: ExecutionParamValue::CredentialReference("local_auth".to_owned()),
                },
            ],
            body: ExecutionBody::Bytes {
                content_type: "application/json".to_owned(),
                content: br#"{"qty":1}"#.to_vec(),
            },
        }
    }

    #[test]
    fn connect_time_ip_revalidation_rejects_non_loopback_mixed_empty_and_ipv4_mapped() {
        let spec = base_spec();
        let creds = MockCreds {
            secrets: [("local_auth".to_owned(), "Bearer top-secret-canary".to_owned())].into(),
            calls: Cell::new(0),
        };
        let transport = MockTransport {
            result: Ok(RawHttpResponse { status_code: 200, body: b"{}".to_vec() }),
            calls: Cell::new(0),
        };
        let bad_cases = [
            (vec![], ExerciseFailureClass::DnsResolutionFailed),
            (
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 8080)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8080)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)),
                    8080,
                )],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 8080),
                ],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
            (
                vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)],
                ExerciseFailureClass::NonLoopbackDestination,
            ),
        ];
        for (addrs, expected) in bad_cases {
            let dns = MockDns(Ok(addrs));
            let err = execute_with_transport(
                &spec,
                ExecutorBounds::default(),
                &ExecutionGate::new(),
                1000,
                &dns,
                &creds,
                &transport,
            )
            .unwrap_err();
            assert_eq!(err.failure_class, expected);
        }
        assert_eq!(creds.calls.get(), 0, "DNS refusal must happen before credential resolution");
        assert_eq!(transport.calls.get(), 0, "DNS refusal must happen before transport");
    }

    #[test]
    fn literal_v4_and_v6_loopback_prepare_header_and_do_not_leak_secrets() {
        let mut creds_map = BTreeMap::new();
        creds_map.insert("local_auth".to_owned(), "Bearer top-secret-canary".to_owned());
        let creds = MockCreds { secrets: creds_map, calls: Cell::new(0) };

        for (base_url, addr) in [
            ("http://127.0.0.1:8080", SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)),
            ("http://[::1]:8080", SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)),
        ] {
            let mut spec = base_spec();
            spec.base_url = base_url.to_owned();
            let dns = LoopbackLiteralResolver;
            let prepared = prepare_request(&spec, ExecutorBounds::default(), &dns, &creds).unwrap();
            assert_eq!(prepared.target_addr, addr);
            assert!(!format!("{prepared:?}").contains("top-secret-canary"));
            let wire = core::str::from_utf8(prepared.wire_bytes()).unwrap();
            assert!(wire.contains("POST /orders/42 HTTP/1.1\r\n"));
            assert!(
                wire.contains("X-XTrace-Exercise-Item: 018f0000-0000-8000-8000-000000000001\r\n")
            );
            assert!(wire.contains("Authorization: Bearer top-secret-canary\r\n"));
            assert!(wire.contains("Connection: close\r\n"));
        }
        let secret = CredentialSecret::new("my-secret-value").unwrap();
        assert!(!format!("{secret:?}").contains("my-secret-value"));
    }

    #[test]
    fn redirect_refusal_and_request_response_size_caps_are_enforced() {
        let spec = base_spec();
        let creds = MockCreds {
            secrets: [("local_auth".to_owned(), "Bearer ok".to_owned())].into(),
            calls: Cell::new(0),
        };
        let dns = LoopbackLiteralResolver;
        let gate = ExecutionGate::new();

        for code in [301, 302, 303, 307, 308] {
            let transport = MockTransport {
                result: Ok(RawHttpResponse { status_code: code, body: vec![] }),
                calls: Cell::new(0),
            };
            let outcome = execute_with_transport(
                &spec,
                ExecutorBounds::default(),
                &gate,
                1000,
                &dns,
                &creds,
                &transport,
            )
            .unwrap();
            assert_eq!(outcome.status, ExecutionStatus::Failed);
            assert_eq!(outcome.failure_class, Some(ExerciseFailureClass::RedirectRefused));
            assert_eq!(outcome.http_status, Some(code));
        }

        // Response exceeding 1,048,576 bytes must fail closed.
        let oversized_resp = MockTransport {
            result: Ok(RawHttpResponse {
                status_code: 200,
                body: vec![b'a'; DEFAULT_MAX_RESPONSE_BYTES as usize + 1],
            }),
            calls: Cell::new(0),
        };
        let outcome = execute_with_transport(
            &spec,
            ExecutorBounds::default(),
            &ExecutionGate::new(),
            2000,
            &dns,
            &creds,
            &oversized_resp,
        )
        .unwrap();
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert_eq!(outcome.failure_class, Some(ExerciseFailureClass::ResponseSizeExceeded));

        // Request exceeding 131,072 bytes via large header accumulation must fail closed.
        let mut large_spec = base_spec();
        for idx in 0..33 {
            large_spec.params.push(ExecutionParam {
                name: format!("X-Pad-{idx}"),
                location: ExecutionParamLocation::Header,
                required: false,
                value: ExecutionParamValue::Literal("x".repeat(4096)),
            });
        }
        let err =
            prepare_request(&large_spec, ExecutorBounds::default(), &dns, &creds).unwrap_err();
        assert_eq!(err.failure_class, ExerciseFailureClass::RequestSizeExceeded);
    }

    #[test]
    fn concurrency_and_rate_limits_and_header_spoofing_are_enforced() {
        let gate = ExecutionGate::new();
        let bounds = ExecutorBounds::default();
        let permit = gate.try_acquire(10_000, bounds).unwrap();
        assert_eq!(
            gate.try_acquire(10_500, bounds).err().map(|e| e.failure_class),
            Some(ExerciseFailureClass::RateLimitExceeded)
        );
        drop(permit);
        assert_eq!(
            gate.try_acquire(10_999, bounds).err().map(|e| e.failure_class),
            Some(ExerciseFailureClass::RateLimitExceeded)
        );
        assert!(gate.try_acquire(11_000, bounds).is_ok());

        let mut spoofed = base_spec();
        spoofed.params.push(ExecutionParam {
            name: "X-XTrace-Exercise-Item".to_owned(),
            location: ExecutionParamLocation::Header,
            required: false,
            value: ExecutionParamValue::Literal("018f0000-0000-8000-8000-000000000099".to_owned()),
        });
        let creds = MockCreds {
            secrets: [("local_auth".to_owned(), "Bearer ok".to_owned())].into(),
            calls: Cell::new(0),
        };
        let err =
            prepare_request(&spoofed, ExecutorBounds::default(), &LoopbackLiteralResolver, &creds)
                .unwrap_err();
        assert_eq!(err.failure_class, ExerciseFailureClass::InvalidRequest);
    }
}
