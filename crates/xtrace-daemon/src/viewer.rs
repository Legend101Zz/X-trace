//! Experimental foreground loopback viewer adapter.
//!
//! This listener is deliberately separate from XTP's TLS listener. It exposes
//! only a fixed asset manifest and the bounded recording and observed-query
//! application services; it has no storage or repository dependency.

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware::Next};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use xtrace_application::{
    ListObservedEndpoints, ListOperationRecordings, ListUnmatchedRecordings,
    MAX_OBSERVED_ENDPOINT_LIMIT, MAX_OBSERVED_RECORDING_LIMIT, MAX_RECORDING_LIST_LIMIT,
    ObservedEndpointQueryService, ObservedEndpointReadPort, RecordingDetail, RecordingListPage,
    RecordingQueryService, RecordingReadPort, ShowRecording,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CorrelationId, OperationId, ProjectId, RecordingId};

const MAX_CONNECTIONS: usize = 32;
const MAX_HTTP_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_AUTH_BODY_BYTES: usize = 1_024;
const MAX_QUERY_CONCURRENCY: usize = 2;
const MAX_OBSERVED_QUERY_BYTES: usize = 2_080;
const MAX_OBSERVED_CURSOR_BYTES: usize = 2_048;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_TTL_SECONDS: u64 = 15 * 60;
const BOOTSTRAP_TTL: Duration = Duration::from_secs(60);
const SESSION_COOKIE: &str = "xtrace_viewer_session";

/// Readiness document printed by the CLI for an explicitly started viewer.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewerReadiness {
    /// Readiness document kind.
    pub kind: &'static str,
    /// Viewer HTTP origin (without credentials).
    pub origin: String,
    /// One-time bootstrap URL. Its fragment is not sent in HTTP requests.
    pub url: String,
    /// Selected project identity.
    pub project_id: ProjectId,
    /// Honest lifecycle description for this foreground mode.
    pub lifecycle: &'static str,
}

/// Errors that can occur while binding or serving the local viewer.
#[derive(Debug, thiserror::Error)]
pub enum ViewerError {
    /// Listener creation or serving failed.
    #[error("viewer listener failed")]
    Listener(#[source] std::io::Error),
    /// The operating system CSPRNG did not provide token bytes.
    #[error("viewer token generation failed")]
    Random(#[source] ring::error::Unspecified),
}

struct BootstrapState {
    digest: [u8; 32],
    expires_at: Instant,
    token: String,
}

struct ViewerState<P> {
    recording_service: RecordingQueryService<P>,
    observed_service: ObservedEndpointQueryService<P>,
    query_lane: QueryLane,
    project_id: ProjectId,
    origin: String,
    host: String,
    bootstrap: tokio::sync::Mutex<Option<BootstrapState>>,
    sessions: tokio::sync::Mutex<HashMap<[u8; 32], Instant>>,
}

#[derive(Clone)]
struct QueryLane(Arc<QueryLaneState>);

struct QueryLaneState {
    permits: Arc<Semaphore>,
    active: AtomicUsize,
    drained: Notify,
}

struct QueryCompletion {
    state: Arc<QueryLaneState>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryLaneError {
    Busy,
    Closed,
    Join,
}

impl QueryLane {
    fn new(limit: usize) -> Self {
        Self(Arc::new(QueryLaneState {
            permits: Arc::new(Semaphore::new(limit)),
            active: AtomicUsize::new(0),
            drained: Notify::new(),
        }))
    }

    async fn run<T, F>(&self, query: F) -> Result<T, QueryLaneError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self.0.permits.clone().try_acquire_owned().map_err(|error| match error {
            tokio::sync::TryAcquireError::Closed => QueryLaneError::Closed,
            tokio::sync::TryAcquireError::NoPermits => QueryLaneError::Busy,
        })?;
        self.0.active.fetch_add(1, Ordering::AcqRel);
        let completion = QueryCompletion { state: self.0.clone(), _permit: permit };
        tokio::task::spawn_blocking(move || {
            let _completion = completion;
            query()
        })
        .await
        .map_err(|_| QueryLaneError::Join)
    }

    fn close(&self) {
        self.0.permits.close();
    }

    async fn wait_drained(&self) {
        loop {
            let notified = self.0.drained.notified();
            if self.0.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for QueryCompletion {
    fn drop(&mut self) {
        if self.state.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.state.drained.notify_one();
        }
    }
}

/// Bound viewer listener and the URL needed to authenticate its first browser.
pub struct BoundViewer<P> {
    listener: TcpListener,
    state: Arc<ViewerState<P>>,
}

impl<P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static> BoundViewer<P> {
    /// Binds an experimental viewer to an OS-assigned IPv4 loopback port.
    ///
    /// # Errors
    ///
    /// Returns an error if the loopback socket or CSPRNG cannot be used.
    pub async fn bind(
        recording_service: RecordingQueryService<P>,
        observed_service: ObservedEndpointQueryService<P>,
        project_id: ProjectId,
    ) -> Result<Self, ViewerError> {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.map_err(ViewerError::Listener)?;
        let address = listener.local_addr().map_err(ViewerError::Listener)?;
        let host = address.to_string();
        let origin = format!("http://{host}");
        let token_bytes = random_bytes()?;
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let digest = *blake3::hash(&token_bytes).as_bytes();
        let state = Arc::new(ViewerState {
            recording_service,
            observed_service,
            query_lane: QueryLane::new(MAX_QUERY_CONCURRENCY),
            project_id,
            origin,
            host,
            bootstrap: tokio::sync::Mutex::new(Some(BootstrapState {
                digest,
                expires_at: Instant::now() + BOOTSTRAP_TTL,
                token,
            })),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        });
        Ok(Self { listener, state })
    }

    /// Returns the structured, credential-bearing initial browser URL.
    #[must_use]
    pub fn readiness(&self) -> ViewerReadiness {
        let state = &self.state;
        let token = state
            .bootstrap
            .try_lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|item| item.token.clone()))
            .unwrap_or_default();
        ViewerReadiness {
            kind: "viewer_ready",
            origin: state.origin.clone(),
            url: format!("{}/#token={token}", state.origin),
            project_id: state.project_id,
            lifecycle: "foreground_experimental",
        }
    }

    /// Runs the viewer until the supplied shutdown future resolves.
    ///
    /// The HTTP adapter is bounded to 32 connections, 8 KiB of headers, 1 KiB
    /// of auth body, a 15-second request lifetime, and two synchronous query
    /// calls on blocking workers. Saturated queries receive a safe 503. On
    /// shutdown, new queries are rejected and in-flight queries drain for at
    /// most the two-second connection shutdown window. The browser uses plain
    /// HTTP only on IPv4 loopback, so the cookie is HttpOnly and SameSite=Strict
    /// but cannot carry Secure; Host and Origin validation remains mandatory.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting or serving an HTTP connection fails.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), ViewerError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let app = router(self.state.clone());
        let service =
            ServiceBuilder::new().layer(ConcurrencyLimitLayer::new(MAX_CONNECTIONS)).service(app);
        let shutdown = Box::pin(shutdown);
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted.map_err(ViewerError::Listener)?;
                    if !peer.ip().is_loopback() {
                        drop(stream);
                        continue;
                    }
                    if connections.len() >= MAX_CONNECTIONS {
                        drop(stream);
                        continue;
                    }
                    let service = service.clone();
                    connections.spawn(async move {
                        let _ = serve_connection(stream, service).await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        drop(service);
        let end = Instant::now() + Duration::from_secs(2);
        self.state.query_lane.close();
        while !connections.is_empty() && Instant::now() < end {
            if timeout(Duration::from_millis(100), connections.join_next()).await.is_err() {
                continue;
            }
        }
        let _ = timeout(
            end.saturating_duration_since(Instant::now()),
            self.state.query_lane.wait_drained(),
        )
        .await;
        connections.abort_all();
        self.state.sessions.lock().await.clear();
        Ok(())
    }
}

async fn serve_connection<S>(stream: TcpStream, service: S) -> Result<(), hyper::Error>
where
    S: tower::Service<
            Request<hyper::body::Incoming>,
            Response = Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    serve_connection_with_timeout(stream, service, REQUEST_TIMEOUT).await
}

async fn serve_connection_with_timeout<S>(
    stream: TcpStream,
    service: S,
    request_timeout: Duration,
) -> Result<(), hyper::Error>
where
    S: tower::Service<
            Request<hyper::body::Incoming>,
            Response = Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let mut builder = http1::Builder::new();
    builder.max_headers(MAX_HTTP_HEADERS).max_buf_size(MAX_HEADER_BYTES);
    let connection =
        builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
    match timeout(request_timeout, connection).await {
        Ok(Ok(())) | Err(_) => {}
        Ok(Err(error)) => {
            let _ = error;
        }
    }
    Ok(())
}

fn router<P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static>(
    state: Arc<ViewerState<P>>,
) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/index.css", get(app_css))
        .route("/assets/fonts/chivo-latin-400-normal.woff2", get(chivo_font))
        .route("/assets/fonts/chivo-latin-600-normal.woff2", get(chivo_bold_font))
        .route("/assets/fonts/azeret-mono-latin-400-normal.woff2", get(mono_font))
        .route("/api/v1/auth/exchange", post(exchange))
        .route("/api/v1/recordings", get(list_recordings))
        .route("/api/v1/recordings/:recording_id", get(show_recording))
        .route(
            "/api/v1/recordings/:recording_id/frames/:frame_id/navigation",
            get(frame_navigation_route),
        )
        .route("/api/v1/recordings/:recording_id/navigate", get(navigate_route))
        .route("/api/v1/recordings/:recording_id/frames", get(replay_not_implemented_frames))
        .route("/api/v1/recordings/:recording_id/graph", get(replay_not_implemented_graph))
        .route("/api/v1/endpoints", get(list_observed_endpoints))
        .route("/api/v1/endpoints/:operation_id/recordings", get(list_operation_recordings))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
        .layer(axum::middleware::from_fn(add_response_security))
        .fallback(not_found)
        .with_state(state)
}

async fn add_response_security(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    add_security_headers(response.headers_mut());
    response
}

async fn not_found<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort,
{
    if !valid_host(&headers, &state.host) {
        return problem(StatusCode::BAD_REQUEST, "XTR-VIEWER-HOST", "Host is not accepted");
    }
    problem(StatusCode::NOT_FOUND, "XTR-VIEWER-ROUTE", "Requested viewer resource was not found")
}

async fn index<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort,
{
    if !valid_host(&headers, &state.host) {
        return problem(StatusCode::BAD_REQUEST, "XTR-VIEWER-HOST", "Host is not accepted");
    }
    let body = include_str!("../assets/ui/index.html");
    response_with_security(StatusCode::OK, "text/html; charset=utf-8", body.as_bytes())
}

async fn app_js<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort,
{
    asset_response(
        &headers,
        &state.host,
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/ui/app.js"),
    )
}

async fn app_css<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort,
{
    asset_response(
        &headers,
        &state.host,
        "text/css; charset=utf-8",
        include_bytes!("../assets/ui/index.css"),
    )
}

async fn chivo_font<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort,
{
    asset_response(
        &headers,
        &state.host,
        "font/woff2",
        include_bytes!("../assets/ui/fonts/chivo-latin-400-normal.woff2"),
    )
}

async fn chivo_bold_font<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
) -> Response
where
    P: RecordingReadPort,
{
    asset_response(
        &headers,
        &state.host,
        "font/woff2",
        include_bytes!("../assets/ui/fonts/chivo-latin-600-normal.woff2"),
    )
}

async fn mono_font<P>(State(state): State<Arc<ViewerState<P>>>, headers: HeaderMap) -> Response
where
    P: RecordingReadPort,
{
    asset_response(
        &headers,
        &state.host,
        "font/woff2",
        include_bytes!("../assets/ui/fonts/azeret-mono-latin-400-normal.woff2"),
    )
}

fn asset_response(
    headers: &HeaderMap,
    host: &str,
    content_type: &'static str,
    body: &'static [u8],
) -> Response {
    if !valid_host(headers, host) {
        return problem(StatusCode::BAD_REQUEST, "XTR-VIEWER-HOST", "Host is not accepted");
    }
    response_with_security(StatusCode::OK, content_type, body)
}

#[derive(Deserialize)]
struct ExchangeRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    authenticated: bool,
    request_id: CorrelationId,
}

async fn exchange<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    P: RecordingReadPort,
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
    let body = match body {
        Ok(body) => body,
        Err(_) => {
            return problem_with_id(
                StatusCode::PAYLOAD_TOO_LARGE,
                "XTR-VIEWER-AUTH-REQUEST",
                "Authentication request exceeds its size limit",
                request_id,
            );
        }
    };
    if body.len() > MAX_AUTH_BODY_BYTES || !is_json(&headers) {
        return problem_with_id(
            StatusCode::BAD_REQUEST,
            "XTR-VIEWER-AUTH-REQUEST",
            "Authentication request is invalid",
            request_id,
        );
    }
    let request: ExchangeRequest = match serde_json::from_slice::<ExchangeRequest>(&body) {
        Ok(value) if value.token.len() <= 128 => value,
        _ => {
            return problem_with_id(
                StatusCode::BAD_REQUEST,
                "XTR-VIEWER-AUTH-REQUEST",
                "Authentication request is invalid",
                request_id,
            );
        }
    };
    let supplied = match URL_SAFE_NO_PAD.decode(request.token.as_bytes()) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            return problem_with_id(
                StatusCode::UNAUTHORIZED,
                "XTR-VIEWER-AUTH-REJECTED",
                "Bootstrap token is invalid or expired",
                request_id,
            );
        }
    };
    let supplied_digest = *blake3::hash(&supplied).as_bytes();
    let mut bootstrap = state.bootstrap.lock().await;
    if bootstrap.as_ref().is_some_and(|expected| Instant::now() > expected.expires_at) {
        *bootstrap = None;
        return problem_with_id(
            StatusCode::UNAUTHORIZED,
            "XTR-VIEWER-AUTH-REJECTED",
            "Bootstrap token is invalid or expired",
            request_id,
        );
    }
    let accepted = bootstrap.as_ref().is_some_and(|expected| {
        constant_time_eq::constant_time_eq(&expected.digest, &supplied_digest)
    });
    if !accepted {
        return problem_with_id(
            StatusCode::UNAUTHORIZED,
            "XTR-VIEWER-AUTH-REJECTED",
            "Bootstrap token is invalid or expired",
            request_id,
        );
    }
    *bootstrap = None;
    drop(bootstrap);
    let session = match random_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            return problem_with_id(
                StatusCode::INTERNAL_SERVER_ERROR,
                "XTR-VIEWER-AUTH-FAILED",
                "Authentication could not be completed",
                request_id,
            );
        }
    };
    let session_value = URL_SAFE_NO_PAD.encode(session);
    let session_digest = *blake3::hash(&session).as_bytes();
    state
        .sessions
        .lock()
        .await
        .insert(session_digest, Instant::now() + Duration::from_secs(SESSION_TTL_SECONDS));
    let mut response = Json(ExchangeResponse { authenticated: true, request_id }).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={session_value}; Path=/; HttpOnly; SameSite=Strict"
    )) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    add_security_headers(response.headers_mut());
    response
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListParams {
    limit: Option<u32>,
    after: Option<RecordingId>,
}

#[derive(Default)]
struct ObservedParams {
    limit: Option<u32>,
    cursor: Option<String>,
}

fn has_unmatched_selector(raw: Option<&str>) -> bool {
    raw.is_some_and(|query| {
        query.split('&').any(|pair| pair.split_once('=').is_some_and(|(key, _)| key == "unmatched"))
    })
}

fn parse_observed_query(
    raw: Option<&str>,
    allow_unmatched: bool,
    require_unmatched: bool,
) -> Result<ObservedParams, ()> {
    let Some(raw) = raw else {
        return if require_unmatched { Err(()) } else { Ok(ObservedParams::default()) };
    };
    if raw.is_empty() || raw.len() > MAX_OBSERVED_QUERY_BYTES {
        return Err(());
    }
    let mut params = ObservedParams::default();
    let mut saw_unmatched = false;
    for pair in raw.split('&') {
        let (key, value) = pair.split_once('=').ok_or(())?;
        if value.is_empty() || value.contains('=') {
            return Err(());
        }
        match key {
            "limit"
                if params.limit.is_none() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                params.limit = Some(value.parse::<u32>().map_err(|_| ())?);
            }
            "cursor"
                if params.cursor.is_none()
                    && value.len() <= MAX_OBSERVED_CURSOR_BYTES
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                    }) =>
            {
                params.cursor = Some(value.to_owned());
            }
            "unmatched" if allow_unmatched && !saw_unmatched && value == "true" => {
                saw_unmatched = true;
            }
            _ => return Err(()),
        }
    }
    if require_unmatched != saw_unmatched {
        return Err(());
    }
    Ok(params)
}

async fn authorize_api<P>(
    state: &ViewerState<P>,
    headers: &HeaderMap,
    request_id: CorrelationId,
) -> Result<(), Response> {
    if !valid_request_origin(headers, &state.host, &state.origin, true) {
        return Err(problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-ORIGIN",
            "Request origin is not accepted",
            request_id,
        ));
    }
    if !one_header_equals(headers, HeaderName::from_static("x-xtrace-client"), "viewer-v1") {
        return Err(problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-CLIENT",
            "Viewer request is not accepted",
            request_id,
        ));
    }
    if !authorized(headers, state).await {
        return Err(problem_with_id(
            StatusCode::UNAUTHORIZED,
            "XTR-VIEWER-SESSION",
            "Viewer session is missing or expired",
            request_id,
        ));
    }
    Ok(())
}

async fn list_observed_endpoints<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    if let Err(response) = authorize_api(&state, &headers, request_id).await {
        return response;
    }
    let params = match parse_observed_query(query.as_deref(), false, false) {
        Ok(params) => params,
        Err(()) => return observed_query_problem(request_id),
    };
    if params.limit.is_some_and(|limit| limit == 0 || limit > MAX_OBSERVED_ENDPOINT_LIMIT) {
        return observed_query_problem(request_id);
    }
    let service = state.observed_service.clone();
    let request = ListObservedEndpoints {
        project_id: state.project_id,
        limit: params.limit,
        cursor: params.cursor,
    };
    let page = match run_observed_query(&state, request_id, move || {
        service.list_observed_endpoints(request, request_id)
    })
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    success_json(page, request_id)
}

async fn list_operation_recordings<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    operation_path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    RawQuery(query): RawQuery,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    if let Err(response) = authorize_api(&state, &headers, request_id).await {
        return response;
    }
    let Ok(Path(operation_id)) = operation_path else {
        return observed_query_problem(request_id);
    };
    let params = match parse_observed_query(query.as_deref(), false, false) {
        Ok(params) => params,
        Err(()) => return observed_query_problem(request_id),
    };
    if params.limit.is_some_and(|limit| limit == 0 || limit > MAX_OBSERVED_RECORDING_LIMIT) {
        return observed_query_problem(request_id);
    }
    let Ok(parsed_id) = operation_id.parse::<OperationId>() else {
        return observed_query_problem(request_id);
    };
    if parsed_id.to_string() != operation_id
        || parsed_id.as_uuid().get_version_num() != 7
        || parsed_id.as_uuid().get_variant() != uuid::Variant::RFC4122
    {
        return observed_query_problem(request_id);
    }
    let service = state.observed_service.clone();
    let request = ListOperationRecordings {
        project_id: state.project_id,
        operation_id: parsed_id,
        limit: params.limit,
        cursor: params.cursor,
    };
    let page = match run_observed_query(&state, request_id, move || {
        service.list_operation_recordings(request, request_id)
    })
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    success_json(page, request_id)
}

async fn list_unmatched_recordings_authorized<P>(
    state: &ViewerState<P>,
    request_id: CorrelationId,
    query: Option<&str>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let params = match parse_observed_query(query, true, true) {
        Ok(params) => params,
        Err(()) => return observed_query_problem(request_id),
    };
    if params.limit.is_some_and(|limit| limit == 0 || limit > MAX_OBSERVED_RECORDING_LIMIT) {
        return observed_query_problem(request_id);
    }
    let service = state.observed_service.clone();
    let request = ListUnmatchedRecordings {
        project_id: state.project_id,
        limit: params.limit,
        cursor: params.cursor,
    };
    let page = match run_observed_query(state, request_id, move || {
        service.list_unmatched_recordings(request, request_id)
    })
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    success_json(page, request_id)
}

fn observed_query_problem(request_id: CorrelationId) -> Response {
    problem_with_id(
        StatusCode::BAD_REQUEST,
        "XTR-VALIDATION-ENDPOINT-QUERY",
        "Observed endpoint query is invalid",
        request_id,
    )
}

async fn list_recordings<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    if !valid_request_origin(&headers, &state.host, &state.origin, true) {
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
    if has_unmatched_selector(query.as_deref()) {
        return list_unmatched_recordings_authorized(&state, request_id, query.as_deref()).await;
    }
    let params = match parse_query::<ListParams>(query.as_deref(), &["limit", "after"]) {
        Ok(params) => params,
        Err(()) => {
            return problem_with_id(
                StatusCode::BAD_REQUEST,
                "XTR-VIEWER-QUERY",
                "Recording query is invalid",
                request_id,
            );
        }
    };
    let limit = params.limit.unwrap_or(50);
    if limit == 0 || limit > MAX_RECORDING_LIST_LIMIT {
        return problem_with_id(
            StatusCode::BAD_REQUEST,
            "XTR-VALIDATION-RECORDING-QUERY",
            "Recording query limit is outside supported bounds",
            request_id,
        );
    }
    let service = state.recording_service.clone();
    let request = xtrace_application::ListRecordings {
        project_id: state.project_id,
        limit,
        after: params.after,
    };
    let page =
        match run_recording_query(&state, request_id, move || service.list(request, request_id))
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    success_json(to_transport_list(page, request_id), request_id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShowParams {
    limit: Option<u32>,
    cursor: Option<String>,
    around_frame: Option<String>,
    projection: Option<String>,
}

/// Stable code for replay routes whose behaviour is registered but not yet served.
const REPLAY_NOT_IMPLEMENTED_CODE: &str = "XTR-REPLAY-NOT-IMPLEMENTED";
const REPLAY_NOT_IMPLEMENTED_DETAIL: &str = "Replay route is registered but not implemented yet";

fn replay_not_implemented_response(request_id: CorrelationId) -> Response {
    problem_with_id(
        StatusCode::NOT_IMPLEMENTED,
        REPLAY_NOT_IMPLEMENTED_CODE,
        REPLAY_NOT_IMPLEMENTED_DETAIL,
        request_id,
    )
}

/// Applies the same origin, client and session guards as every other viewer
/// route; `Some` is the rejection to return.
async fn viewer_guard_rejection<P>(
    headers: &HeaderMap,
    state: &ViewerState<P>,
    request_id: CorrelationId,
) -> Option<Response> {
    if !valid_request_origin(headers, &state.host, &state.origin, true) {
        return Some(problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-ORIGIN",
            "Request origin is not accepted",
            request_id,
        ));
    }
    if !one_header_equals(headers, HeaderName::from_static("x-xtrace-client"), "viewer-v1") {
        return Some(problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-CLIENT",
            "Viewer request is not accepted",
            request_id,
        ));
    }
    if !authorized(headers, state).await {
        return Some(problem_with_id(
            StatusCode::UNAUTHORIZED,
            "XTR-VIEWER-SESSION",
            "Viewer session is missing or expired",
            request_id,
        ));
    }
    None
}

async fn replay_not_implemented_guarded<P>(
    state: &ViewerState<P>,
    headers: &HeaderMap,
    recording_id: &str,
) -> Response {
    let request_id = CorrelationId::new();
    if let Some(rejection) = viewer_guard_rejection(headers, state, request_id).await {
        return rejection;
    }
    if recording_id.parse::<RecordingId>().is_err() {
        return problem_with_id(
            StatusCode::NOT_FOUND,
            "XTR-NOT-FOUND-RECORDING",
            "Recording was not found",
            request_id,
        );
    }
    replay_not_implemented_response(request_id)
}

/// Resolves the viewer guards and the path ids shared by the per-frame routes.
async fn frame_route_preamble<P>(
    state: &ViewerState<P>,
    headers: &HeaderMap,
    recording_id: &str,
    request_id: CorrelationId,
) -> Result<RecordingId, Response> {
    if let Some(rejection) = viewer_guard_rejection(headers, state, request_id).await {
        return Err(rejection);
    }
    recording_id.parse::<RecordingId>().map_err(|_| {
        problem_with_id(
            StatusCode::NOT_FOUND,
            "XTR-NOT-FOUND-RECORDING",
            "Recording was not found",
            request_id,
        )
    })
}

fn frame_not_found(request_id: CorrelationId) -> Response {
    problem_with_id(
        StatusCode::NOT_FOUND,
        "XTR-NOT-FOUND-RECORDING",
        "Recording frame was not found",
        request_id,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportFrameNavigation {
    #[serde(flatten)]
    view: xtrace_application::FrameNavigationView,
    request_id: CorrelationId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportNavigateResult {
    frame_id: xtrace_domain::FrameId,
    action: &'static str,
    result: xtrace_application::NavigationResult,
    request_id: CorrelationId,
}

#[derive(Deserialize)]
struct NavigateParams {
    frame: Option<String>,
    action: Option<String>,
    kinds: Option<String>,
    kind: Option<String>,
    dir: Option<String>,
}

async fn frame_navigation_route<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    Path((recording_id, frame_id)): Path<(String, String)>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    let recording_id = match frame_route_preamble(&state, &headers, &recording_id, request_id).await
    {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Ok(frame_id) = frame_id.parse::<xtrace_domain::FrameId>() else {
        return frame_not_found(request_id);
    };
    let service = state.recording_service.clone();
    let project_id = state.project_id;
    let view = match run_recording_query(&state, request_id, move || {
        service.frame_navigation(project_id, recording_id, frame_id, request_id)
    })
    .await
    {
        Ok(view) => view,
        Err(response) => return response,
    };
    success_json(TransportFrameNavigation { view, request_id }, request_id)
}

async fn navigate_route<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    Path(recording_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    let recording_id = match frame_route_preamble(&state, &headers, &recording_id, request_id).await
    {
        Ok(id) => id,
        Err(response) => return response,
    };
    let invalid = || {
        problem_with_id(
            StatusCode::BAD_REQUEST,
            "XTR-VALIDATION-RECORDING-QUERY",
            "Recording query is invalid",
            request_id,
        )
    };
    let Ok(params) = parse_query::<NavigateParams>(
        query.as_deref(),
        &["frame", "action", "kinds", "kind", "dir"],
    ) else {
        return problem_with_id(
            StatusCode::BAD_REQUEST,
            "XTR-VIEWER-QUERY",
            "Recording query is invalid",
            request_id,
        );
    };
    // The kind-filtered step and the gap/error/interaction jump are registered but
    // not served yet; they are never answered with an unfiltered result.
    if params.kinds.is_some() || params.kind.is_some() || params.dir.is_some() {
        return replay_not_implemented_response(request_id);
    }
    let Some(action) =
        params.action.as_deref().and_then(xtrace_application::NavigationAction::parse)
    else {
        return invalid();
    };
    let Some(frame) = params.frame.as_deref() else {
        return invalid();
    };
    let Ok(frame_id) = frame.parse::<xtrace_domain::FrameId>() else {
        return frame_not_found(request_id);
    };
    let service = state.recording_service.clone();
    let project_id = state.project_id;
    let view = match run_recording_query(&state, request_id, move || {
        service.frame_navigation(project_id, recording_id, frame_id, request_id)
    })
    .await
    {
        Ok(view) => view,
        Err(response) => return response,
    };
    success_json(
        TransportNavigateResult {
            frame_id: view.frame_id,
            action: action.as_str(),
            result: action.select(&view.navigation),
            request_id,
        },
        request_id,
    )
}

async fn replay_not_implemented_frames<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    Path(recording_id): Path<String>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    replay_not_implemented_guarded(&state, &headers, &recording_id).await
}

async fn replay_not_implemented_graph<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    Path(recording_id): Path<String>,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    replay_not_implemented_guarded(&state, &headers, &recording_id).await
}

async fn show_recording<P>(
    State(state): State<Arc<ViewerState<P>>>,
    headers: HeaderMap,
    Path(recording_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    let request_id = CorrelationId::new();
    if !valid_request_origin(&headers, &state.host, &state.origin, true) {
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
    let params = match parse_query::<ShowParams>(
        query.as_deref(),
        &["limit", "cursor", "aroundFrame", "projection"],
    ) {
        Ok(params) => params,
        Err(()) => {
            return problem_with_id(
                StatusCode::BAD_REQUEST,
                "XTR-VIEWER-QUERY",
                "Recording query is invalid",
                request_id,
            );
        }
    };
    if params.cursor.is_some() && params.around_frame.is_some() {
        return problem_with_id(
            StatusCode::BAD_REQUEST,
            "XTR-VALIDATION-RECORDING-QUERY",
            "Recording query is invalid",
            request_id,
        );
    }
    let projection_structure = match params.projection.as_deref() {
        None | Some("full") => false,
        Some("structure") => true,
        Some(_) => {
            return problem_with_id(
                StatusCode::BAD_REQUEST,
                "XTR-VALIDATION-RECORDING-QUERY",
                "Recording query is invalid",
                request_id,
            );
        }
    };
    let Ok(recording_id) = recording_id.parse::<RecordingId>() else {
        return problem_with_id(
            StatusCode::NOT_FOUND,
            "XTR-NOT-FOUND-RECORDING",
            "Recording was not found",
            request_id,
        );
    };
    if projection_structure {
        return replay_not_implemented_response(request_id);
    }
    let around_frame = match params.around_frame.as_deref() {
        None => None,
        Some(raw) => match raw.parse::<xtrace_domain::FrameId>() {
            Ok(frame_id) => Some(frame_id),
            Err(_) => return frame_not_found(request_id),
        },
    };
    let service = state.recording_service.clone();
    let request = ShowRecording {
        project_id: state.project_id,
        recording_id,
        limit: params.limit.unwrap_or(200),
        cursor: params.cursor,
        around_frame,
    };
    let detail =
        match run_recording_query(&state, request_id, move || service.show(request, request_id))
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    success_json(to_transport_detail(detail, request_id), request_id)
}

async fn run_recording_query<T, P, F>(
    state: &ViewerState<P>,
    request_id: CorrelationId,
    query: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    P: RecordingReadPort + Clone + 'static,
    F: FnOnce() -> Result<T, xtrace_domain::AppError> + Send + 'static,
{
    match state.query_lane.run(query).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(app_problem(error, request_id)),
        Err(QueryLaneError::Busy | QueryLaneError::Closed) => Err(problem_with_id(
            StatusCode::SERVICE_UNAVAILABLE,
            "XTR-VIEWER-QUERY-BUSY",
            "Viewer query capacity is unavailable",
            request_id,
        )),
        Err(QueryLaneError::Join) => Err(problem_with_id(
            StatusCode::INTERNAL_SERVER_ERROR,
            "XTR-VIEWER-QUERY-FAILED",
            "Recording query could not be completed",
            request_id,
        )),
    }
}

async fn run_observed_query<T, P, F>(
    state: &ViewerState<P>,
    request_id: CorrelationId,
    query: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    P: RecordingReadPort + Clone + 'static,
    F: FnOnce() -> Result<T, xtrace_domain::AppError> + Send + 'static,
{
    match state.query_lane.run(query).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(observed_app_problem(error, request_id)),
        Err(QueryLaneError::Busy | QueryLaneError::Closed) => Err(problem_with_id(
            StatusCode::SERVICE_UNAVAILABLE,
            "XTR-VIEWER-QUERY-BUSY",
            "Viewer query capacity is unavailable",
            request_id,
        )),
        Err(QueryLaneError::Join) => Err(problem_with_id(
            StatusCode::INTERNAL_SERVER_ERROR,
            "XTR-VIEWER-QUERY-FAILED",
            "Observed endpoint query could not be completed",
            request_id,
        )),
    }
}

fn observed_app_problem(error: xtrace_domain::AppError, request_id: CorrelationId) -> Response {
    let (status, title, detail) = match error.category {
        xtrace_domain::ErrorCategory::NotFound => {
            (StatusCode::NOT_FOUND, "Not Found", "Requested endpoint resource was not found")
        }
        xtrace_domain::ErrorCategory::Corruption => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Content",
            "Persisted endpoint query could not be verified",
        ),
        xtrace_domain::ErrorCategory::Validation => {
            (StatusCode::BAD_REQUEST, "Bad Request", "Observed endpoint query is invalid")
        }
        xtrace_domain::ErrorCategory::Resource => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "Observed endpoint query capacity is unavailable",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "Observed endpoint query could not be completed",
        ),
    };
    problem_with_dynamic_code(status, title, detail, error.code.as_str(), request_id)
}

fn parse_query<T: for<'de> Deserialize<'de>>(raw: Option<&str>, allowed: &[&str]) -> Result<T, ()> {
    let Some(raw) = raw else {
        return serde_json::from_value(serde_json::json!({})).map_err(|_| ());
    };
    if raw.len() > 512 || raw.is_empty() {
        return Err(());
    }
    let mut object = serde_json::Map::new();
    for pair in raw.split('&') {
        let (key, value) = pair.split_once('=').ok_or(())?;
        if !allowed.contains(&key)
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
            || object.contains_key(key)
        {
            return Err(());
        }
        let parsed = if key == "limit" {
            serde_json::Value::Number(value.parse::<u64>().map_err(|_| ())?.into())
        } else {
            serde_json::Value::String(value.to_owned())
        };
        object.insert(key.to_owned(), parsed);
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(|_| ())
}

fn success_json<T: Serialize>(document: T, request_id: CorrelationId) -> Response {
    let mut response = Json(document).into_response();
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(HeaderName::from_static("x-xtrace-request-id"), value);
    }
    add_security_headers(response.headers_mut());
    response
}

async fn authorized<P>(headers: &HeaderMap, state: &ViewerState<P>) -> bool {
    let Some(cookie) = cookie_value(headers, SESSION_COOKIE) else {
        return false;
    };
    let Ok(raw) = URL_SAFE_NO_PAD.decode(cookie.as_bytes()) else {
        return false;
    };
    if raw.len() != 32 {
        return false;
    }
    let digest = *blake3::hash(&raw).as_bytes();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, expires| Instant::now() <= *expires);
    sessions.get(&digest).is_some_and(|expires| Instant::now() <= *expires)
}

fn valid_request_origin(
    headers: &HeaderMap,
    host: &str,
    origin: &str,
    allow_missing: bool,
) -> bool {
    if !valid_host(headers, host)
        || !one_header_equals(headers, HeaderName::from_static("sec-fetch-site"), "same-origin")
    {
        return false;
    }
    let values = headers.get_all(header::ORIGIN);
    let count = values.iter().count();
    if count == 0 {
        return allow_missing;
    }
    if count != 1 {
        return false;
    }
    let Some(raw) = values.iter().next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(parsed) = Uri::from_str(raw) else {
        return false;
    };
    parsed.scheme_str() == Some("http")
        && parsed.authority().is_some_and(|authority| authority.as_str() == host)
        && parsed.path_and_query().is_none_or(|path| path.as_str() == "/")
        && raw == origin
}

fn valid_host(headers: &HeaderMap, host: &str) -> bool {
    let values = headers.get_all(header::HOST);
    if values.iter().count() != 1 {
        return false;
    }
    let Some(raw) = values.iter().next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = axum::http::uri::Authority::from_str(raw) else {
        return false;
    };
    authority.host() == "127.0.0.1" && authority.as_str() == host && !raw.contains('@')
}

fn one_header_equals(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    let values = headers.get_all(name);
    values.iter().count() == 1
        && values.iter().next().is_some_and(|value| value.as_bytes() == expected.as_bytes())
}

fn is_json(headers: &HeaderMap) -> bool {
    one_header_equals(headers, header::CONTENT_TYPE, "application/json")
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE).iter() {
        let text = header.to_str().ok()?;
        for item in text.split(';') {
            let (key, value) = item.trim().split_once('=')?;
            if key == name {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

fn random_bytes() -> Result<[u8; 32], ViewerError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(ViewerError::Random)?;
    Ok(bytes)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportList {
    schema_version: u32,
    project_id: ProjectId,
    limit: u32,
    after: Option<RecordingId>,
    recordings: Vec<TransportRecording>,
    next_after: Option<RecordingId>,
    unavailable: xtrace_application::UnavailableEvidence,
    request_id: CorrelationId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportRecording {
    recording_id: RecordingId,
    status: xtrace_application::RecordingStatus,
    completion: xtrace_application::RecordingCompletionEvidence,
    opened_at: String,
    segment_count: String,
    event_count: String,
    first_sequence: Option<String>,
    last_sequence: Option<String>,
    incomplete_evidence: Vec<String>,
    event_cap: Option<u32>,
    outcome_kind: Option<String>,
}

fn to_transport_list(page: RecordingListPage, request_id: CorrelationId) -> TransportList {
    TransportList {
        schema_version: page.schema_version,
        project_id: page.project_id,
        limit: page.limit,
        after: page.after,
        recordings: page
            .recordings
            .into_iter()
            .map(|item| TransportRecording {
                recording_id: item.recording_id,
                status: item.status,
                completion: item.completion,
                opened_at: item.opened_at,
                segment_count: item.segment_count,
                event_count: item.event_count,
                first_sequence: item.first_sequence,
                last_sequence: item.last_sequence,
                incomplete_evidence: item.incomplete_evidence,
                event_cap: item.event_cap,
                outcome_kind: item.outcome_kind,
            })
            .collect(),
        next_after: page.next_after,
        unavailable: page.unavailable,
        request_id,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportDetail {
    schema_version: u32,
    project_id: ProjectId,
    recording_id: RecordingId,
    status: xtrace_application::RecordingStatus,
    completion: xtrace_application::RecordingCompletionEvidence,
    adapter_summary: Option<xtrace_domain::CapturedValue>,
    duration_ns: Option<String>,
    drop_counts_by_priority: std::collections::BTreeMap<u32, String>,
    limit: u32,
    cursor: Option<String>,
    next_cursor: Option<String>,
    segment_count: String,
    events: Vec<TransportEvent>,
    incomplete_evidence: Vec<String>,
    unavailable: xtrace_application::UnavailableEvidence,
    outcome: Option<xtrace_application::PersistedOutcome>,
    capacity: Option<xtrace_application::RecordingCapacity>,
    limitations: Vec<String>,
    honesty: xtrace_application::HonestySummary,
    anchor_frame_id: Option<xtrace_domain::FrameId>,
    first_sequence: Option<String>,
    last_sequence: Option<String>,
    prev_cursor: Option<String>,
    projection: xtrace_application::Projection,
    request_id: CorrelationId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportEvent {
    sequence: String,
    frame_id: Option<xtrace_domain::FrameId>,
    navigation: xtrace_application::FrameNavigation,
    monotonic_ns: String,
    event_id: Option<String>,
    parent_event_id: Option<String>,
    async_parent_event_id: Option<String>,
    kind: String,
    symbol: Option<String>,
    interaction: Option<xtrace_application::PersistedInteraction>,
    source: Option<xtrace_application::PersistedSource>,
    source_binding: xtrace_domain::SourceBinding,
    field_truncations: Vec<TransportTruncation>,
    depth: Option<u32>,
    parent_frame_id: Option<xtrace_domain::FrameId>,
    async_parent_frame_id: Option<xtrace_domain::FrameId>,
    line: Option<u32>,
    bindings: Vec<xtrace_application::PersistedBinding>,
    gap: Option<xtrace_application::PersistedGap>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportTruncation {
    field: String,
    original_bytes: String,
    representation: xtrace_application::FieldRepresentation,
}

fn to_transport_detail(detail: RecordingDetail, request_id: CorrelationId) -> TransportDetail {
    TransportDetail {
        schema_version: detail.schema_version,
        project_id: detail.project_id,
        recording_id: detail.recording_id,
        status: detail.status,
        completion: detail.completion,
        adapter_summary: detail.adapter_summary,
        duration_ns: detail.duration_ns,
        drop_counts_by_priority: detail.drop_counts_by_priority,
        limit: detail.limit,
        cursor: detail.cursor,
        next_cursor: detail.next_cursor,
        segment_count: detail.segment_count,
        events: detail
            .events
            .into_iter()
            .map(|item| TransportEvent {
                sequence: item.sequence,
                frame_id: item.frame_id,
                navigation: item.navigation,
                monotonic_ns: item.monotonic_ns,
                event_id: item.event_id,
                parent_event_id: item.parent_event_id,
                async_parent_event_id: item.async_parent_event_id,
                kind: item.kind,
                symbol: item.symbol,
                interaction: item.interaction,
                source: item.source,
                source_binding: item.source_binding,
                depth: item.depth,
                parent_frame_id: item.parent_frame_id,
                async_parent_frame_id: item.async_parent_frame_id,
                line: item.line,
                bindings: item.bindings,
                gap: item.gap,
                field_truncations: item
                    .field_truncations
                    .into_iter()
                    .map(|entry| TransportTruncation {
                        field: entry.field,
                        original_bytes: entry.original_bytes,
                        representation: entry.representation,
                    })
                    .collect(),
            })
            .collect(),
        incomplete_evidence: detail.incomplete_evidence,
        unavailable: detail.unavailable,
        outcome: detail.outcome,
        capacity: detail.capacity,
        limitations: detail.limitations,
        honesty: detail.honesty,
        anchor_frame_id: detail.anchor_frame_id,
        first_sequence: detail.first_sequence,
        last_sequence: detail.last_sequence,
        prev_cursor: detail.prev_cursor,
        projection: detail.projection,
        request_id,
    }
}

fn app_problem(error: xtrace_domain::AppError, request_id: CorrelationId) -> Response {
    let (status, title, detail) = match error.category {
        xtrace_domain::ErrorCategory::NotFound => {
            (StatusCode::NOT_FOUND, "Not Found", "Requested recording was not found")
        }
        xtrace_domain::ErrorCategory::Corruption => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Content",
            "Persisted recording could not be verified",
        ),
        xtrace_domain::ErrorCategory::Validation => {
            (StatusCode::BAD_REQUEST, "Bad Request", "Recording query is invalid")
        }
        xtrace_domain::ErrorCategory::Resource => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Content Too Large",
            "Recording window exceeds supported resource bounds",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "Recording query could not be completed",
        ),
    };
    let code = error.code.as_str();
    problem_with_dynamic_code(status, title, detail, code, request_id)
}

fn problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    problem_with_id(status, code, detail, CorrelationId::new())
}

fn problem_with_id(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: CorrelationId,
) -> Response {
    problem_with_dynamic_code(
        status,
        status.canonical_reason().unwrap_or("Error"),
        detail,
        code,
        request_id,
    )
}

fn problem_with_dynamic_code(
    status: StatusCode,
    title: &'static str,
    detail: &'static str,
    code: &str,
    request_id: CorrelationId,
) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
        "requestId": request_id.to_string(),
    });
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
    response.headers_mut().insert(
        HeaderName::from_static("x-xtrace-request-id"),
        HeaderValue::from_str(&request_id.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    add_security_headers(response.headers_mut());
    response
}

fn response_with_security(status: StatusCode, content_type: &'static str, body: &[u8]) -> Response {
    let mut response = (status, body.to_vec()).into_response();
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    add_security_headers(response.headers_mut());
    response
}

fn add_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(HeaderName::from_static("content-security-policy"), HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "HTTP tests use fixed local fixture data"
)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xtrace_application::FrameNavigationView;
    use xtrace_application::observed_endpoint_queries::{
        ObservedEndpointKey, ObservedEndpointRecord, ObservedRecordingKey, ObservedRecordingRecord,
    };
    use xtrace_application::recording::{BeginRecording, EndpointObservationInput};
    use xtrace_application::{
        ObservedEndpointReadPort, PortError, PortErrorKind, ProjectRepository,
        RecordingEventWindow, RecordingMetadata, RecordingPersistencePort, ShowWindowRequest,
    };
    use xtrace_domain::{FrameId, Project, RepositoryFingerprint, RuntimeSessionId, WallTime};
    use xtrace_store::{
        OpenOptions, SqliteRecordingPersistence, SqliteRecordingReader, SqliteStore,
    };

    #[derive(Clone, Default)]
    struct ReadFixture {
        observed_calls: Arc<AtomicUsize>,
        observed_error: Option<PortErrorKind>,
    }

    impl ReadFixture {
        fn failing(kind: PortErrorKind) -> Self {
            Self { observed_error: Some(kind), ..Self::default() }
        }

        fn observed_result<T>(&self, value: T) -> Result<T, PortError> {
            self.observed_calls.fetch_add(1, Ordering::AcqRel);
            match self.observed_error {
                Some(kind) => {
                    Err(PortError::new(kind, "PRIVATE_DATABASE_CANARY", CorrelationId::new()))
                }
                None => Ok(value),
            }
        }
    }

    impl RecordingReadPort for ReadFixture {
        fn frame_navigation(
            &self,
            _project_id: ProjectId,
            _recording_id: RecordingId,
            _frame_id: FrameId,
        ) -> Result<FrameNavigationView, PortError> {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "fixture has no frames",
                CorrelationId::new(),
            ))
        }

        fn list_recordings(
            &self,
            _project_id: ProjectId,
            _after: Option<RecordingId>,
            _limit: u32,
        ) -> Result<(Vec<RecordingMetadata>, bool), PortError> {
            Ok((Vec::new(), false))
        }

        fn show_recording(
            &self,
            _request: &ShowWindowRequest,
        ) -> Result<RecordingEventWindow, PortError> {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "recording was not found",
                CorrelationId::new(),
            ))
        }
    }

    impl ObservedEndpointReadPort for ReadFixture {
        fn list_observed_endpoints(
            &self,
            _project_id: ProjectId,
            _after: Option<&ObservedEndpointKey>,
            _limit: u32,
        ) -> Result<(Vec<ObservedEndpointRecord>, bool), PortError> {
            self.observed_result((Vec::new(), false))
        }

        fn list_operation_recordings(
            &self,
            _project_id: ProjectId,
            _operation_id: OperationId,
            _after: Option<&ObservedRecordingKey>,
            _limit: u32,
        ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
            self.observed_calls.fetch_add(1, Ordering::AcqRel);
            if let Some(kind) = self.observed_error {
                Err(PortError::new(kind, "PRIVATE_DATABASE_CANARY", CorrelationId::new()))
            } else {
                Err(PortError::new(
                    PortErrorKind::NotFound,
                    "endpoint was not found",
                    CorrelationId::new(),
                ))
            }
        }

        fn list_unmatched_recordings(
            &self,
            _project_id: ProjectId,
            _after: Option<&ObservedRecordingKey>,
            _limit: u32,
        ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
            self.observed_result((Vec::new(), false))
        }
    }

    struct RunningViewer {
        host: String,
        origin: String,
        token: String,
        observed_calls: Arc<AtomicUsize>,
        query_lane: QueryLane,
        shutdown: tokio::sync::oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<(), ViewerError>>,
    }

    async fn start() -> RunningViewer {
        start_with(ReadFixture::default()).await
    }

    async fn start_with(fixture: ReadFixture) -> RunningViewer {
        let project_id = ProjectId::new();
        let bound = BoundViewer::bind(
            RecordingQueryService::new(fixture.clone()),
            ObservedEndpointQueryService::new(fixture.clone()),
            project_id,
        )
        .await
        .expect("bind local viewer");
        let query_lane = bound.state.query_lane.clone();
        let ready = bound.readiness();
        let host = ready.origin.strip_prefix("http://").unwrap().to_owned();
        let token = ready.url.rsplit_once("token=").unwrap().1.to_owned();
        assert_eq!(token.len(), 43);
        assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)));
        let origin = ready.origin;
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(bound.serve(async move {
            let _ = receiver.await;
        }));
        RunningViewer {
            host,
            origin,
            token,
            observed_calls: fixture.observed_calls,
            query_lane,
            shutdown,
            task,
        }
    }

    async fn request(host: &str, text: &str) -> String {
        let bytes = wire_request(host, text).await.expect("complete HTTP response");
        String::from_utf8(bytes).expect("HTTP response is UTF-8")
    }

    async fn wire_request(host: &str, text: &str) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(host).await.expect("connect viewer");
        stream.write_all(text.as_bytes()).await.expect("send HTTP request");
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await.map_err(
            |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "viewer response timeout"),
        )??;
        Ok(response)
    }

    fn request_headers(host: &str, origin: &str) -> String {
        format!(
            "Host: {host}\r\nOrigin: {origin}\r\nSec-Fetch-Site: same-origin\r\nX-XTrace-Client: viewer-v1\r\n"
        )
    }

    async fn authenticate(viewer: &RunningViewer) -> String {
        let response = exchange_response(viewer).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let cookie = response
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
            .expect("session cookie")
            .split_once(':')
            .unwrap()
            .1
            .trim()
            .to_owned();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(!cookie.contains("Max-Age="));
        assert!(!cookie.contains("Expires="));
        assert!(!cookie.contains("Secure"));
        assert!(!cookie.contains("Domain="));
        cookie.split(';').next().unwrap().to_owned()
    }

    async fn exchange_response(viewer: &RunningViewer) -> String {
        exchange_token(viewer, &viewer.token).await
    }

    async fn exchange_token(viewer: &RunningViewer, token: &str) -> String {
        let body = serde_json::json!({ "token": token });
        let body = body.to_string();
        let raw = format!(
            "POST /api/v1/auth/exchange HTTP/1.1\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            request_headers(&viewer.host, &viewer.origin),
            body.len(),
            body
        );
        request(&viewer.host, &raw).await
    }

    #[tokio::test]
    async fn one_time_bootstrap_sets_safe_cookie_and_rejects_replay() {
        let viewer = start().await;
        let wrong = exchange_token(&viewer, &URL_SAFE_NO_PAD.encode([0_u8; 32])).await;
        assert!(wrong.starts_with("HTTP/1.1 401"));
        let body = serde_json::json!({ "token": viewer.token.as_str() }).to_string();
        let missing_origin = format!(
            "POST /api/v1/auth/exchange HTTP/1.1\r\nHost: {}\r\nSec-Fetch-Site: same-origin\r\nX-XTrace-Client: viewer-v1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            viewer.host,
            body.len(),
            body
        );
        assert!(request(&viewer.host, &missing_origin).await.starts_with("HTTP/1.1 403"));
        let cookie = authenticate(&viewer).await;
        let replay = exchange_response(&viewer).await;
        assert!(replay.starts_with("HTTP/1.1 401"));
        assert!(!replay.contains(&viewer.token));
        assert!(!cookie.contains(&viewer.token));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn expired_bootstrap_is_rejected_without_disclosing_token() {
        let project_id = ProjectId::new();
        let bound = BoundViewer::bind(
            RecordingQueryService::new(ReadFixture::default()),
            ObservedEndpointQueryService::new(ReadFixture::default()),
            project_id,
        )
        .await
        .expect("bind local viewer");
        if let Some(token) = bound.state.bootstrap.lock().await.as_mut() {
            token.expires_at = Instant::now() - Duration::from_secs(1);
        }
        let ready = bound.readiness();
        let host = ready.origin.strip_prefix("http://").unwrap().to_owned();
        let token = ready.url.rsplit_once("token=").unwrap().1.to_owned();
        let origin = ready.origin;
        let query_lane = bound.state.query_lane.clone();
        let state = bound.state.clone();
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(bound.serve(async move {
            let _ = receiver.await;
        }));
        let expired = RunningViewer {
            host,
            origin,
            token: token.clone(),
            observed_calls: Arc::new(AtomicUsize::new(0)),
            query_lane,
            shutdown,
            task,
        };
        let response = exchange_response(&expired).await;
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(!response.contains(&token));
        assert!(state.bootstrap.lock().await.is_none());
        let _ = expired.shutdown.send(());
        expired.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn host_origin_cookie_cursor_and_unknown_recording_fail_as_safe_problems() {
        let viewer = start().await;
        let index = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", viewer.host);
        let page = request(&viewer.host, &index).await;
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("default-src 'none'"));
        assert!(page.contains("no-referrer"));
        assert!(page.contains("no-store"));
        assert!(!page.contains(&viewer.token));
        let no_cookie = format!(
            "GET /api/v1/recordings HTTP/1.1\r\n{}Connection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let response = request(&viewer.host, &no_cookie).await;
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(response.contains("application/problem+json"));
        assert!(response.contains("requestId"));
        assert!(response.contains("no-store"));

        let _cookie = authenticate(&viewer).await;
        let bad_origin = format!(
            "GET /api/v1/recordings HTTP/1.1\r\n{}Connection: close\r\n\r\n",
            request_headers(&viewer.host, "http://127.0.0.1:1")
        );
        assert!(request(&viewer.host, &bad_origin).await.starts_with("HTTP/1.1 403"));

        let bad_host = "GET / HTTP/1.1\r\nHost: localhost:80\r\nConnection: close\r\n\r\n";
        assert!(request(&viewer.host, bad_host).await.starts_with("HTTP/1.1 400"));

        let traversal = format!(
            "GET /assets/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            viewer.host
        );
        let traversal_response = request(&viewer.host, &traversal).await;
        assert!(traversal_response.starts_with("HTTP/1.1 404"));
        assert!(!traversal_response.contains("root:"));

        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_api_has_exact_origin_and_safe_unknown_and_bad_cursor_responses() {
        let viewer = start().await;
        let cookie = authenticate(&viewer).await;
        let valid_list = format!(
            "GET /api/v1/recordings?limit=50 HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let list = request(&viewer.host, &valid_list).await;
        assert!(list.starts_with("HTTP/1.1 200"));
        assert!(list.contains("\"schemaVersion\":3"));
        assert!(list.contains("\"requestId\""));
        assert!(list.contains("no-store"));

        let browser_get_without_origin = format!(
            "GET /api/v1/recordings HTTP/1.1\r\nHost: {}\r\nSec-Fetch-Site: same-origin\r\nX-XTrace-Client: viewer-v1\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            viewer.host
        );
        assert!(
            request(&viewer.host, &browser_get_without_origin).await.starts_with("HTTP/1.1 200")
        );

        let duplicate_origin = format!(
            "GET /api/v1/recordings HTTP/1.1\r\n{}Origin: {}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin),
            viewer.origin
        );
        assert!(request(&viewer.host, &duplicate_origin).await.starts_with("HTTP/1.1 403"));

        let null_origin = format!(
            "GET /api/v1/recordings HTTP/1.1\r\nHost: {}\r\nOrigin: null\r\nSec-Fetch-Site: same-origin\r\nX-XTrace-Client: viewer-v1\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            viewer.host
        );
        assert!(request(&viewer.host, &null_origin).await.starts_with("HTTP/1.1 403"));

        let missing_fetch = format!(
            "GET /api/v1/recordings HTTP/1.1\r\nHost: {}\r\nX-XTrace-Client: viewer-v1\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            viewer.host
        );
        assert!(request(&viewer.host, &missing_fetch).await.starts_with("HTTP/1.1 403"));

        let malformed_cursor = format!(
            "GET /api/v1/recordings/018f0000-0000-7000-8000-000000000001?cursor=bad%2f%2f HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let bad_cursor = request(&viewer.host, &malformed_cursor).await;
        assert!(bad_cursor.starts_with("HTTP/1.1 400"));
        assert!(bad_cursor.contains("application/problem+json"));

        let unknown = format!(
            "GET /api/v1/recordings/018f0000-0000-7000-8000-000000000001 HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let missing = request(&viewer.host, &unknown).await;
        assert!(missing.starts_with("HTTP/1.1 404"));
        assert!(!missing.contains("SQLite"));

        let duplicate_host = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nHost: {}\r\nConnection: close\r\n\r\n",
            viewer.host, viewer.host
        );
        assert!(request(&viewer.host, &duplicate_host).await.starts_with("HTTP/1.1 400"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn replay_routes_are_guarded_and_answer_501_until_implemented() {
        let viewer = start().await;
        let recording = RecordingId::new();
        let frame = xtrace_domain::FrameId::new();
        let paths = [
            format!("/api/v1/recordings/{recording}/frames/{frame}/navigation"),
            format!("/api/v1/recordings/{recording}/navigate?frame={frame}&action=next"),
            format!("/api/v1/recordings/{recording}/frames?fromOrdinal=0&limit=10"),
            format!("/api/v1/recordings/{recording}/graph"),
            format!("/api/v1/recordings/{recording}?aroundFrame={frame}&limit=50"),
            format!("/api/v1/recordings/{recording}?projection=structure&limit=500"),
        ];
        for path in &paths {
            let unauthenticated = format!(
                "GET {path} HTTP/1.1\r\n{}Connection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            assert!(
                request(&viewer.host, &unauthenticated).await.starts_with("HTTP/1.1 401"),
                "{path} must be session guarded"
            );
        }
        let cookie = authenticate(&viewer).await;
        for path in &paths {
            let raw = format!(
                "GET {path} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            let response = request(&viewer.host, &raw).await;
            assert!(response.starts_with("HTTP/1.1 501"), "{path}: {response}");
            assert!(response.contains("XTR-REPLAY-NOT-IMPLEMENTED"), "{path}: {response}");
        }
        for (path, status) in [
            (format!("/api/v1/recordings/{recording}?cursor=abc&aroundFrame={frame}"), "400"),
            (format!("/api/v1/recordings/{recording}?projection=other"), "400"),
            ("/api/v1/recordings/not-a-recording/graph".to_owned(), "404"),
        ] {
            let raw = format!(
                "GET {path} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            let response = request(&viewer.host, &raw).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{path}: {response}");
        }
    }

    /// Every serialized field of the detail and event DTOs must be documented in
    /// the checked-in OpenAPI schema, and every documented property must exist.
    #[test]
    fn openapi_schema_matches_viewer_dto_for_every_event_field() {
        use xtrace_application::{
            FrameNavigation, HonestySummary, PersistedEvent, Projection,
            RecordingCompletionEvidence, RecordingDetail, RecordingStatus,
        };
        let yaml = include_str!("../../../schema/xtp-client/openapi.yaml");
        let section = |name: &str| -> Vec<String> {
            let header = format!("    {name}:\n");
            let start = yaml.find(&header).expect("schema present") + header.len();
            let rest = &yaml[start..];
            let end = rest
                .match_indices("\n    ")
                .find(|(index, _)| {
                    let after = &rest[index + 1..];
                    after.starts_with("    ") && !after.starts_with("     ")
                })
                .map_or(rest.len(), |(index, _)| index);
            let block = &rest[..end];
            let marker = "      properties:\n";
            let properties = block.find(marker).expect("properties") + marker.len();
            block[properties..]
                .lines()
                .filter(|line| line.starts_with("        ") && !line.starts_with("         "))
                .filter_map(|line| line.trim().split(':').next().map(str::to_owned))
                .collect()
        };
        let detail = RecordingDetail {
            schema_version: 3,
            project_id: ProjectId::new(),
            recording_id: RecordingId::new(),
            status: RecordingStatus::Recording,
            completion: RecordingCompletionEvidence::Unavailable,
            adapter_summary: None,
            duration_ns: None,
            drop_counts_by_priority: std::collections::BTreeMap::new(),
            limit: 1,
            cursor: None,
            next_cursor: None,
            segment_count: "0".into(),
            events: vec![PersistedEvent {
                sequence: "2".into(),
                frame_id: None,
                navigation: FrameNavigation::UNAVAILABLE,
                monotonic_ns: "0".into(),
                event_id: None,
                parent_event_id: None,
                async_parent_event_id: None,
                kind: "frame_enter".into(),
                symbol: None,
                interaction: None,
                source: None,
                source_binding: xtrace_domain::SourceBinding::Unspecified,
                field_truncations: Vec::new(),
                depth: None,
                parent_frame_id: None,
                async_parent_frame_id: None,
                line: None,
                bindings: Vec::new(),
                gap: None,
            }],
            incomplete_evidence: Vec::new(),
            unavailable: xtrace_application::UnavailableEvidence::default(),
            outcome: None,
            capacity: None,
            limitations: Vec::new(),
            honesty: HonestySummary::from_window(
                RecordingCompletionEvidence::Unavailable,
                &[],
                None,
                &std::collections::BTreeMap::new(),
                &[],
            ),
            anchor_frame_id: None,
            first_sequence: None,
            last_sequence: None,
            prev_cursor: None,
            projection: Projection::Full,
        };
        let json = serde_json::to_value(to_transport_detail(detail, CorrelationId::new()))
            .expect("serialize detail");
        let mut actual: Vec<String> = json.as_object().expect("object").keys().cloned().collect();
        let mut documented = section("RecordingDetail");
        actual.sort();
        documented.sort();
        assert_eq!(actual, documented, "RecordingDetail DTO drifted from openapi");
        let mut actual_event: Vec<String> =
            json["events"][0].as_object().expect("event object").keys().cloned().collect();
        let mut documented_event = section("Event");
        actual_event.sort();
        documented_event.sort();
        assert_eq!(actual_event, documented_event, "Event DTO drifted from openapi");
    }

    #[tokio::test]
    async fn observed_routes_use_direct_pages_shared_validation_and_viewer_guards() {
        let viewer = start().await;
        let unauthenticated = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\n{}Connection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        assert!(request(&viewer.host, &unauthenticated).await.starts_with("HTTP/1.1 401"));
        let unauthenticated_linked = format!(
            "GET /api/v1/endpoints/018f0000-0000-7000-8000-000000000001/recordings HTTP/1.1\r\n{}Connection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        assert!(request(&viewer.host, &unauthenticated_linked).await.starts_with("HTTP/1.1 401"));
        let unauthenticated_unmatched = format!(
            "GET /api/v1/recordings?unmatched=true HTTP/1.1\r\n{}Connection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        assert!(
            request(&viewer.host, &unauthenticated_unmatched).await.starts_with("HTTP/1.1 401")
        );
        assert_eq!(viewer.observed_calls.load(Ordering::Acquire), 0);
        let cookie = authenticate(&viewer).await;

        let endpoints = format!(
            "GET /api/v1/endpoints?limit=100 HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let response = request(&viewer.host, &endpoints).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("{\"items\":[],\"nextCursor\":null}"));
        assert!(response.to_ascii_lowercase().contains("x-xtrace-request-id:"));
        assert!(
            response.contains("cache-control: no-store")
                || response.contains("Cache-Control: no-store")
        );
        assert!(!response.contains("requestId\""), "observed page has no wrapper");
        let calls_after_valid_endpoint = viewer.observed_calls.load(Ordering::Acquire);
        assert_eq!(calls_after_valid_endpoint, 1);

        for query in [
            "unmatched=false",
            "unmatched=maybe",
            "unmatched=true&unmatched=true",
            "unmatched=true&after=018f0000-0000-7000-8000-000000000001",
            "unmatched=true&cursor=bad%2f",
            "unmatched=true&limit=0",
            "unmatched=true&unknown=1",
            "unmatched=true&limit=1&limit=2",
            "unmatched=true&cursor=",
            "unmatched=true&limit=+1",
            "%75nmatched=true",
        ] {
            let raw = format!(
                "GET /api/v1/recordings?{query} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            let response = request(&viewer.host, &raw).await;
            assert!(response.starts_with("HTTP/1.1 400"), "observed query validation failed");
            assert!(response.contains("requestId"));
            assert!(!response.contains("bad%2f"));
        }

        for query in
            ["limit=0", "limit=101", "limit=1&limit=2", "cursor=bad%2f", "cursor=abc&unknown=1"]
        {
            let raw = format!(
                "GET /api/v1/endpoints?{query} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            assert!(request(&viewer.host, &raw).await.starts_with("HTTP/1.1 400"));
        }

        let operation_id = OperationId::new().to_string();
        for path in [
            format!("/api/v1/endpoints/{operation_id}/recordings?limit=0"),
            format!("/api/v1/endpoints/{operation_id}/recordings?cursor=bad%2f"),
            format!("/api/v1/endpoints/{operation_id}/recordings?cursor=abc&cursor=def"),
        ] {
            let raw = format!(
                "GET {path} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            assert!(request(&viewer.host, &raw).await.starts_with("HTTP/1.1 400"));
        }
        assert_eq!(
            viewer.observed_calls.load(Ordering::Acquire),
            calls_after_valid_endpoint,
            "invalid observed query modes must be rejected before port calls"
        );

        let valid_unmatched = format!(
            "GET /api/v1/recordings?unmatched=true&limit=50 HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let response = request(&viewer.host, &valid_unmatched).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("{\"items\":[],\"nextCursor\":null}"));
        assert_eq!(viewer.observed_calls.load(Ordering::Acquire), calls_after_valid_endpoint + 1);

        let exact_cursor = format!("cursor={}", "A".repeat(MAX_OBSERVED_CURSOR_BYTES));
        let raw = format!(
            "GET /api/v1/endpoints?{exact_cursor} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let response = request(&viewer.host, &raw).await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(response.contains("XTR-VALIDATION-ENDPOINT-CURSOR"));
        assert!(!response.contains(&"A".repeat(MAX_OBSERVED_CURSOR_BYTES)));

        let oversized_cursor = format!("cursor={}", "A".repeat(MAX_OBSERVED_CURSOR_BYTES + 1));
        let raw = format!(
            "GET /api/v1/endpoints?{oversized_cursor} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        assert!(request(&viewer.host, &raw).await.starts_with("HTTP/1.1 400"));

        let op_id = OperationId::new().to_string();
        for (path, status) in [
            (format!("/api/v1/endpoints/{}/recordings", op_id.to_uppercase()), 400),
            ("/api/v1/endpoints/not-an-operation/recordings".to_owned(), 400),
            ("/api/v1/endpoints/%FF/recordings".to_owned(), 400),
            ("/api/v1/endpoints/SECRET_OPERATION_CANARY/recordings".to_owned(), 400),
            ("/api/v1/endpoints/018f0000-0000-4000-8000-000000000001/recordings".to_owned(), 400),
            ("/api/v1/endpoints/018f0000-0000-7000-0000-000000000001/recordings".to_owned(), 400),
        ] {
            let raw = format!(
                "GET {path} HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
                request_headers(&viewer.host, &viewer.origin)
            );
            let response = request(&viewer.host, &raw).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{response}");
            assert!(response.contains("requestId"));
            assert!(!response.contains("not-an-operation"));
            assert!(!response.contains("SECRET_OPERATION_CANARY"));
        }

        let canonical_unknown = format!(
            "GET /api/v1/endpoints/{op_id}/recordings HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let unknown_response = request(&viewer.host, &canonical_unknown).await;
        assert!(unknown_response.starts_with("HTTP/1.1 404"));
        assert!(!unknown_response.contains(&op_id));

        let client_rejected = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nSec-Fetch-Site: same-origin\r\nX-XTrace-Client: wrong\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
            viewer.host, viewer.origin
        );
        assert!(request(&viewer.host, &client_rejected).await.starts_with("HTTP/1.1 403"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn observed_handlers_map_corruption_and_capacity_failures_safely() {
        let corrupt = start_with(ReadFixture::failing(PortErrorKind::Corruption)).await;
        let cookie = authenticate(&corrupt).await;
        let raw = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&corrupt.host, &corrupt.origin)
        );
        let response = request(&corrupt.host, &raw).await;
        assert!(response.starts_with("HTTP/1.1 422"), "{response}");
        assert!(response.contains("requestId"));
        assert!(response.to_ascii_lowercase().contains("x-xtrace-request-id:"));
        assert!(!response.contains("PRIVATE_DATABASE_CANARY"));
        let _ = corrupt.shutdown.send(());
        corrupt.task.await.unwrap().unwrap();

        let unavailable = start_with(ReadFixture::failing(PortErrorKind::Resource)).await;
        let cookie = authenticate(&unavailable).await;
        let raw = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&unavailable.host, &unavailable.origin)
        );
        let response = request(&unavailable.host, &raw).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("requestId"));
        assert!(!response.contains("PRIVATE_DATABASE_CANARY"));
        assert_eq!(unavailable.observed_calls.load(Ordering::Acquire), 1);
        let _ = unavailable.shutdown.send(());
        unavailable.task.await.unwrap().unwrap();

        let saturated = start().await;
        let first_permit = saturated
            .query_lane
            .0
            .permits
            .clone()
            .try_acquire_owned()
            .expect("acquire first shared query permit");
        let second_permit = saturated
            .query_lane
            .0
            .permits
            .clone()
            .try_acquire_owned()
            .expect("acquire second shared query permit");
        let cookie = authenticate(&saturated).await;
        let raw = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&saturated.host, &saturated.origin)
        );
        let response = request(&saturated.host, &raw).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("XTR-VIEWER-QUERY-BUSY"));
        assert!(response.contains("requestId"));
        assert_eq!(saturated.observed_calls.load(Ordering::Acquire), 0);
        drop((first_permit, second_permit));
        let recovered = request(&saturated.host, &raw).await;
        assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
        assert_eq!(saturated.observed_calls.load(Ordering::Acquire), 1);
        let _ = saturated.shutdown.send(());
        saturated.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sqlite_identity_corruption_is_reported_by_the_authenticated_http_handler() {
        let scratch = std::path::PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        xtrace_private_storage::AdmittedPrivateRoot::open(&scratch)
            .expect("admitted private test scratch");
        let project_root = tempfile::Builder::new()
            .prefix("viewer-observed-corruption-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("temporary project root");
        #[cfg(unix)]
        std::fs::set_permissions(project_root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure temporary project root");
        let database = project_root.path().join("metadata.sqlite3");
        let store =
            SqliteStore::open(&database, OpenOptions::default()).expect("open fixture store");
        #[cfg(unix)]
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("secure temporary database");
        let timestamp = WallTime::from_parts(2026, 10, 3, 1, 2, 3, 0).expect("fixture time");
        let project = Project {
            id: ProjectId::new(),
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
            display_name: "fixture".to_owned(),
            created_at: timestamp,
            last_opened_at: timestamp,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        };
        store.project_repository().insert_project(&project).expect("insert fixture project");
        let persistence = SqliteRecordingPersistence::new(store.clone(), project_root.path());
        persistence
            .begin_recording(&BeginRecording {
                project_id: project.id(),
                recording_id: RecordingId::new(),
                runtime_session_id: RuntimeSessionId::new(),
                opened_at: timestamp,
                endpoint_observation: EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    application_component: Some("spring-fixture".to_owned()),
                    binding_key: Some("default".to_owned()),
                    method: "POST".to_owned(),
                    route_template: "/orders".to_owned(),
                },
            })
            .expect("persist linked observed recording");
        Connection::open(&database)
            .expect("open isolated corruption connection")
            .execute("UPDATE operations SET endpoint_fingerprint = ?1", params![vec![0xA5_u8; 32]])
            .expect("corrupt persisted endpoint identity");

        let reader = SqliteRecordingReader::new(store, project_root.path());
        let bound = BoundViewer::bind(
            RecordingQueryService::new(reader.clone()),
            ObservedEndpointQueryService::new(reader),
            project.id(),
        )
        .await
        .expect("bind viewer to SQLite reader");
        let ready = bound.readiness();
        let host = ready.origin.strip_prefix("http://").expect("loopback origin").to_owned();
        let token = ready.url.rsplit_once("token=").expect("bootstrap token").1.to_owned();
        let origin = ready.origin;
        let query_lane = bound.state.query_lane.clone();
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(bound.serve(async move {
            let _ = receiver.await;
        }));
        let viewer = RunningViewer {
            host,
            origin,
            token,
            observed_calls: Arc::new(AtomicUsize::new(0)),
            query_lane,
            shutdown,
            task,
        };
        let cookie = authenticate(&viewer).await;
        let raw = format!(
            "GET /api/v1/endpoints HTTP/1.1\r\n{}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            request_headers(&viewer.host, &viewer.origin)
        );
        let response = request(&viewer.host, &raw).await;
        assert!(response.starts_with("HTTP/1.1 422"), "{response}");
        assert!(response.contains("requestId"));
        assert!(response.to_ascii_lowercase().contains("x-xtrace-request-id:"));
        assert!(!response.contains("0xA5"));
        assert!(!response.contains("/fixture/repo"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn query_lane_offloads_bounds_saturation_and_drains_on_shutdown() {
        let lane = QueryLane::new(1);
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_started = started.clone();
        let active_lane = lane.clone();
        let active = tokio::spawn(async move {
            active_lane
                .run(move || {
                    worker_started.store(true, Ordering::Release);
                    std::thread::sleep(Duration::from_millis(150));
                    7
                })
                .await
        });
        timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking query worker starts");
        assert_eq!(lane.run(|| 9).await, Err(QueryLaneError::Busy));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(active.await.unwrap(), Ok(7));

        let shutdown_lane = QueryLane::new(1);
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_started = started.clone();
        let active_lane = shutdown_lane.clone();
        let active = tokio::spawn(async move {
            active_lane
                .run(move || {
                    worker_started.store(true, Ordering::Release);
                    std::thread::sleep(Duration::from_millis(50));
                })
                .await
        });
        timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown query starts");
        shutdown_lane.close();
        assert_eq!(shutdown_lane.run(|| ()).await, Err(QueryLaneError::Closed));
        timeout(Duration::from_secs(1), shutdown_lane.wait_drained())
            .await
            .expect("in-flight query drains");
        assert_eq!(active.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn saturated_query_lane_maps_to_safe_service_unavailable_problem() {
        let state = ViewerState {
            recording_service: RecordingQueryService::new(ReadFixture::default()),
            observed_service: ObservedEndpointQueryService::new(ReadFixture::default()),
            query_lane: QueryLane::new(0),
            project_id: ProjectId::new(),
            origin: "http://127.0.0.1:12345".to_owned(),
            host: "127.0.0.1:12345".to_owned(),
            bootstrap: tokio::sync::Mutex::new(None),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        };
        let response = run_recording_query(&state, CorrelationId::new(), || {
            Ok::<_, xtrace_domain::AppError>(())
        })
        .await
        .expect_err("zero query capacity rejects work");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("XTR-VIEWER-QUERY-BUSY"));
        assert!(body.contains("requestId"));
        assert!(!body.contains("SQLite"));
    }

    #[tokio::test]
    async fn http_limits_reject_oversized_uri_header_and_auth_body() {
        let viewer = start().await;
        let large_uri = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            "x".repeat(MAX_HEADER_BYTES),
            viewer.host
        );
        let response = wire_request(&viewer.host, &large_uri).await;
        assert!(response.is_err() || !response.unwrap().starts_with(b"HTTP/1.1 200"));

        let large_header = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nX-Padding: {}\r\nConnection: close\r\n\r\n",
            viewer.host,
            "x".repeat(MAX_HEADER_BYTES)
        );
        let response = wire_request(&viewer.host, &large_header).await;
        assert!(response.is_err() || !response.unwrap().starts_with(b"HTTP/1.1 200"));

        let body = format!("{{\"token\":\"{}\"}}{}", viewer.token, " ".repeat(1_024));
        let raw_request = format!(
            "POST /api/v1/auth/exchange HTTP/1.1\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            request_headers(&viewer.host, &viewer.origin),
            body.len(),
            body
        );
        let response = request(&viewer.host, &raw_request).await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        assert!(response.contains("application/problem+json"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn slow_http_request_is_terminated_by_the_configured_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ViewerState {
            recording_service: RecordingQueryService::new(ReadFixture::default()),
            observed_service: ObservedEndpointQueryService::new(ReadFixture::default()),
            query_lane: QueryLane::new(MAX_QUERY_CONCURRENCY),
            project_id: ProjectId::new(),
            origin: format!("http://{address}"),
            host: address.to_string(),
            bootstrap: tokio::sync::Mutex::new(None),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        });
        let service = ServiceBuilder::new()
            .layer(ConcurrencyLimitLayer::new(MAX_CONNECTIONS))
            .service(router(state));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection_with_timeout(stream, service, Duration::from_millis(80)).await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
        timeout(Duration::from_secs(1), server)
            .await
            .expect("connection deadline terminates slow client")
            .unwrap()
            .unwrap();
    }
}
