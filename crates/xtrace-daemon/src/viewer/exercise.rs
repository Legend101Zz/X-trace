//! Authenticated, project-scoped planning actions. No transport to an application.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use xtrace_application::exercise::{CreateExercisePlan, ExerciseError, MAX_PLAN_DOCUMENT_BYTES};
use xtrace_domain::CorrelationId;

use super::{
    ObservedEndpointReadPort, QueryLaneError, RecordingReadPort, ViewerState, authorize_api,
    is_json, problem_with_id, success_json, valid_request_origin,
};

/// Operations admitted from the private viewer session. A successful approval records consent.
pub enum ViewerExerciseAction {
    /// Create a new independent draft.
    Create(CreateExercisePlan),
    /// Supersede this exact original and permanently revoke its consent.
    Edit {
        /// Exact original that loses consent.
        hash: String,
        /// Independently reviewable replacement draft.
        replacement: CreateExercisePlan,
    },
    /// Pin the review to this exact immutable plan.
    Review {
        /// Immutable identity selected for review.
        hash: String,
    },
    /// Read the current private state without changing consent.
    Show {
        /// Immutable identity selected for inspection.
        hash: String,
    },
    /// Confirm the target and the exact items the operator reviewed.
    Approve {
        /// Exact reviewed immutable identity.
        hash: String,
        /// Independent UUID displayed alongside the reviewed hash.
        plan_id: String,
        /// Every item explicitly selected by the operator.
        item_ids: Vec<String>,
        /// Fresh confirmation that the target belongs to the operator.
        confirm_owned_development: bool,
    },
}

/// A project-bound planning capability supplied by the CLI composition root.
pub type ViewerExerciseHandler =
    Arc<dyn Fn(ViewerExerciseAction) -> Result<serde_json::Value, ExerciseError> + Send + Sync>;

pub(super) fn routes<P>(handler: Option<ViewerExerciseHandler>) -> Router<Arc<ViewerState<P>>>
where
    P: RecordingReadPort + ObservedEndpointReadPort + Clone + 'static,
{
    Router::new()
        .route("/api/v1/exercise/plans", post(create::<P>))
        .route("/api/v1/exercise/plans/:hash", get(show::<P>))
        .route("/api/v1/exercise/plans/:hash/:transition", post(transition::<P>))
        .layer(Extension(handler))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    plan_id: String,
    item_ids: Vec<String>,
    confirm_owned_development: bool,
}

enum RequestAction {
    Create,
    Show(String),
    Transition(String, String),
}

async fn create<P>(
    State(state): State<Arc<ViewerState<P>>>,
    Extension(handler): Extension<Option<ViewerExerciseHandler>>,
    request: Request<Body>,
) -> Response {
    dispatch(state, handler, RequestAction::Create, request).await
}

async fn show<P>(
    State(state): State<Arc<ViewerState<P>>>,
    Extension(handler): Extension<Option<ViewerExerciseHandler>>,
    Path(hash): Path<String>,
    request: Request<Body>,
) -> Response {
    dispatch(state, handler, RequestAction::Show(hash), request).await
}

async fn transition<P>(
    State(state): State<Arc<ViewerState<P>>>,
    Extension(handler): Extension<Option<ViewerExerciseHandler>>,
    Path((hash, transition)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    dispatch(state, handler, RequestAction::Transition(hash, transition), request).await
}

async fn dispatch<P>(
    state: Arc<ViewerState<P>>,
    handler: Option<ViewerExerciseHandler>,
    action: RequestAction,
    request: Request<Body>,
) -> Response {
    let id = CorrelationId::new();
    let headers = request.headers();
    if let Err(response) = authorize_api(&state, headers, id).await {
        return response;
    }
    let write = !matches!(action, RequestAction::Show(_));
    if write && !valid_request_origin(headers, &state.host, &state.origin, false) {
        return problem_with_id(
            StatusCode::FORBIDDEN,
            "XTR-VIEWER-ORIGIN",
            "Request origin is not accepted",
            id,
        );
    }
    if request.uri().query().is_some() || (write && !is_json(headers)) {
        return exercise_problem(ExerciseError::InvalidInput, id);
    }
    let Some(handler) = handler else {
        return problem_with_id(
            StatusCode::SERVICE_UNAVAILABLE,
            "XTR-EXERCISE-UNAVAILABLE",
            "Exercise planning is unavailable for this viewer",
            id,
        );
    };
    let max = if write { MAX_PLAN_DOCUMENT_BYTES } else { 0 };
    let Ok(bytes) = to_bytes(request.into_body(), max).await else {
        return exercise_problem(ExerciseError::InvalidInput, id);
    };
    if write && bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return exercise_problem(ExerciseError::InvalidInput, id);
    }
    let parsed = match action {
        RequestAction::Create => serde_json::from_slice(&bytes).map(ViewerExerciseAction::Create),
        RequestAction::Show(hash) => Ok(ViewerExerciseAction::Show { hash }),
        RequestAction::Transition(hash, transition) => match transition.as_str() {
            "edit" => serde_json::from_slice(&bytes)
                .map(|replacement| ViewerExerciseAction::Edit { hash, replacement }),
            "review" => serde_json::from_slice::<Review>(&bytes)
                .map(|_| ViewerExerciseAction::Review { hash }),
            "approve" => serde_json::from_slice::<Approval>(&bytes).map(|approval| {
                ViewerExerciseAction::Approve {
                    hash,
                    plan_id: approval.plan_id,
                    item_ids: approval.item_ids,
                    confirm_owned_development: approval.confirm_owned_development,
                }
            }),
            _ => {
                return problem_with_id(
                    StatusCode::NOT_FOUND,
                    "XTR-VIEWER-ROUTE",
                    "Requested viewer resource was not found",
                    id,
                );
            }
        },
    };
    let Ok(action) = parsed else { return exercise_problem(ExerciseError::InvalidInput, id) };
    match state.query_lane.run(move || handler(action)).await {
        Ok(Ok(document)) => success_json(document, id),
        Ok(Err(error)) => exercise_problem(error, id),
        Err(QueryLaneError::Busy | QueryLaneError::Closed) => problem_with_id(
            StatusCode::SERVICE_UNAVAILABLE,
            "XTR-VIEWER-QUERY-BUSY",
            "Viewer query capacity is unavailable",
            id,
        ),
        Err(QueryLaneError::Join) => problem_with_id(
            StatusCode::INTERNAL_SERVER_ERROR,
            "XTR-VIEWER-QUERY-FAILED",
            "Exercise plan operation could not be completed",
            id,
        ),
    }
}

fn exercise_problem(error: ExerciseError, id: CorrelationId) -> Response {
    use ExerciseError as E;
    let (status, code) = match error {
        E::InvalidInput => (StatusCode::BAD_REQUEST, "XTR-EXERCISE-INPUT"),
        E::BindingUnavailable => (StatusCode::NOT_FOUND, "XTR-EXERCISE-BINDING"),
        E::NotFound => (StatusCode::NOT_FOUND, "XTR-EXERCISE-NOT-FOUND"),
        E::StorageUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "XTR-EXERCISE-STORAGE"),
        E::StagingOccupied => (StatusCode::CONFLICT, "XTR-EXERCISE-STAGING"),
        E::Conflict => (StatusCode::CONFLICT, "XTR-EXERCISE-CONFLICT"),
        E::HashMismatch => (StatusCode::CONFLICT, "XTR-EXERCISE-HASH"),
        E::Expired => (StatusCode::GONE, "XTR-EXERCISE-EXPIRED"),
        E::UnresolvedInput => (StatusCode::UNPROCESSABLE_ENTITY, "XTR-EXERCISE-UNRESOLVED"),
        E::ApprovalRequired => (StatusCode::CONFLICT, "XTR-EXERCISE-APPROVAL"),
        E::CredentialValue => (StatusCode::UNPROCESSABLE_ENTITY, "XTR-EXERCISE-CREDENTIAL"),
        E::Superseded => (StatusCode::CONFLICT, "XTR-EXERCISE-SUPERSEDED"),
        E::AlreadyConsumed => (StatusCode::CONFLICT, "XTR-EXERCISE-CONSUMED"),
    };
    super::problem_with_dynamic_code(
        status,
        status.canonical_reason().unwrap_or("Error"),
        &error.to_string(),
        code,
        id,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "test assertions")]

    use super::*;
    use crate::session_health_tests::HealthFixture;
    use crate::viewer::{self, BootstrapState, QueryLane, SESSION_COOKIE};
    use axum::http::header;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use xtrace_application::{ObservedEndpointQueryService, RecordingQueryService};
    use xtrace_store::SqliteRecordingReader;

    #[tokio::test]
    async fn authenticated_five_plan_routes_preserve_exact_actions_and_private_responses() {
        let fixture = HealthFixture::new();
        let reader = SqliteRecordingReader::new(fixture.store.clone(), fixture.root.path());
        let state = Arc::new(ViewerState {
            recording_service: RecordingQueryService::new(reader.clone()),
            observed_service: ObservedEndpointQueryService::new(reader),
            query_lane: QueryLane::new(2),
            catalog_exports: None,
            export_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            project_id: fixture.project_id,
            origin: "http://127.0.0.1:43123".to_owned(),
            host: "127.0.0.1:43123".to_owned(),
            bootstrap: tokio::sync::Mutex::new(None::<BootstrapState>),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        });
        let session = [23_u8; 32];
        state
            .sessions
            .lock()
            .await
            .insert(*blake3::hash(&session).as_bytes(), Instant::now() + Duration::from_secs(60));
        let original = "a".repeat(64);
        let replacement = "b".repeat(64);
        let plan_id = "00000000-0000-4000-8000-000000000001";
        let body = serde_json::json!({
            "revision_id":"00000000-0000-4000-8000-000000000002",
            "operation_id":"00000000-0000-4000-8000-000000000003",
            "selected_operation_version_id":"version-one",
            "recording_id":"00000000-0000-4000-8000-000000000004",
            "target":{"base_url":"http://127.0.0.1:43210","operator_owned_development":true},
            "inputs":[{"name":"item","location":"query","required":true,
                "value":{"source":"operator","value":"private-input-canary"}}],
            "body":{"source":"operator","content_type":"text/plain","content":"private-body-canary"},
            "lifetime_seconds":300
        });
        let mut edited = body.clone();
        edited["lifetime_seconds"] = 120.into();
        edited["selected_operation_version_id"] = "version-two".into();
        let expected_create = body.clone();
        let expected_edit = edited.clone();
        let old_hash = original.clone();
        let new_hash = replacement.clone();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let handler: ViewerExerciseHandler = Arc::new(move |action| {
            let (name, hash) = match action {
                ViewerExerciseAction::Create(plan) => {
                    assert_eq!(serde_json::to_value(plan).unwrap(), expected_create);
                    ("create", old_hash.as_str())
                }
                ViewerExerciseAction::Show { hash } => {
                    assert_eq!(hash, new_hash);
                    ("show", new_hash.as_str())
                }
                ViewerExerciseAction::Edit { hash, replacement } => {
                    assert_eq!(hash, old_hash);
                    assert_eq!(serde_json::to_value(replacement).unwrap(), expected_edit);
                    ("edit", new_hash.as_str())
                }
                ViewerExerciseAction::Review { hash } => {
                    assert_eq!(hash, new_hash);
                    ("review", new_hash.as_str())
                }
                ViewerExerciseAction::Approve {
                    hash,
                    plan_id: actual,
                    item_ids,
                    confirm_owned_development,
                } => {
                    assert_eq!(hash, new_hash);
                    assert_eq!(actual, plan_id);
                    assert_eq!(item_ids, ["item-one", "item-two"]);
                    assert!(confirm_owned_development);
                    ("approve", new_hash.as_str())
                }
            };
            observed.lock().unwrap().push(name);
            Ok(
                serde_json::json!({"action":name,"plan_id":plan_id,"plan_hash":hash,"requests_sent":0}),
            )
        });
        let paths = [
            ("POST", "/api/v1/exercise/plans".to_owned(), Some(body), "create", original.clone()),
            (
                "POST",
                format!("/api/v1/exercise/plans/{original}/edit"),
                Some(edited),
                "edit",
                replacement.clone(),
            ),
            (
                "GET",
                format!("/api/v1/exercise/plans/{replacement}"),
                None,
                "show",
                replacement.clone(),
            ),
            (
                "POST",
                format!("/api/v1/exercise/plans/{replacement}/review"),
                Some(serde_json::json!({})),
                "review",
                replacement.clone(),
            ),
            (
                "POST",
                format!("/api/v1/exercise/plans/{replacement}/approve"),
                Some(
                    serde_json::json!({"plan_id":plan_id,"item_ids":["item-one","item-two"],"confirm_owned_development":true}),
                ),
                "approve",
                replacement.clone(),
            ),
        ];
        for (method, path, body, action, hash) in paths {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, &state.host)
                .header(header::ORIGIN, &state.origin)
                .header("sec-fetch-site", "same-origin")
                .header("x-xtrace-client", "viewer-v1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={}", URL_SAFE_NO_PAD.encode(session)),
                )
                .body(Body::from(body.map(|value| value.to_string()).unwrap_or_default()))
                .unwrap();
            let response = tower::Service::call(
                &mut viewer::router(state.clone(), Some(handler.clone())),
                request,
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("private-input-canary"));
            assert!(!text.contains("private-body-canary"));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"action":action,"plan_id":plan_id,"plan_hash":hash,"requests_sent":0})
            );
        }
        assert_eq!(*calls.lock().unwrap(), ["create", "edit", "show", "review", "approve"]);
    }
}
