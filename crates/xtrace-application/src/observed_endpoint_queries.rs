//! Shared, bounded projections for the observed endpoint catalog.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    AppError, CorrelationId, ErrorCategory, ErrorCode, OperationId, ProjectId, RecordingId,
    RetryAdvice, WallTime,
};

use crate::{
    PortError,
    recording_queries::{RecordingCompletionEvidence, RecordingMetadata, RecordingStatus},
};

/// Default and maximum endpoint page sizes.
pub const DEFAULT_OBSERVED_ENDPOINT_LIMIT: u32 = 50;
/// Maximum number of endpoints in one page.
pub const MAX_OBSERVED_ENDPOINT_LIMIT: u32 = 100;
/// Default recording page size for linked and unmatched recordings.
pub const DEFAULT_OBSERVED_RECORDING_LIMIT: u32 = 25;
/// Maximum linked or unmatched recording page size.
pub const MAX_OBSERVED_RECORDING_LIMIT: u32 = 50;
const MAX_CURSOR_BYTES: usize = 2048;

/// Full endpoint ordering key used for keyset pagination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedEndpointKey {
    /// Canonical HTTP method.
    pub method: String,
    /// Exact allowlisted route template.
    pub route_template: String,
    /// Run-scoped application component.
    pub application_component: String,
    /// Run-scoped binding key.
    pub binding: String,
    /// Public operation identity.
    pub operation_id: OperationId,
}

/// Stable safe facts returned by an endpoint read port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedEndpointRecord {
    /// Public operation identity.
    pub operation_id: OperationId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Application component in endpoint identity.
    pub application_component: String,
    /// Binding in endpoint identity.
    pub binding: String,
    /// Canonical HTTP method.
    pub method: String,
    /// Exact observed route template.
    pub route_template: String,
    /// Accepted observation policy.
    pub observation_policy: String,
}

/// Stable recording key for descending opening time and recording ID order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRecordingKey {
    /// Persisted opening wall time.
    pub opened_at: String,
    /// Stable recording identity.
    pub recording_id: RecordingId,
}

/// Safe recording facts plus endpoint association facts from the read port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRecordingRecord {
    /// Existing safe recording summary.
    pub metadata: RecordingMetadata,
    /// Linked operation, or none for unmatched/legacy rows.
    pub operation_id: Option<OperationId>,
    /// Accepted policy for the disposition, absent on legacy or policy-free rows.
    pub observation_policy: Option<String>,
    /// Allowlisted reason for new unmatched rows; absent for legacy rows.
    pub unmatched_reason: Option<String>,
}

/// Application-owned read contract implemented by SQLite.
pub trait ObservedEndpointReadPort: Send + Sync {
    /// Reads at most `limit + 1` project-scoped observed endpoints after `after`.
    fn list_observed_endpoints(
        &self,
        project_id: ProjectId,
        after: Option<&ObservedEndpointKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedEndpointRecord>, bool), PortError>;
    /// Reads linked recordings for one project-owned operation.
    fn list_operation_recordings(
        &self,
        project_id: ProjectId,
        operation_id: OperationId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError>;
    /// Reads legacy and newly unmatched recordings for one project.
    fn list_unmatched_recordings(
        &self,
        project_id: ProjectId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError>;
}

/// Request to list observed endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListObservedEndpoints {
    /// Project whose catalog is read.
    pub project_id: ProjectId,
    /// Optional page size; omitted requests use 50.
    pub limit: Option<u32>,
    /// Opaque cursor returned by an earlier page.
    pub cursor: Option<String>,
}

/// Request to list recordings linked to one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListOperationRecordings {
    /// Project whose recordings are read.
    pub project_id: ProjectId,
    /// Project-scoped operation identity.
    pub operation_id: OperationId,
    /// Optional page size; omitted requests use 25.
    pub limit: Option<u32>,
    /// Opaque cursor returned by an earlier page.
    pub cursor: Option<String>,
}

/// Request to list unmatched and legacy recordings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListUnmatchedRecordings {
    /// Project whose recordings are read.
    pub project_id: ProjectId,
    /// Optional page size; omitted requests use 25.
    pub limit: Option<u32>,
    /// Opaque cursor returned by an earlier page.
    pub cursor: Option<String>,
}

/// Safe endpoint projection serialized with lowerCamelCase fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedEndpointDto {
    /// Public operation UUIDv7.
    pub operation_id: OperationId,
    /// Owning project UUIDv7.
    pub project_id: ProjectId,
    /// Component included in endpoint identity.
    pub application_component: String,
    /// Binding included in endpoint identity.
    pub binding: String,
    /// Canonical method.
    pub method: String,
    /// Exact matched route template.
    pub route_template: String,
    /// Fixed truth label for this projection.
    pub observation: String,
    /// Operator-selected policy used to accept this observation.
    pub observation_policy: String,
}

/// Safe recording projection with explicit endpoint disposition fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedRecordingDto {
    /// Stable recording identity.
    pub recording_id: RecordingId,
    /// Persisted lifecycle state.
    pub status: RecordingStatus,
    /// Completion state established from validated durable finish evidence.
    pub completion: RecordingCompletionEvidence,
    /// Persisted opening wall time.
    pub opened_at: String,
    /// Number of durable segments.
    pub segment_count: String,
    /// Number of durable events.
    pub event_count: String,
    /// First persisted sequence, if present.
    pub first_sequence: Option<String>,
    /// Last persisted sequence, if present.
    pub last_sequence: Option<String>,
    /// Persisted incomplete evidence.
    pub incomplete_evidence: Vec<String>,
    /// Operation identity when the recording has a valid linked observation.
    pub operation_id: Option<OperationId>,
    /// Accepted policy retained with the observation.
    pub observation_policy: Option<String>,
    /// Safe allowlisted reason for a new unmatched observation.
    pub unmatched_reason: Option<String>,
}

/// A bounded endpoint page serialized as `{items,nextCursor}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedEndpointPage {
    /// Returned endpoint summaries.
    pub items: Vec<ObservedEndpointDto>,
    /// Opaque continuation token, absent when there is no next page.
    pub next_cursor: Option<String>,
}

/// A bounded recording page serialized as `{items,nextCursor}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedRecordingPage {
    /// Returned safe recording summaries.
    pub items: Vec<ObservedRecordingDto>,
    /// Opaque continuation token, absent when there is no next page.
    pub next_cursor: Option<String>,
}

/// Shared framework-neutral service for all observed catalog queries.
#[derive(Clone)]
pub struct ObservedEndpointQueryService<P> {
    port: P,
}

impl<P: ObservedEndpointReadPort> ObservedEndpointQueryService<P> {
    /// Creates the shared service over a typed read port.
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Lists observed endpoints in stable endpoint order.
    pub fn list_observed_endpoints(
        &self,
        request: ListObservedEndpoints,
        correlation_id: CorrelationId,
    ) -> Result<ObservedEndpointPage, AppError> {
        let limit = validate_limit(
            request.limit.unwrap_or(DEFAULT_OBSERVED_ENDPOINT_LIMIT),
            MAX_OBSERVED_ENDPOINT_LIMIT,
            correlation_id,
        )?;
        let after = request
            .cursor
            .as_deref()
            .map(decode_endpoint_cursor)
            .transpose()
            .map_err(|()| cursor_error(correlation_id))?;
        if after.as_ref().is_some_and(|cursor| cursor.project_id != request.project_id) {
            return Err(cursor_error(correlation_id));
        }
        let (rows, has_more) = self
            .port
            .list_observed_endpoints(
                request.project_id,
                after.as_ref().map(|cursor| &cursor.last),
                limit,
            )
            .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_endpoint_cursor(request.project_id, endpoint_key(row), correlation_id)
                })
                .transpose()?
        } else {
            None
        };
        Ok(ObservedEndpointPage {
            items: rows.into_iter().map(endpoint_dto).collect(),
            next_cursor,
        })
    }

    /// Lists recordings linked to one operation in stable descending order.
    pub fn list_operation_recordings(
        &self,
        request: ListOperationRecordings,
        correlation_id: CorrelationId,
    ) -> Result<ObservedRecordingPage, AppError> {
        if request.operation_id.as_uuid().get_version_num() != 7
            || request.operation_id.as_uuid().get_variant() != uuid::Variant::RFC4122
        {
            return Err(query_error(correlation_id));
        }
        let limit = validate_limit(
            request.limit.unwrap_or(DEFAULT_OBSERVED_RECORDING_LIMIT),
            MAX_OBSERVED_RECORDING_LIMIT,
            correlation_id,
        )?;
        let after = request
            .cursor
            .as_deref()
            .map(|token| {
                decode_recording_cursor(
                    token,
                    QueryKind::Operation,
                    request.project_id,
                    Some(request.operation_id),
                )
            })
            .transpose()
            .map_err(|()| cursor_error(correlation_id))?;
        let (rows, has_more) = self
            .port
            .list_operation_recordings(
                request.project_id,
                request.operation_id,
                after.as_ref().map(|cursor| &cursor.last),
                limit,
            )
            .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_recording_cursor(
                        QueryKind::Operation,
                        request.project_id,
                        Some(request.operation_id),
                        recording_key(row),
                        correlation_id,
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(ObservedRecordingPage {
            items: rows.into_iter().map(recording_dto).collect(),
            next_cursor,
        })
    }

    /// Lists unmatched sidecar rows and legacy sidecar-absent recordings.
    pub fn list_unmatched_recordings(
        &self,
        request: ListUnmatchedRecordings,
        correlation_id: CorrelationId,
    ) -> Result<ObservedRecordingPage, AppError> {
        let limit = validate_limit(
            request.limit.unwrap_or(DEFAULT_OBSERVED_RECORDING_LIMIT),
            MAX_OBSERVED_RECORDING_LIMIT,
            correlation_id,
        )?;
        let after = request
            .cursor
            .as_deref()
            .map(|token| {
                decode_recording_cursor(token, QueryKind::Unmatched, request.project_id, None)
            })
            .transpose()
            .map_err(|()| cursor_error(correlation_id))?;
        let (rows, has_more) = self
            .port
            .list_unmatched_recordings(
                request.project_id,
                after.as_ref().map(|cursor| &cursor.last),
                limit,
            )
            .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_recording_cursor(
                        QueryKind::Unmatched,
                        request.project_id,
                        None,
                        recording_key(row),
                        correlation_id,
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(ObservedRecordingPage {
            items: rows.into_iter().map(recording_dto).collect(),
            next_cursor,
        })
    }
}

fn endpoint_key(row: &ObservedEndpointRecord) -> ObservedEndpointKey {
    ObservedEndpointKey {
        method: row.method.clone(),
        route_template: row.route_template.clone(),
        application_component: row.application_component.clone(),
        binding: row.binding.clone(),
        operation_id: row.operation_id,
    }
}
fn recording_key(row: &ObservedRecordingRecord) -> ObservedRecordingKey {
    ObservedRecordingKey {
        opened_at: row.metadata.opened_at.clone(),
        recording_id: row.metadata.recording_id,
    }
}
fn endpoint_dto(row: ObservedEndpointRecord) -> ObservedEndpointDto {
    ObservedEndpointDto {
        operation_id: row.operation_id,
        project_id: row.project_id,
        application_component: row.application_component,
        binding: row.binding,
        method: row.method,
        route_template: row.route_template,
        observation: "observed".to_owned(),
        observation_policy: row.observation_policy,
    }
}
fn recording_dto(row: ObservedRecordingRecord) -> ObservedRecordingDto {
    ObservedRecordingDto {
        recording_id: row.metadata.recording_id,
        status: row.metadata.status,
        completion: row.metadata.completion,
        opened_at: row.metadata.opened_at,
        segment_count: row.metadata.segment_count,
        event_count: row.metadata.event_count,
        first_sequence: row.metadata.first_sequence,
        last_sequence: row.metadata.last_sequence,
        incomplete_evidence: row.metadata.incomplete_evidence,
        operation_id: row.operation_id,
        observation_policy: row.observation_policy,
        unmatched_reason: row.unmatched_reason,
    }
}

fn validate_limit(
    limit: u32,
    maximum: u32,
    correlation_id: CorrelationId,
) -> Result<u32, AppError> {
    if limit == 0 || limit > maximum { Err(query_error(correlation_id)) } else { Ok(limit) }
}
fn query_error(correlation_id: CorrelationId) -> AppError {
    AppError::new(
        ErrorCode::new("XTR-VALIDATION-ENDPOINT-QUERY"),
        ErrorCategory::Validation,
        "observed endpoint query limit is outside supported bounds",
        RetryAdvice::None,
        correlation_id,
    )
}
fn cursor_error(correlation_id: CorrelationId) -> AppError {
    AppError::new(
        ErrorCode::new("XTR-VALIDATION-ENDPOINT-CURSOR"),
        ErrorCategory::Validation,
        "observed endpoint cursor is malformed or belongs to a different query",
        RetryAdvice::None,
        correlation_id,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum QueryKind {
    Endpoints,
    Operation,
    Unmatched,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointCursor {
    version: u32,
    kind: QueryKind,
    project_id: String,
    filter: String,
    sort: String,
    last: EndpointCursorKey,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointCursorKey {
    method: String,
    route_template: String,
    application_component: String,
    binding: String,
    operation_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordingCursor {
    version: u32,
    kind: QueryKind,
    project_id: String,
    operation_id: Option<String>,
    filter: String,
    sort: String,
    last: RecordingCursorKey,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordingCursorKey {
    opened_at: String,
    recording_id: String,
}

fn encode_endpoint_cursor(
    project_id: ProjectId,
    last: ObservedEndpointKey,
    correlation_id: CorrelationId,
) -> Result<String, AppError> {
    let cursor = EndpointCursor {
        version: 1,
        kind: QueryKind::Endpoints,
        project_id: project_id.to_string(),
        filter: "observed".to_owned(),
        sort: "method_route_component_binding_operation_id_asc".to_owned(),
        last: EndpointCursorKey {
            method: last.method,
            route_template: last.route_template,
            application_component: last.application_component,
            binding: last.binding,
            operation_id: last.operation_id.to_string(),
        },
    };
    encode_json(&cursor).map_err(|()| cursor_error(correlation_id))
}
fn decode_endpoint_cursor(token: &str) -> Result<DecodedEndpointCursor, ()> {
    let value: EndpointCursor = decode_json(token)?;
    if value.version != 1
        || value.kind != QueryKind::Endpoints
        || value.filter != "observed"
        || value.sort != "method_route_component_binding_operation_id_asc"
    {
        return Err(());
    }
    let project_id = canonical_id::<ProjectId>(&value.project_id)?;
    let operation_id = canonical_id::<OperationId>(&value.last.operation_id)?;
    if operation_id.as_uuid().get_version_num() != 7
        || operation_id.as_uuid().get_variant() != uuid::Variant::RFC4122
    {
        return Err(());
    }
    if value.last.method != "POST"
        || value.last.route_template != "/orders"
        || value.last.application_component != "spring-fixture"
        || value.last.binding != "default"
    {
        return Err(());
    }
    Ok(DecodedEndpointCursor {
        project_id,
        last: ObservedEndpointKey {
            method: value.last.method,
            route_template: value.last.route_template,
            application_component: value.last.application_component,
            binding: value.last.binding,
            operation_id,
        },
    })
}
struct DecodedEndpointCursor {
    project_id: ProjectId,
    last: ObservedEndpointKey,
}

fn encode_recording_cursor(
    kind: QueryKind,
    project_id: ProjectId,
    operation_id: Option<OperationId>,
    last: ObservedRecordingKey,
    correlation_id: CorrelationId,
) -> Result<String, AppError> {
    let filter =
        if kind == QueryKind::Unmatched { "unmatched_or_legacy" } else { "operation_linked" };
    let cursor = RecordingCursor {
        version: 1,
        kind,
        project_id: project_id.to_string(),
        operation_id: operation_id.map(|id| id.to_string()),
        filter: filter.to_owned(),
        sort: "opened_at_recording_id_desc".to_owned(),
        last: RecordingCursorKey {
            opened_at: last.opened_at,
            recording_id: last.recording_id.to_string(),
        },
    };
    encode_json(&cursor).map_err(|()| cursor_error(correlation_id))
}
fn decode_recording_cursor(
    token: &str,
    kind: QueryKind,
    project_id: ProjectId,
    operation_id: Option<OperationId>,
) -> Result<DecodedRecordingCursor, ()> {
    let value: RecordingCursor = decode_json(token)?;
    let filter =
        if kind == QueryKind::Unmatched { "unmatched_or_legacy" } else { "operation_linked" };
    if value.version != 1
        || value.kind != kind
        || value.filter != filter
        || value.sort != "opened_at_recording_id_desc"
        || value.project_id != project_id.to_string()
        || value.operation_id.as_deref() != operation_id.map(|id| id.to_string()).as_deref()
    {
        return Err(());
    }
    let cursor_project = canonical_id::<ProjectId>(&value.project_id)?;
    if cursor_project != project_id {
        return Err(());
    }
    let recording_id = canonical_id::<RecordingId>(&value.last.recording_id)?;
    let recording_uuid = recording_id.as_uuid();
    if !matches!(recording_uuid.get_version_num(), 4 | 7)
        || recording_uuid.get_variant() != uuid::Variant::RFC4122
    {
        return Err(());
    }
    if value.last.opened_at.len() > 64 {
        return Err(());
    }
    let opened_at = value.last.opened_at.parse::<WallTime>().map_err(|_| ())?;
    if opened_at.to_rfc3339() != value.last.opened_at {
        return Err(());
    }
    Ok(DecodedRecordingCursor {
        last: ObservedRecordingKey { opened_at: value.last.opened_at, recording_id },
    })
}
struct DecodedRecordingCursor {
    last: ObservedRecordingKey,
}

fn canonical_id<T>(value: &str) -> Result<T, ()>
where
    T: std::str::FromStr + ToString,
{
    let parsed = value.parse::<T>().map_err(|_| ())?;
    if parsed.to_string() != value {
        return Err(());
    }
    Ok(parsed)
}
fn encode_json<T: Serialize>(value: &T) -> Result<String, ()> {
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).map_err(|_| ())?);
    if token.len() > MAX_CURSOR_BYTES {
        return Err(());
    }
    Ok(token)
}
fn decode_json<T>(token: &str) -> Result<T, ()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if token.is_empty() || token.len() > MAX_CURSOR_BYTES || token.contains('=') {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(());
    }
    let value: T = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if serde_json::to_vec(&value).map_err(|_| ())? != bytes {
        return Err(());
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "fixed query fixtures")]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type FakeCall = (String, u32, Option<String>);

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<FakeCall>>>,
        has_more: bool,
        empty: bool,
    }
    impl ObservedEndpointReadPort for Fake {
        fn list_observed_endpoints(
            &self,
            project_id: ProjectId,
            after: Option<&ObservedEndpointKey>,
            limit: u32,
        ) -> Result<(Vec<ObservedEndpointRecord>, bool), PortError> {
            self.calls.lock().expect("lock").push((
                "endpoints".into(),
                limit,
                after.map(|key| key.operation_id.to_string()),
            ));
            let op = OperationId::new();
            let rows = if self.empty {
                Vec::new()
            } else {
                vec![ObservedEndpointRecord {
                    operation_id: op,
                    project_id,
                    application_component: "spring-fixture".into(),
                    binding: "default".into(),
                    method: "POST".into(),
                    route_template: "/orders".into(),
                    observation_policy: "spring-orders-v1".into(),
                }]
            };
            Ok((rows, self.has_more && !self.empty))
        }
        fn list_operation_recordings(
            &self,
            _project_id: ProjectId,
            _operation_id: OperationId,
            after: Option<&ObservedRecordingKey>,
            limit: u32,
        ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
            self.calls.lock().expect("lock").push((
                "operation".into(),
                limit,
                after.map(|key| key.recording_id.to_string()),
            ));
            Ok((Vec::new(), false))
        }
        fn list_unmatched_recordings(
            &self,
            _project_id: ProjectId,
            after: Option<&ObservedRecordingKey>,
            limit: u32,
        ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
            self.calls.lock().expect("lock").push((
                "unmatched".into(),
                limit,
                after.map(|key| key.recording_id.to_string()),
            ));
            Ok((Vec::new(), false))
        }
    }
    #[test]
    fn defaults_page_shape_and_bounds_are_explicit() {
        let fake = Fake::default();
        let service = ObservedEndpointQueryService::new(fake.clone());
        let project = ProjectId::new();
        let page = service
            .list_observed_endpoints(
                ListObservedEndpoints { project_id: project, limit: None, cursor: None },
                CorrelationId::new(),
            )
            .expect("page");
        assert_eq!(page.items.len(), 1);
        assert!(page.next_cursor.is_none());
        assert_eq!(fake.calls.lock().expect("lock")[0], ("endpoints".into(), 50, None));
        let json = serde_json::to_value(page).expect("serialize");
        assert!(json.get("items").is_some());
        assert!(json.get("nextCursor").is_some());
        let endpoint_keys = json["items"][0]
            .as_object()
            .expect("endpoint object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            endpoint_keys,
            [
                "applicationComponent",
                "binding",
                "method",
                "observation",
                "observationPolicy",
                "operationId",
                "projectId",
                "routeTemplate"
            ]
            .into_iter()
            .collect()
        );
        for limit in [Some(0), Some(MAX_OBSERVED_ENDPOINT_LIMIT + 1)] {
            assert!(
                service
                    .list_observed_endpoints(
                        ListObservedEndpoints { project_id: project, limit, cursor: None },
                        CorrelationId::new()
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn endpoint_cursor_round_trips_and_rejects_noncanonical_or_wrong_scope() {
        let project = ProjectId::new();
        let operation_id = OperationId::new();
        let token = encode_endpoint_cursor(
            project,
            ObservedEndpointKey {
                method: "POST".into(),
                route_template: "/orders".into(),
                application_component: "spring-fixture".into(),
                binding: "default".into(),
                operation_id,
            },
            CorrelationId::new(),
        )
        .expect("encode");
        let decoded = decode_endpoint_cursor(&token).expect("cursor");
        assert_eq!(decoded.project_id, project);
        assert_eq!(decoded.last.operation_id, operation_id);
        assert!(decode_endpoint_cursor(&(token.clone() + "=")).is_err());
        assert!(decode_endpoint_cursor(&token[..token.len() - 1]).is_err());
        let mut unknown = EndpointCursor {
            version: 1,
            kind: QueryKind::Endpoints,
            project_id: project.to_string(),
            filter: "observed".into(),
            sort: "method_route_component_binding_operation_id_asc".into(),
            last: EndpointCursorKey {
                method: "POST".into(),
                route_template: "/orders".into(),
                application_component: "spring-fixture".into(),
                binding: "default".into(),
                operation_id: operation_id.to_string(),
            },
        };
        unknown.version = 2;
        assert!(decode_endpoint_cursor(&encode_json(&unknown).expect("encode stale")).is_err());
        let mut edited = EndpointCursor {
            version: 1,
            kind: QueryKind::Endpoints,
            project_id: project.to_string(),
            filter: "observed".into(),
            sort: "method_route_component_binding_operation_id_asc".into(),
            last: EndpointCursorKey {
                method: "POST".into(),
                route_template: "/orders".into(),
                application_component: "spring-fixture".into(),
                binding: "default".into(),
                operation_id: OperationId::new().to_string(),
            },
        };
        let edited_token = encode_json(&edited).expect("encode edited");
        let edited_position =
            decode_endpoint_cursor(&edited_token).expect("edited position remains valid");
        assert_eq!(edited_position.project_id, project);
        edited.last.route_template = "/private-canary".into();
        assert!(
            decode_endpoint_cursor(&encode_json(&edited).expect("encode invalid key")).is_err()
        );
        let duplicate = format!(
            "{{\"version\":1,\"version\":1,\"kind\":\"endpoints\",\"project_id\":\"{}\",\"filter\":\"observed\",\"sort\":\"method_route_component_binding_operation_id_asc\",\"last\":{{\"method\":\"POST\",\"route_template\":\"/orders\",\"application_component\":\"spring-fixture\",\"binding\":\"default\",\"operation_id\":\"{}\"}}}}",
            project, operation_id
        );
        assert!(decode_endpoint_cursor(&URL_SAFE_NO_PAD.encode(duplicate)).is_err());
        let extra = format!(
            "{{\"version\":1,\"kind\":\"endpoints\",\"project_id\":\"{}\",\"filter\":\"observed\",\"sort\":\"method_route_component_binding_operation_id_asc\",\"last\":{{\"method\":\"POST\",\"route_template\":\"/orders\",\"application_component\":\"spring-fixture\",\"binding\":\"default\",\"operation_id\":\"{}\"}},\"extra\":true}}",
            project, operation_id
        );
        assert!(decode_endpoint_cursor(&URL_SAFE_NO_PAD.encode(extra)).is_err());
    }

    #[test]
    fn service_uses_next_cursor_scope_and_returns_empty_pages() {
        let fake = Fake { has_more: true, ..Fake::default() };
        let service = ObservedEndpointQueryService::new(fake.clone());
        let project = ProjectId::new();
        let first = service
            .list_observed_endpoints(
                ListObservedEndpoints { project_id: project, limit: Some(7), cursor: None },
                CorrelationId::new(),
            )
            .expect("first page");
        let token = first.next_cursor.expect("next cursor");
        let second = service
            .list_observed_endpoints(
                ListObservedEndpoints { project_id: project, limit: Some(7), cursor: Some(token) },
                CorrelationId::new(),
            )
            .expect("second page");
        assert!(second.next_cursor.is_some());
        let calls = fake.calls.lock().expect("calls");
        assert_eq!(calls[0].1, 7);
        assert!(calls[1].2.is_some());
        drop(calls);

        let empty_service =
            ObservedEndpointQueryService::new(Fake { empty: true, ..Fake::default() });
        let empty = empty_service
            .list_observed_endpoints(
                ListObservedEndpoints { project_id: project, limit: None, cursor: None },
                CorrelationId::new(),
            )
            .expect("empty page");
        assert!(empty.items.is_empty());
        assert!(empty.next_cursor.is_none());
    }

    #[test]
    fn recording_cursor_binds_operation_filter_and_sort() {
        let project = ProjectId::new();
        let operation = OperationId::new();
        let key = ObservedRecordingKey {
            opened_at: "2026-09-30T00:00:00.000000Z".into(),
            recording_id: RecordingId::new(),
        };
        let token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            key.clone(),
            CorrelationId::new(),
        )
        .expect("token");
        assert!(
            decode_recording_cursor(&token, QueryKind::Operation, project, Some(operation)).is_ok()
        );
        assert!(
            decode_recording_cursor(
                &token,
                QueryKind::Operation,
                project,
                Some(OperationId::new())
            )
            .is_err()
        );
        assert!(decode_recording_cursor(&token, QueryKind::Unmatched, project, None).is_err());
        assert!(
            decode_recording_cursor(
                &token,
                QueryKind::Operation,
                ProjectId::new(),
                Some(operation)
            )
            .is_err()
        );

        let uuid_v4 = RecordingId::from_uuid(
            uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("UUIDv4"),
        );
        let v4_key =
            ObservedRecordingKey { opened_at: key.opened_at.clone(), recording_id: uuid_v4 };
        let v4_token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            v4_key,
            CorrelationId::new(),
        )
        .expect("canonical JSON cursor with UUIDv4");
        let decoded_v4 =
            decode_recording_cursor(&v4_token, QueryKind::Operation, project, Some(operation))
                .expect("canonical UUIDv4 continuation key remains supported");
        assert_eq!(decoded_v4.last.recording_id, uuid_v4);

        let decoded_v7 =
            decode_recording_cursor(&token, QueryKind::Operation, project, Some(operation))
                .expect("canonical UUIDv7 continuation key remains supported");
        assert_eq!(decoded_v7.last.recording_id, key.recording_id);

        for recording_id in [uuid_v4, key.recording_id] {
            let continuation = encode_recording_cursor(
                QueryKind::Operation,
                project,
                Some(operation),
                ObservedRecordingKey { opened_at: key.opened_at.clone(), recording_id },
                CorrelationId::new(),
            )
            .expect("recording continuation cursor");
            let fake = Fake::default();
            let service = ObservedEndpointQueryService::new(fake.clone());
            service
                .list_operation_recordings(
                    ListOperationRecordings {
                        project_id: project,
                        operation_id: operation,
                        limit: Some(1),
                        cursor: Some(continuation),
                    },
                    CorrelationId::new(),
                )
                .expect("continue with canonical v4 or v7 recording ID");
            assert_eq!(
                fake.calls.lock().expect("calls")[0].2.as_deref(),
                Some(recording_id.to_string().as_str())
            );
        }

        let non_rfc4122 = uuid::Uuid::parse_str("01890f3e-7c00-7000-0000-000000000001")
            .expect("UUIDv7 with non-RFC 4122 variant");
        assert_eq!(non_rfc4122.get_version_num(), 7);
        assert_ne!(non_rfc4122.get_variant(), uuid::Variant::RFC4122);
        let non_rfc_key = ObservedRecordingKey {
            opened_at: key.opened_at.clone(),
            recording_id: RecordingId::from_uuid(non_rfc4122),
        };
        let non_rfc_token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            non_rfc_key,
            CorrelationId::new(),
        )
        .expect("canonical JSON cursor with non-RFC 4122 UUIDv7");
        assert!(
            decode_recording_cursor(&non_rfc_token, QueryKind::Operation, project, Some(operation))
                .is_err()
        );

        let invalid_versions = [
            uuid::Uuid::parse_str("f47ac10b-58cc-1372-a567-0e02b2c3d479").expect("UUIDv1"),
            uuid::Uuid::parse_str("f47ac10b-58cc-5372-a567-0e02b2c3d479").expect("UUIDv5"),
            uuid::Uuid::nil(),
        ];
        for invalid_uuid in invalid_versions {
            let invalid_key = ObservedRecordingKey {
                opened_at: key.opened_at.clone(),
                recording_id: RecordingId::from_uuid(invalid_uuid),
            };
            let invalid_token = encode_recording_cursor(
                QueryKind::Operation,
                project,
                Some(operation),
                invalid_key,
                CorrelationId::new(),
            )
            .expect("canonical cursor with an invalid recording UUID");
            assert!(
                decode_recording_cursor(
                    &invalid_token,
                    QueryKind::Operation,
                    project,
                    Some(operation)
                )
                .is_err()
            );
        }

        let mut invalid = key.clone();
        invalid.opened_at = "not-a-time".into();
        let invalid_token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            invalid,
            CorrelationId::new(),
        )
        .expect("canonical JSON cursor");
        assert!(
            decode_recording_cursor(&invalid_token, QueryKind::Operation, project, Some(operation))
                .is_err()
        );

        let mut noncanonical = key.clone();
        noncanonical.opened_at = "2026-09-30T00:00:00Z".into();
        let noncanonical_token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            noncanonical,
            CorrelationId::new(),
        )
        .expect("canonical JSON cursor");
        assert!(
            decode_recording_cursor(
                &noncanonical_token,
                QueryKind::Operation,
                project,
                Some(operation)
            )
            .is_err()
        );

        let edited = ObservedRecordingKey {
            opened_at: "2026-10-01T00:00:00.000000Z".into(),
            recording_id: RecordingId::new(),
        };
        let edited_token = encode_recording_cursor(
            QueryKind::Operation,
            project,
            Some(operation),
            edited.clone(),
            CorrelationId::new(),
        )
        .expect("edited cursor");
        assert_eq!(
            decode_recording_cursor(&edited_token, QueryKind::Operation, project, Some(operation))
                .expect("same-scope edited canonical position")
                .last,
            edited
        );
    }

    #[test]
    fn linked_and_unmatched_recording_limits_enforce_their_bounds() {
        let fake = Fake::default();
        let service = ObservedEndpointQueryService::new(fake.clone());
        let project = ProjectId::new();
        let operation = OperationId::new();
        for limit in [0, MAX_OBSERVED_RECORDING_LIMIT + 1] {
            assert!(
                service
                    .list_operation_recordings(
                        ListOperationRecordings {
                            project_id: project,
                            operation_id: operation,
                            limit: Some(limit),
                            cursor: None
                        },
                        CorrelationId::new()
                    )
                    .is_err()
            );
            assert!(
                service
                    .list_unmatched_recordings(
                        ListUnmatchedRecordings {
                            project_id: project,
                            limit: Some(limit),
                            cursor: None
                        },
                        CorrelationId::new()
                    )
                    .is_err()
            );
        }
        service
            .list_operation_recordings(
                ListOperationRecordings {
                    project_id: project,
                    operation_id: operation,
                    limit: Some(MAX_OBSERVED_RECORDING_LIMIT),
                    cursor: None,
                },
                CorrelationId::new(),
            )
            .expect("linked max limit");
        service
            .list_unmatched_recordings(
                ListUnmatchedRecordings {
                    project_id: project,
                    limit: Some(MAX_OBSERVED_RECORDING_LIMIT),
                    cursor: None,
                },
                CorrelationId::new(),
            )
            .expect("unmatched max limit");
        assert_eq!(
            fake.calls.lock().expect("calls").iter().map(|call| call.1).collect::<Vec<_>>(),
            [MAX_OBSERVED_RECORDING_LIMIT, MAX_OBSERVED_RECORDING_LIMIT]
        );
    }
}
