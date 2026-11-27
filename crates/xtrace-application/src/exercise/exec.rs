//! Approved exercise execution orchestration and ephemeral provenance contract.

use std::fmt;

use serde::{Deserialize, Serialize};
use xtrace_domain::{OperationId, ProjectId, RecordingId, RunId, WallTime};
pub use xtrace_exercise::executor::ExerciseFailureClass;
use xtrace_exercise::executor::{
    CredentialResolver, DnsResolver, ExecutionBody, ExecutionError, ExecutionGate, ExecutionParam,
    ExecutionParamLocation, ExecutionParamValue, ExecutionRequestSpec, ExecutionStatus,
    ExecutorBounds, HttpTransport, PreparedWireRequest, RawHttpResponse, TransportFailure,
    execute_with_transport, finalize_response, prepare_request,
};

use super::model::{
    ExecutionBounds, ExerciseBody, ExerciseError, ExercisePhase, ExercisePlanPort, InputLocation,
    InputValue,
};
use super::service::ExercisePlanService;

/// Ephemeral execution run lifecycle state persisted in provenance storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseRunStatus {
    /// Plan was consumed and run provenance initialized before resolving credentials or sending.
    Reserved,
    /// Socket transmission started.
    Running,
    /// Request transmitted and non-redirect response received within caps.
    Succeeded,
    /// Refused or failed deterministically (`non_loopback`, `3xx`, size cap, connect error, ...).
    Failed,
    /// Outcome unknown after write start; must never be retried.
    DeliveryUnknown,
}

impl ExerciseRunStatus {
    /// Stable lowercase persistence tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    /// Parses a persisted status tag.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "delivery_unknown" => Some(Self::DeliveryUnknown),
            _ => None,
        }
    }
}

/// Ephemeral execution item lifecycle state persisted in provenance storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseItemStatus {
    /// Item reserved after `consume_once`.
    Reserved,
    /// Item transmission started.
    Sending,
    /// Item completed cleanly within caps without redirect.
    Succeeded,
    /// Item refused or failed deterministically.
    Failed,
    /// Item delivery unknown after write start.
    DeliveryUnknown,
}

impl ExerciseItemStatus {
    /// Stable lowercase persistence tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Sending => "sending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    /// Parses a persisted item status tag.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "sending" => Some(Self::Sending),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "delivery_unknown" => Some(Self::DeliveryUnknown),
            _ => None,
        }
    }
}

/// Initial ephemeral run record inserted immediately after `consume_once`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewExerciseRun {
    /// Fresh UUIDv7 identity for this execution run.
    pub exercise_run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Approved plan UUIDv7.
    pub plan_id: uuid::Uuid,
    /// Immutable lifecycle plan hash (`64` lowercase hex chars).
    pub plan_hash: String,
    /// Sanitized loopback origin (`http://127.0.0.1:<port>` or `http://[::1]:<port>`).
    pub target_origin: String,
    /// Timestamp when the run was reserved.
    pub started_at: WallTime,
}

/// Initial ephemeral item record inserted alongside [`NewExerciseRun`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewExerciseItem {
    /// Owning execution run.
    pub exercise_run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Deterministic UUIDv8 item identity emitted in `X-XTrace-Exercise-Item`.
    pub exercise_item_id: uuid::Uuid,
    /// Linked catalog operation.
    pub operation_id: OperationId,
    /// Uppercase HTTP method.
    pub method: String,
    /// Catalog route template (never interpolated private inputs).
    pub route_template: String,
    /// Candidate effect classification (`read_only`, `mutating`, `unknown`).
    pub effect: String,
}

/// Terminal provenance update persisted after pre-send refusal or transport completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishExerciseRun {
    /// Owning project.
    pub project_id: ProjectId,
    /// Execution run being finalized.
    pub exercise_run_id: RunId,
    /// Item identity within the run.
    pub exercise_item_id: uuid::Uuid,
    /// Terminal run status (`succeeded`, `failed`, or `delivery_unknown`).
    pub run_status: ExerciseRunStatus,
    /// Terminal item status (`succeeded`, `failed`, or `delivery_unknown`).
    pub item_status: ExerciseItemStatus,
    /// Typed failure class when `run_status != Succeeded`.
    pub failure_class: Option<String>,
    /// Observed HTTP status code when available.
    pub http_status: Option<u16>,
    /// Encoded wire request byte count when prepared.
    pub request_bytes: Option<u32>,
    /// Response body byte count when cleanly received.
    pub response_bytes: Option<u32>,
    /// Elapsed milliseconds for execution.
    pub duration_ms: Option<u64>,
    /// Completion timestamp.
    pub finished_at: WallTime,
}

/// Explicit linkage between an executed exercise item and an observed recording.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewExerciseRecordingLink {
    /// Owning project.
    pub project_id: ProjectId,
    /// Execution run that produced the item.
    pub exercise_run_id: RunId,
    /// Executed item UUID (`X-XTrace-Exercise-Item`).
    pub exercise_item_id: uuid::Uuid,
    /// Observed recording UUID inside the same project.
    pub recording_id: RecordingId,
    /// Timestamp when the link was persisted.
    pub linked_at: WallTime,
}

/// Persisted ephemeral run summary (never carries private inputs or secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseRunRecord {
    /// Run UUIDv7.
    pub exercise_run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Executed plan UUIDv7.
    pub plan_id: uuid::Uuid,
    /// Immutable lifecycle plan hash.
    pub plan_hash: String,
    /// Sanitized loopback origin.
    pub target_origin: String,
    /// Current run status.
    pub status: ExerciseRunStatus,
    /// Typed failure class when failed or delivery unknown.
    pub failure_class: Option<String>,
    /// Run reservation timestamp.
    pub started_at: String,
    /// Completion timestamp when terminal.
    pub finished_at: Option<String>,
}

/// Persisted ephemeral item summary (never carries private inputs, headers, bodies, or secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseItemRecord {
    /// Owning run UUIDv7.
    pub exercise_run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Item UUID emitted in `X-XTrace-Exercise-Item`.
    pub exercise_item_id: uuid::Uuid,
    /// Catalog operation UUID.
    pub operation_id: OperationId,
    /// HTTP method.
    pub method: String,
    /// Route template.
    pub route_template: String,
    /// Candidate effect label.
    pub effect: String,
    /// Current item status.
    pub status: ExerciseItemStatus,
    /// Typed failure class when failed or delivery unknown.
    pub failure_class: Option<String>,
    /// HTTP status code if received.
    pub http_status: Option<u16>,
    /// Encoded request wire bytes.
    pub request_bytes: Option<u32>,
    /// Received response body bytes.
    pub response_bytes: Option<u32>,
    /// Elapsed milliseconds.
    pub duration_ms: Option<u64>,
}

/// Persisted `exercise_item_id -> recording_id` linkage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseRecordingLink {
    /// Owning project.
    pub project_id: ProjectId,
    /// Owning run UUIDv7.
    pub exercise_run_id: RunId,
    /// Linked exercise item UUID.
    pub exercise_item_id: uuid::Uuid,
    /// Linked recording UUID.
    pub recording_id: RecordingId,
    /// Linkage timestamp.
    pub linked_at: String,
}

/// Complete ephemeral provenance projection for one exercise run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseRunDetail {
    /// Run record.
    pub run: ExerciseRunRecord,
    /// Items belonging to this run.
    pub items: Vec<ExerciseItemRecord>,
    /// Recording links attached to items in this run.
    pub recording_links: Vec<ExerciseRecordingLink>,
}

/// Ephemeral provenance storage port backed by SQLite migration v11.
pub trait ExerciseProvenancePort {
    /// Inserts the initial `reserved` run and item atomically after `consume_once`.
    fn begin_run(&self, run: &NewExerciseRun, item: &NewExerciseItem) -> Result<(), ExerciseError>;

    /// Records terminal run and item status, failure class, and bounded metrics.
    fn finish_run(&self, completion: &FinishExerciseRun) -> Result<(), ExerciseError>;

    /// Explicitly links an exercise item to a project-owned observed recording.
    fn link_recording(
        &self,
        link: &NewExerciseRecordingLink,
    ) -> Result<ExerciseRecordingLink, ExerciseError>;

    /// Loads one run with its items and recording links within `project`.
    fn get_run(
        &self,
        project: ProjectId,
        exercise_run_id: RunId,
    ) -> Result<Option<ExerciseRunDetail>, ExerciseError>;

    /// Lists runs (newest first) for an exact `plan_hash` within `project`.
    fn list_runs_for_plan(
        &self,
        project: ProjectId,
        plan_hash: &str,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError>;

    /// Lists recent runs (newest first) within `project`.
    fn list_runs_for_project(
        &self,
        project: ProjectId,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError>;
}

/// Explicit request to execute one owner-approved exercise plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutePlanRequest {
    /// Owning project identity.
    pub project_id: ProjectId,
    /// Exact lifecycle hash of the approved plan.
    pub plan_hash: String,
    /// Exact plan UUIDv7 displayed to and confirmed by the operator.
    pub plan_id: String,
    /// Explicit operator confirmation that the target is their ordinary local dev application.
    pub confirm_owned_development_target: bool,
}

/// Sanitized error returned by [`ExerciseExecutionService`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExerciseExecutionError {
    /// Lifecycle, approval, expiry, hash, or storage refusal before execution.
    Lifecycle(ExerciseError),
    /// Execution refused or failed with a typed failure class (and persisted run ID if consumed).
    Failed {
        /// Ephemeral run ID created after `consume_once`, if consumption succeeded.
        run_id: Option<RunId>,
        /// Typed failure class.
        failure_class: ExerciseFailureClass,
        /// Observed HTTP status code if a response status line was received.
        http_status: Option<u16>,
        /// Fixed sanitized message.
        message: &'static str,
    },
}

impl ExerciseExecutionError {
    /// Returns the typed failure class across both lifecycle and execution failures.
    #[must_use]
    pub const fn failure_class(&self) -> ExerciseFailureClass {
        match self {
            Self::Lifecycle(err) => match err {
                ExerciseError::InvalidInput => ExerciseFailureClass::InvalidRequest,
                ExerciseError::BindingUnavailable | ExerciseError::NotFound => {
                    ExerciseFailureClass::HashMismatch
                }
                ExerciseError::StorageUnavailable | ExerciseError::StagingOccupied => {
                    ExerciseFailureClass::StorageError
                }
                ExerciseError::Conflict | ExerciseError::HashMismatch => {
                    ExerciseFailureClass::HashMismatch
                }
                ExerciseError::Expired => ExerciseFailureClass::PlanExpired,
                ExerciseError::UnresolvedInput => ExerciseFailureClass::UnresolvedInput,
                ExerciseError::ApprovalRequired => ExerciseFailureClass::ApprovalRequired,
                ExerciseError::CredentialValue => ExerciseFailureClass::CredentialResolutionFailed,
                ExerciseError::Superseded => ExerciseFailureClass::PlanSuperseded,
                ExerciseError::AlreadyConsumed => ExerciseFailureClass::AlreadyConsumed,
            },
            Self::Failed { failure_class, .. } => *failure_class,
        }
    }
}

impl fmt::Display for ExerciseExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifecycle(err) => fmt::Display::fmt(err, f),
            Self::Failed { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for ExerciseExecutionError {}

impl From<ExerciseError> for ExerciseExecutionError {
    fn from(value: ExerciseError) -> Self {
        Self::Lifecycle(value)
    }
}

/// Consumed, DNS-validated, credential-resolved request ready for socket transmission.
#[derive(Debug)]
pub struct PreparedExerciseExecution {
    /// Minted ephemeral run ID.
    pub run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Approved plan UUIDv7.
    pub plan_id: uuid::Uuid,
    /// Immutable lifecycle plan hash.
    pub plan_hash: String,
    /// Deterministic UUIDv8 item ID emitted in `X-XTrace-Exercise-Item`.
    pub item_id: uuid::Uuid,
    /// Linked catalog operation.
    pub operation_id: OperationId,
    /// Redacted-Debug, zero-on-drop bounded HTTP/1.1 wire request.
    pub wire_request: PreparedWireRequest,
    /// Pinned execution bounds.
    pub bounds: ExecutorBounds,
    /// Reservation timestamp.
    pub started_at: WallTime,
}

/// Sanitized execution receipt returned on stdout (never contains secrets or response bodies).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseExecutionReceipt {
    /// Fixed document discriminant.
    pub kind: &'static str,
    /// Ephemeral run UUIDv7.
    pub exercise_run_id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Executed plan UUIDv7.
    pub plan_id: uuid::Uuid,
    /// Immutable lifecycle plan hash.
    pub plan_hash: String,
    /// Executed exercise item UUIDv8 (`X-XTrace-Exercise-Item`).
    pub exercise_item_id: uuid::Uuid,
    /// Linked catalog operation.
    pub operation_id: OperationId,
    /// Sanitized loopback origin.
    pub target_origin: String,
    /// Terminal execution status.
    pub status: ExerciseRunStatus,
    /// Typed failure class when `status != Succeeded`.
    pub failure_class: Option<String>,
    /// Observed HTTP status code when received.
    pub http_status: Option<u16>,
    /// Encoded wire request size in bytes.
    pub request_bytes: usize,
    /// Received response body size in bytes.
    pub response_bytes: Option<usize>,
    /// Elapsed execution duration in milliseconds.
    pub duration_ms: u64,
    /// Reservation timestamp.
    pub started_at: String,
    /// Completion timestamp.
    pub finished_at: String,
}

fn to_executor_bounds(bounds: &ExecutionBounds) -> ExecutorBounds {
    ExecutorBounds {
        concurrency: bounds.concurrency,
        requests_per_second: bounds.requests_per_second,
        timeout_seconds: bounds.timeout_seconds,
        total_seconds: bounds.total_seconds,
        request_bytes: bounds.request_bytes,
        response_bytes: bounds.response_bytes,
        redirects: bounds.redirects,
    }
}

/// Approved-plan execution use case combining atomic consumption, fail-closed
/// loopback request preparation, and ephemeral SQLite provenance persistence.
pub struct ExerciseExecutionService<P, Q> {
    plan_port: P,
    provenance_port: Q,
}

impl<P: ExercisePlanPort, Q: ExerciseProvenancePort> ExerciseExecutionService<P, Q> {
    /// Creates an execution service over plan and provenance ports.
    pub const fn new(plan_port: P, provenance_port: Q) -> Self {
        Self { plan_port, provenance_port }
    }

    /// Borrows the underlying provenance port.
    pub const fn provenance(&self) -> &Q {
        &self.provenance_port
    }

    /// Verifies explicit approval & expiry, consumes approval atomically via `consume_once`,
    /// persists `reserved` provenance, validates connect-time loopback IPs, and resolves
    /// credentials just in time.
    ///
    /// # Errors
    ///
    /// Returns [`ExerciseExecutionError`] on any lifecycle, expiry, target/DNS, credential,
    /// size, or storage check failure.
    pub fn prepare_execution(
        &self,
        req: &ExecutePlanRequest,
        now_unix: u64,
        clock_before_send: impl FnOnce() -> Result<u64, ExerciseError>,
        started_at: WallTime,
        dns: &dyn DnsResolver,
        creds: &dyn CredentialResolver,
    ) -> Result<PreparedExerciseExecution, ExerciseExecutionError> {
        if !req.confirm_owned_development_target {
            return Err(ExerciseExecutionError::Lifecycle(ExerciseError::ApprovalRequired));
        }

        let plan_service = ExercisePlanService::new(&self.plan_port);
        let plan = plan_service.show(req.project_id, &req.plan_hash)?;
        if plan.content.plan_id != req.plan_id {
            return Err(ExerciseExecutionError::Lifecycle(ExerciseError::HashMismatch));
        }
        plan.ensure_active_at(now_unix)?;

        let expected_item_str = xtrace_exercise::canonical::item_uuid(
            &req.plan_hash,
            &plan.content.binding.operation_id.to_string(),
        );
        match &plan.phase {
            ExercisePhase::Approved { item_ids, .. } => {
                if item_ids.as_slice() != [expected_item_str.as_str()] {
                    return Err(ExerciseExecutionError::Lifecycle(ExerciseError::ApprovalRequired));
                }
            }
            ExercisePhase::Consumed { .. } => {
                return Err(ExerciseExecutionError::Lifecycle(ExerciseError::AlreadyConsumed));
            }
            ExercisePhase::Superseded { .. } => {
                return Err(ExerciseExecutionError::Lifecycle(ExerciseError::Superseded));
            }
            ExercisePhase::Draft {} | ExercisePhase::Reviewed { .. } => {
                return Err(ExerciseExecutionError::Lifecycle(ExerciseError::ApprovalRequired));
            }
        }

        let bounds = to_executor_bounds(&plan.content.bounds);
        bounds.validate().map_err(|err| ExerciseExecutionError::Failed {
            run_id: None,
            failure_class: err.failure_class,
            http_status: None,
            message: err.message,
        })?;

        // Atomically consume approval BEFORE persisting provenance, resolving credentials, or I/O.
        let consumed = plan_service.consume_once(req.project_id, &req.plan_hash, now_unix)?;
        let run_id = RunId::new();
        let plan_uuid = uuid::Uuid::parse_str(&consumed.content.plan_id)
            .map_err(|_| ExerciseExecutionError::Lifecycle(ExerciseError::HashMismatch))?;
        let item_uuid = uuid::Uuid::parse_str(&expected_item_str)
            .map_err(|_| ExerciseExecutionError::Lifecycle(ExerciseError::HashMismatch))?;
        let catalog = &consumed.content.binding.selected_catalog;
        let effect = xtrace_exercise::classify(&catalog.method, &[], catalog.conflicted);

        self.provenance_port.begin_run(
            &NewExerciseRun {
                exercise_run_id: run_id,
                project_id: req.project_id,
                plan_id: plan_uuid,
                plan_hash: consumed.plan_hash.clone(),
                target_origin: consumed.content.request.target.base_url.clone(),
                started_at,
            },
            &NewExerciseItem {
                exercise_run_id: run_id,
                project_id: req.project_id,
                exercise_item_id: item_uuid,
                operation_id: consumed.content.binding.operation_id,
                method: catalog.method.clone(),
                route_template: catalog.route_template.clone(),
                effect: effect.name().to_owned(),
            },
        )?;

        let fail_after_begin = |class: ExerciseFailureClass, message: &'static str| {
            let _ = self.provenance_port.finish_run(&FinishExerciseRun {
                project_id: req.project_id,
                exercise_run_id: run_id,
                exercise_item_id: item_uuid,
                run_status: ExerciseRunStatus::Failed,
                item_status: ExerciseItemStatus::Failed,
                failure_class: Some(class.as_str().to_owned()),
                http_status: None,
                request_bytes: None,
                response_bytes: None,
                duration_ms: Some(0),
                finished_at: started_at,
            });
            ExerciseExecutionError::Failed {
                run_id: Some(run_id),
                failure_class: class,
                http_status: None,
                message,
            }
        };

        let fresh_now = match clock_before_send() {
            Ok(ts) => ts,
            Err(_) => {
                return Err(fail_after_begin(
                    ExerciseFailureClass::PlanExpired,
                    "exercise plan expired before transmission",
                ));
            }
        };
        if consumed.ensure_active_at(fresh_now).is_err() {
            return Err(fail_after_begin(
                ExerciseFailureClass::PlanExpired,
                "exercise plan expired before transmission",
            ));
        }

        let spec =
            match build_request_spec(&consumed.content, &consumed.plan_hash, &expected_item_str) {
                Ok(spec) => spec,
                Err(err) => return Err(fail_after_begin(err.failure_class, err.message)),
            };

        let wire_request = match prepare_request(&spec, bounds, dns, creds) {
            Ok(wire) => wire,
            Err(err) => return Err(fail_after_begin(err.failure_class, err.message)),
        };

        Ok(PreparedExerciseExecution {
            run_id,
            project_id: req.project_id,
            plan_id: plan_uuid,
            plan_hash: consumed.plan_hash,
            item_id: item_uuid,
            operation_id: consumed.content.binding.operation_id,
            wire_request,
            bounds,
            started_at,
        })
    }

    /// Validates transport output against bounds/redirect rules and persists terminal provenance.
    ///
    /// # Errors
    ///
    /// Returns [`ExerciseExecutionError`] if provenance persistence fails or the execution failed/is unknown.
    pub fn finish_execution(
        &self,
        prepared: PreparedExerciseExecution,
        transport_result: Result<RawHttpResponse, TransportFailure>,
        finished_at: WallTime,
        duration_ms: u64,
    ) -> Result<ExerciseExecutionReceipt, ExerciseExecutionError> {
        let outcome = finalize_response(&prepared.wire_request, transport_result, prepared.bounds);
        let (run_status, item_status) = match outcome.status {
            ExecutionStatus::Succeeded => {
                (ExerciseRunStatus::Succeeded, ExerciseItemStatus::Succeeded)
            }
            ExecutionStatus::Failed => (ExerciseRunStatus::Failed, ExerciseItemStatus::Failed),
            ExecutionStatus::DeliveryUnknown => {
                (ExerciseRunStatus::DeliveryUnknown, ExerciseItemStatus::DeliveryUnknown)
            }
        };
        let failure_class_str = outcome.failure_class.map(|c| c.as_str().to_owned());
        let request_bytes_u32 = u32::try_from(outcome.request_bytes).ok();
        let response_bytes_u32 = outcome.response_bytes.and_then(|n| u32::try_from(n).ok());

        self.provenance_port.finish_run(&FinishExerciseRun {
            project_id: prepared.project_id,
            exercise_run_id: prepared.run_id,
            exercise_item_id: prepared.item_id,
            run_status,
            item_status,
            failure_class: failure_class_str.clone(),
            http_status: outcome.http_status,
            request_bytes: request_bytes_u32,
            response_bytes: response_bytes_u32,
            duration_ms: Some(duration_ms),
            finished_at,
        })?;

        if outcome.status == ExecutionStatus::Succeeded {
            return Ok(ExerciseExecutionReceipt {
                kind: "exercise_execution",
                exercise_run_id: prepared.run_id,
                project_id: prepared.project_id,
                plan_id: prepared.plan_id,
                plan_hash: prepared.plan_hash,
                exercise_item_id: prepared.item_id,
                operation_id: prepared.operation_id,
                target_origin: outcome.target_origin,
                status: run_status,
                failure_class: failure_class_str,
                http_status: outcome.http_status,
                request_bytes: outcome.request_bytes,
                response_bytes: outcome.response_bytes,
                duration_ms,
                started_at: prepared.started_at.to_rfc3339(),
                finished_at: finished_at.to_rfc3339(),
            });
        }

        let class = outcome.failure_class.unwrap_or(ExerciseFailureClass::DeliveryUnknown);
        let message = match class {
            ExerciseFailureClass::RedirectRefused => {
                "exercise target returned a redirect, which is refused"
            }
            ExerciseFailureClass::ResponseSizeExceeded => {
                "exercise target response exceeded maximum byte limit"
            }
            ExerciseFailureClass::Timeout => "exercise request timed out",
            ExerciseFailureClass::TransportError => "could not connect to exercise target",
            _ => "exercise delivery outcome is unknown; approval remains consumed",
        };
        Err(ExerciseExecutionError::Failed {
            run_id: Some(prepared.run_id),
            failure_class: class,
            http_status: outcome.http_status,
            message,
        })
    }

    /// Synchronous end-to-end execution through an injectable [`HttpTransport`] and [`ExecutionGate`].
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit injectable clocks and security boundaries"
    )]
    pub fn execute_sync(
        &self,
        req: &ExecutePlanRequest,
        now_unix: u64,
        now_ms: u64,
        started_at: WallTime,
        finished_at: impl FnOnce() -> WallTime,
        gate: &ExecutionGate,
        dns: &dyn DnsResolver,
        creds: &dyn CredentialResolver,
        transport: &dyn HttpTransport,
    ) -> Result<ExerciseExecutionReceipt, ExerciseExecutionError> {
        let prepared =
            self.prepare_execution(req, now_unix, || Ok(now_unix), started_at, dns, creds)?;
        let permit = match gate.try_acquire(now_ms, prepared.bounds) {
            Ok(permit) => permit,
            Err(err) => {
                let _ = self.provenance_port.finish_run(&FinishExerciseRun {
                    project_id: prepared.project_id,
                    exercise_run_id: prepared.run_id,
                    exercise_item_id: prepared.item_id,
                    run_status: ExerciseRunStatus::Failed,
                    item_status: ExerciseItemStatus::Failed,
                    failure_class: Some(err.failure_class.as_str().to_owned()),
                    http_status: None,
                    request_bytes: u32::try_from(prepared.wire_request.request_bytes()).ok(),
                    response_bytes: None,
                    duration_ms: Some(0),
                    finished_at: finished_at(),
                });
                return Err(ExerciseExecutionError::Failed {
                    run_id: Some(prepared.run_id),
                    failure_class: err.failure_class,
                    http_status: None,
                    message: err.message,
                });
            }
        };
        let raw = transport.send(&prepared.wire_request, prepared.bounds);
        drop(permit);
        self.finish_execution(prepared, raw, finished_at(), 0)
    }

    /// Also delegates direct execution via `execute_with_transport` helper for pure tests.
    #[doc(hidden)]
    pub fn execute_direct_for_test(
        spec: &ExecutionRequestSpec,
        bounds: ExecutorBounds,
        gate: &ExecutionGate,
        now_ms: u64,
        dns: &dyn DnsResolver,
        creds: &dyn CredentialResolver,
        transport: &dyn HttpTransport,
    ) -> Result<xtrace_exercise::executor::ExecutionOutcome, ExecutionError> {
        execute_with_transport(spec, bounds, gate, now_ms, dns, creds, transport)
    }
}

/// Read and explicit recording-linkage service over [`ExerciseProvenancePort`].
pub struct ExerciseProvenanceService<Q> {
    port: Q,
}

impl<Q: ExerciseProvenancePort> ExerciseProvenanceService<Q> {
    /// Binds the service to a provenance adapter.
    pub const fn new(port: Q) -> Self {
        Self { port }
    }

    /// Persists explicit `exercise_item_id -> recording_id` linkage within `project`.
    pub fn link_recording(
        &self,
        project: ProjectId,
        exercise_run_id: RunId,
        exercise_item_id: &str,
        recording_id: RecordingId,
        linked_at: WallTime,
    ) -> Result<ExerciseRecordingLink, ExerciseError> {
        let item_uuid =
            uuid::Uuid::parse_str(exercise_item_id).map_err(|_| ExerciseError::InvalidInput)?;
        self.port.link_recording(&NewExerciseRecordingLink {
            project_id: project,
            exercise_run_id,
            exercise_item_id: item_uuid,
            recording_id,
            linked_at,
        })
    }

    /// Loads one run provenance detail within `project`.
    pub fn get_run(
        &self,
        project: ProjectId,
        exercise_run_id: RunId,
    ) -> Result<ExerciseRunDetail, ExerciseError> {
        self.port.get_run(project, exercise_run_id)?.ok_or(ExerciseError::NotFound)
    }

    /// Lists runs for an exact plan hash within `project`.
    pub fn list_runs_for_plan(
        &self,
        project: ProjectId,
        plan_hash: &str,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
        if plan_hash.len() != 64
            || !plan_hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ExerciseError::InvalidInput);
        }
        if limit == 0 || limit > 100 {
            return Err(ExerciseError::InvalidInput);
        }
        self.port.list_runs_for_plan(project, plan_hash, limit)
    }

    /// Lists recent runs within `project`.
    pub fn list_runs_for_project(
        &self,
        project: ProjectId,
        limit: u32,
    ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
        if limit == 0 || limit > 100 {
            return Err(ExerciseError::InvalidInput);
        }
        self.port.list_runs_for_project(project, limit)
    }
}

fn build_request_spec(
    content: &super::model::ExercisePlanContent,
    plan_hash: &str,
    item_id: &str,
) -> Result<ExecutionRequestSpec, ExecutionError> {
    let mut params = Vec::with_capacity(content.request.inputs.len());
    for input in &content.request.inputs {
        let location = match input.location {
            InputLocation::Path => ExecutionParamLocation::Path,
            InputLocation::Query => ExecutionParamLocation::Query,
            InputLocation::Header => ExecutionParamLocation::Header,
            InputLocation::Cookie => ExecutionParamLocation::Cookie,
        };
        let value = match &input.value {
            InputValue::Unresolved {} => {
                return Err(ExecutionError::new(
                    ExerciseFailureClass::UnresolvedInput,
                    "exercise input is unresolved",
                ));
            }
            InputValue::Operator { value } => ExecutionParamValue::Literal(value.0.clone()),
            InputValue::CredentialReference { reference } => {
                ExecutionParamValue::CredentialReference(reference.0.clone())
            }
        };
        params.push(ExecutionParam {
            name: input.name.clone(),
            location,
            required: input.required,
            value,
        });
    }
    let body = match &content.request.body {
        ExerciseBody::NotRecorded {} => {
            return Err(ExecutionError::new(
                ExerciseFailureClass::UnresolvedInput,
                "request body is not recorded",
            ));
        }
        ExerciseBody::EmptyByOperator {} => ExecutionBody::Empty,
        ExerciseBody::Operator { content_type, content } => ExecutionBody::Bytes {
            content_type: content_type.clone(),
            content: content.0.as_bytes().to_vec(),
        },
    };
    Ok(ExecutionRequestSpec {
        plan_hash: plan_hash.to_owned(),
        item_id: item_id.to_owned(),
        method: content.binding.selected_catalog.method.clone(),
        route_template: content.binding.selected_catalog.route_template.clone(),
        base_url: content.request.target.base_url.clone(),
        operator_owned_development: content.request.target.operator_owned_development,
        params,
        body,
    })
}

/// Borrowed adapter forwarding [`ExercisePlanPort`] so caller can share an in-memory or file store.
impl<T: ExercisePlanPort + ?Sized> ExercisePlanPort for &T {
    fn observed_binding(
        &self,
        project: ProjectId,
        request: &super::model::CreateExercisePlan,
    ) -> Result<super::model::ExerciseOperationBinding, ExerciseError> {
        (**self).observed_binding(project, request)
    }

    fn insert(&self, plan: &super::model::StoredExercisePlan) -> Result<(), ExerciseError> {
        (**self).insert(plan)
    }

    fn supersede(
        &self,
        predecessor: &super::model::StoredExercisePlan,
        replacement: &super::model::StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        (**self).supersede(predecessor, replacement)
    }

    fn load(
        &self,
        project: ProjectId,
        hash: &str,
    ) -> Result<super::model::StoredExercisePlan, ExerciseError> {
        (**self).load(project, hash)
    }

    fn replace(
        &self,
        project: ProjectId,
        hash: &str,
        expected_revision: u64,
        next: &super::model::StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        (**self).replace(project, hash, expected_revision, next)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "execution orchestration unit tests")]
mod tests {
    use super::*;
    use crate::exercise::model::*;
    use crate::exercise::service::review_document;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use xtrace_domain::{CatalogRevisionId, OperationId, ProjectId, RecordingId};
    use xtrace_exercise::executor::{CredentialSecret, LoopbackLiteralResolver};

    #[derive(Clone, Default)]
    struct MemoryPlanPort {
        binding: Option<ExerciseOperationBinding>,
        plans: Arc<Mutex<BTreeMap<String, StoredExercisePlan>>>,
    }

    impl ExercisePlanPort for MemoryPlanPort {
        fn observed_binding(
            &self,
            project: ProjectId,
            request: &CreateExercisePlan,
        ) -> Result<ExerciseOperationBinding, ExerciseError> {
            let b = self.binding.as_ref().ok_or(ExerciseError::BindingUnavailable)?;
            if b.project_id != project
                || b.selected_catalog.revision_id != request.revision_id
                || b.operation_id != request.operation_id
                || b.recording_id != request.recording_id
            {
                return Err(ExerciseError::BindingUnavailable);
            }
            Ok(b.clone())
        }

        fn insert(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
            self.plans.lock().unwrap().insert(plan.plan_hash.clone(), plan.clone());
            Ok(())
        }

        fn supersede(
            &self,
            predecessor: &StoredExercisePlan,
            replacement: &StoredExercisePlan,
        ) -> Result<(), ExerciseError> {
            let revoked = predecessor.revoked_by(replacement)?;
            let mut rows = self.plans.lock().unwrap();
            rows.insert(predecessor.plan_hash.clone(), revoked);
            rows.insert(replacement.plan_hash.clone(), replacement.clone());
            Ok(())
        }

        fn load(
            &self,
            project: ProjectId,
            hash: &str,
        ) -> Result<StoredExercisePlan, ExerciseError> {
            self.plans
                .lock()
                .unwrap()
                .get(hash)
                .filter(|p| p.content.binding.project_id == project)
                .cloned()
                .ok_or(ExerciseError::NotFound)
        }

        fn replace(
            &self,
            project: ProjectId,
            hash: &str,
            expected_revision: u64,
            next: &StoredExercisePlan,
        ) -> Result<(), ExerciseError> {
            let mut rows = self.plans.lock().unwrap();
            let prev = rows.get(hash).ok_or(ExerciseError::NotFound)?;
            if prev.content.binding.project_id != project || prev.revision != expected_revision {
                return Err(ExerciseError::Conflict);
            }
            rows.insert(hash.to_owned(), next.clone());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryProvenancePort {
        runs: Arc<Mutex<BTreeMap<RunId, ExerciseRunDetail>>>,
    }

    impl ExerciseProvenancePort for MemoryProvenancePort {
        fn begin_run(
            &self,
            run: &NewExerciseRun,
            item: &NewExerciseItem,
        ) -> Result<(), ExerciseError> {
            let detail = ExerciseRunDetail {
                run: ExerciseRunRecord {
                    exercise_run_id: run.exercise_run_id,
                    project_id: run.project_id,
                    plan_id: run.plan_id,
                    plan_hash: run.plan_hash.clone(),
                    target_origin: run.target_origin.clone(),
                    status: ExerciseRunStatus::Reserved,
                    failure_class: None,
                    started_at: run.started_at.to_rfc3339(),
                    finished_at: None,
                },
                items: vec![ExerciseItemRecord {
                    exercise_run_id: item.exercise_run_id,
                    project_id: item.project_id,
                    exercise_item_id: item.exercise_item_id,
                    operation_id: item.operation_id,
                    method: item.method.clone(),
                    route_template: item.route_template.clone(),
                    effect: item.effect.clone(),
                    status: ExerciseItemStatus::Reserved,
                    failure_class: None,
                    http_status: None,
                    request_bytes: None,
                    response_bytes: None,
                    duration_ms: None,
                }],
                recording_links: vec![],
            };
            self.runs.lock().unwrap().insert(run.exercise_run_id, detail);
            Ok(())
        }

        fn finish_run(&self, c: &FinishExerciseRun) -> Result<(), ExerciseError> {
            let mut map = self.runs.lock().unwrap();
            let detail = map.get_mut(&c.exercise_run_id).ok_or(ExerciseError::NotFound)?;
            detail.run.status = c.run_status;
            detail.run.failure_class = c.failure_class.clone();
            detail.run.finished_at = Some(c.finished_at.to_rfc3339());
            for item in &mut detail.items {
                if item.exercise_item_id == c.exercise_item_id {
                    item.status = c.item_status;
                    item.failure_class = c.failure_class.clone();
                    item.http_status = c.http_status;
                    item.request_bytes = c.request_bytes;
                    item.response_bytes = c.response_bytes;
                    item.duration_ms = c.duration_ms;
                }
            }
            Ok(())
        }

        fn link_recording(
            &self,
            link: &NewExerciseRecordingLink,
        ) -> Result<ExerciseRecordingLink, ExerciseError> {
            let mut map = self.runs.lock().unwrap();
            let detail = map
                .get_mut(&link.exercise_run_id)
                .filter(|d| d.run.project_id == link.project_id)
                .ok_or(ExerciseError::NotFound)?;
            let record = ExerciseRecordingLink {
                project_id: link.project_id,
                exercise_run_id: link.exercise_run_id,
                exercise_item_id: link.exercise_item_id,
                recording_id: link.recording_id,
                linked_at: link.linked_at.to_rfc3339(),
            };
            detail.recording_links.push(record.clone());
            Ok(record)
        }

        fn get_run(
            &self,
            project: ProjectId,
            exercise_run_id: RunId,
        ) -> Result<Option<ExerciseRunDetail>, ExerciseError> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .get(&exercise_run_id)
                .filter(|d| d.run.project_id == project)
                .cloned())
        }

        fn list_runs_for_plan(
            &self,
            project: ProjectId,
            plan_hash: &str,
            limit: u32,
        ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .values()
                .filter(|d| d.run.project_id == project && d.run.plan_hash == plan_hash)
                .take(limit as usize)
                .cloned()
                .collect())
        }

        fn list_runs_for_project(
            &self,
            project: ProjectId,
            limit: u32,
        ) -> Result<Vec<ExerciseRunDetail>, ExerciseError> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .values()
                .filter(|d| d.run.project_id == project)
                .take(limit as usize)
                .cloned()
                .collect())
        }
    }

    struct MapCreds(BTreeMap<String, String>);
    impl CredentialResolver for MapCreds {
        fn resolve(&self, reference: &str) -> Result<CredentialSecret, ExecutionError> {
            let val = self.0.get(reference).ok_or_else(|| {
                ExecutionError::new(
                    ExerciseFailureClass::CredentialResolutionFailed,
                    "missing credential",
                )
            })?;
            CredentialSecret::new(val.clone())
        }
    }

    struct RecordingTransport {
        wire_seen: Mutex<Vec<Vec<u8>>>,
        response: Result<RawHttpResponse, TransportFailure>,
    }
    impl HttpTransport for RecordingTransport {
        fn send(
            &self,
            request: &PreparedWireRequest,
            _bounds: ExecutorBounds,
        ) -> Result<RawHttpResponse, TransportFailure> {
            self.wire_seen.lock().unwrap().push(request.wire_bytes().to_vec());
            self.response.clone()
        }
    }

    fn setup_approved_plan() -> (MemoryPlanPort, StoredExercisePlan) {
        let binding = ExerciseOperationBinding {
            project_id: ProjectId::new(),
            operation_id: OperationId::new(),
            recording_id: RecordingId::new(),
            selected_catalog: SelectedCatalogOperation {
                revision_id: CatalogRevisionId::new(),
                catalog_hash: "ab".repeat(32),
                operation_version_id: "v1".into(),
                application_component: "exec-fixture".into(),
                binding_key: "default".into(),
                method: "POST".into(),
                route_template: "/orders/{id}".into(),
                conflicted: false,
            },
        };
        let req = CreateExercisePlan {
            revision_id: binding.selected_catalog.revision_id,
            operation_id: binding.operation_id,
            selected_operation_version_id: "v1".into(),
            recording_id: binding.recording_id,
            target: DevelopmentTarget {
                base_url: "http://127.0.0.1:8080".into(),
                operator_owned_development: true,
            },
            inputs: vec![
                ExerciseInput {
                    name: "id".into(),
                    location: InputLocation::Path,
                    required: true,
                    value: InputValue::Operator { value: PrivateText("7".into()) },
                },
                ExerciseInput {
                    name: "Authorization".into(),
                    location: InputLocation::Header,
                    required: true,
                    value: InputValue::CredentialReference {
                        reference: PrivateText("local_login".into()),
                    },
                },
            ],
            body: ExerciseBody::Operator {
                content_type: "application/json".into(),
                content: PrivateText(r#"{"qty":2}"#.into()),
            },
            lifetime_seconds: 120,
        };
        let port = MemoryPlanPort { binding: Some(binding.clone()), plans: Arc::default() };
        let svc = ExercisePlanService::new(port.clone());
        let plan = svc.create(binding.project_id, req, 100).unwrap();
        svc.review(binding.project_id, &plan.plan_hash, 101).unwrap();
        let item_id = review_document(&plan, 101).unwrap()["preview"]["items"][0]["item_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let approved =
            svc.approve(binding.project_id, &plan.plan_hash, &[item_id], true, 102).unwrap();
        (port, approved)
    }

    #[test]
    fn refuses_unapproved_expired_mutated_and_already_consumed_plans() {
        let (plan_port, approved) = setup_approved_plan();
        let prov_port = MemoryProvenancePort::default();
        let exec = ExerciseExecutionService::new(plan_port.clone(), prov_port.clone());
        let creds = MapCreds([("local_login".into(), "Bearer super-secret-canary".into())].into());
        let transport = RecordingTransport {
            wire_seen: Mutex::default(),
            response: Ok(RawHttpResponse { status_code: 201, body: b"{}".to_vec() }),
        };
        let gate = ExecutionGate::new();

        let req = ExecutePlanRequest {
            project_id: approved.content.binding.project_id,
            plan_hash: approved.plan_hash.clone(),
            plan_id: approved.content.plan_id.clone(),
            confirm_owned_development_target: false,
        };
        assert_eq!(
            exec.execute_sync(
                &req,
                103,
                1_000,
                WallTime::now(),
                WallTime::now,
                &gate,
                &LoopbackLiteralResolver,
                &creds,
                &transport,
            )
            .unwrap_err(),
            ExerciseExecutionError::Lifecycle(ExerciseError::ApprovalRequired)
        );
        assert!(transport.wire_seen.lock().unwrap().is_empty());

        // Expired refusal before consume_once
        let mut req_ok = req;
        req_ok.confirm_owned_development_target = true;
        assert_eq!(
            exec.execute_sync(
                &req_ok,
                approved.content.expires_at,
                1_000,
                WallTime::now(),
                WallTime::now,
                &gate,
                &LoopbackLiteralResolver,
                &creds,
                &transport,
            )
            .unwrap_err(),
            ExerciseExecutionError::Lifecycle(ExerciseError::Expired)
        );

        // Mutated plan refusal
        plan_port
            .plans
            .lock()
            .unwrap()
            .get_mut(&approved.plan_hash)
            .unwrap()
            .content
            .request
            .target
            .base_url = "http://127.0.0.1:9999".into();
        assert_eq!(
            exec.execute_sync(
                &req_ok,
                103,
                1_000,
                WallTime::now(),
                WallTime::now,
                &gate,
                &LoopbackLiteralResolver,
                &creds,
                &transport,
            )
            .unwrap_err(),
            ExerciseExecutionError::Lifecycle(ExerciseError::HashMismatch)
        );
        plan_port.plans.lock().unwrap().insert(approved.plan_hash.clone(), approved.clone());

        // Happy execution
        let receipt = exec
            .execute_sync(
                &req_ok,
                103,
                2_000,
                WallTime::now(),
                WallTime::now,
                &gate,
                &LoopbackLiteralResolver,
                &creds,
                &transport,
            )
            .unwrap();
        assert_eq!(receipt.status, ExerciseRunStatus::Succeeded);
        assert_eq!(receipt.http_status, Some(201));
        let wire = String::from_utf8(transport.wire_seen.lock().unwrap()[0].clone()).unwrap();
        assert!(wire.contains(&format!("X-XTrace-Exercise-Item: {}", receipt.exercise_item_id)));
        assert!(wire.contains("Authorization: Bearer super-secret-canary"));
        assert!(!serde_json::to_string(&receipt).unwrap().contains("super-secret-canary"));

        // Second execution refused as AlreadyConsumed
        assert_eq!(
            exec.execute_sync(
                &req_ok,
                104,
                5_000,
                WallTime::now(),
                WallTime::now,
                &gate,
                &LoopbackLiteralResolver,
                &creds,
                &transport,
            )
            .unwrap_err(),
            ExerciseExecutionError::Lifecycle(ExerciseError::AlreadyConsumed)
        );
    }

    #[test]
    fn non_loopback_dns_refusal_consumes_once_records_provenance_and_links_recording() {
        struct BadDns;
        impl DnsResolver for BadDns {
            fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ExecutionError> {
                Ok(vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), port),
                ])
            }
        }
        let (plan_port, approved) = setup_approved_plan();
        let prov_port = MemoryProvenancePort::default();
        let exec = ExerciseExecutionService::new(plan_port, prov_port.clone());
        let creds = MapCreds([("local_login".into(), "Bearer super-secret-canary".into())].into());
        let transport = RecordingTransport {
            wire_seen: Mutex::default(),
            response: Ok(RawHttpResponse { status_code: 200, body: vec![] }),
        };
        let err = exec
            .execute_sync(
                &ExecutePlanRequest {
                    project_id: approved.content.binding.project_id,
                    plan_hash: approved.plan_hash.clone(),
                    plan_id: approved.content.plan_id.clone(),
                    confirm_owned_development_target: true,
                },
                103,
                1_000,
                WallTime::now(),
                WallTime::now,
                &ExecutionGate::new(),
                &BadDns,
                &creds,
                &transport,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ExerciseExecutionError::Failed {
                run_id: Some(_),
                failure_class: ExerciseFailureClass::NonLoopbackDestination,
                ..
            }
        ));
        let ExerciseExecutionError::Failed { run_id: Some(run_id), .. } = err else {
            return;
        };
        assert!(transport.wire_seen.lock().unwrap().is_empty());

        let prov = ExerciseProvenanceService::new(prov_port);
        let detail = prov.get_run(approved.content.binding.project_id, run_id).unwrap();
        assert_eq!(detail.run.status, ExerciseRunStatus::Failed);
        assert_eq!(detail.run.failure_class.as_deref(), Some("non_loopback_destination"));
        assert!(!serde_json::to_string(&detail).unwrap().contains("super-secret-canary"));

        let rec_id = RecordingId::new();
        let link = prov
            .link_recording(
                approved.content.binding.project_id,
                run_id,
                &detail.items[0].exercise_item_id.to_string(),
                rec_id,
                WallTime::now(),
            )
            .unwrap();
        assert_eq!(link.recording_id, rec_id);
        assert_eq!(
            prov.get_run(approved.content.binding.project_id, run_id)
                .unwrap()
                .recording_links
                .len(),
            1
        );
    }
}
