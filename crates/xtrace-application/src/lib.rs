//! Application layer: use cases, ports, and the command/query facade.
//!
//! The application crate sits between the IO-free domain and the
//! infrastructure that implements storage and adapters. It owns:
//!
//! - the command and query types that clients (CLI, TUI, web) speak;
//! - the port traits that infrastructure must implement;
//! - the [`Application`] facade that orchestrates a single command or
//!   query and returns typed [`xtrace_domain::AppError`]s;
//! - the bridge between internal port errors and the public error
//!   contract so domain rules stay in domain, transport stays in
//!   transport, and neither leaks across the boundary.
//!
//! Slice 1A keeps the surface intentionally small. The exact set of
//! commands documented in `03-program-design.md` §3.2 grows in
//! later slices once the ports they need are wired in.

#![allow(
    clippy::module_name_repetitions,
    reason = "application modules are named after their entities"
)]
// Unwrap and expect are forbidden in non-test code so domain errors
// remain typed. Tests deliberately exercise fallible operations on
// fixture data and remain free to use them, hence the test-side allow.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod application;
pub mod commands;
pub mod error;
pub mod observed_endpoint_queries;
pub mod ports;
pub mod queries;
pub mod recording;
pub mod recording_queries;

pub use application::{Application, RequestContext};
pub use commands::{Command, CommandReceipt, InitializeProject, OpenProject};
pub use error::{PortError, PortErrorKind};
pub use observed_endpoint_queries::{
    DEFAULT_OBSERVED_ENDPOINT_LIMIT, DEFAULT_OBSERVED_RECORDING_LIMIT, ListObservedEndpoints,
    ListOperationRecordings, ListUnmatchedRecordings, MAX_OBSERVED_ENDPOINT_LIMIT,
    MAX_OBSERVED_RECORDING_LIMIT, ObservedEndpointDto, ObservedEndpointPage,
    ObservedEndpointQueryService, ObservedEndpointReadPort, ObservedRecordingDto,
    ObservedRecordingPage,
};
pub use ports::{IdempotencyStore, ProjectRepository, StoredReceipt};
pub use queries::{
    CapabilityReport, GetProject, GetStoreStatus, ProjectStatus, Query, QueryResult,
    StoreStatusReport,
};
pub use recording::{
    AcceptedRecordingEvent, BeginRecording, BeginRecordingDisposition, BeginRecordingReceipt,
    DEFAULT_MAX_RETAINED_RECORDINGS, DEFAULT_SEGMENT_EVENT_BYTES, DEFAULT_SEGMENT_EVENTS,
    DEFAULT_SEGMENT_SPAN_NS, FinishRecording, FinishRecordingReceipt, MAX_RECORDED_EVENTS,
    MAX_XTF_EVENT_ENVELOPE_BYTES, PersistRecordingSegment, PersistSegmentDisposition,
    PersistSegmentReceipt, RecordEvents, RecordEventsReceipt, RecordingCapture,
    RecordingCaptureService, RecordingPersistencePort, SegmentPolicy,
};
pub use recording_queries::{
    DEFAULT_RECORDING_EVENT_LIMIT, DEFAULT_RECORDING_LIST_LIMIT, FieldRepresentation,
    FieldTruncation, ListRecordings, MAX_RECORDING_DISPLAY_FIELD_BYTES, MAX_RECORDING_EVENT_LIMIT,
    MAX_RECORDING_EVENT_PROJECTION_BYTES, MAX_RECORDING_LIST_LIMIT,
    MAX_RECORDING_RELATIONSHIP_ID_BYTES, MAX_RECORDING_VERIFIED_INPUT_BYTES, PersistedEvent,
    PersistedInteraction, RECORDING_READ_SCHEMA_VERSION, RecordingDetail, RecordingEventWindow,
    RecordingListPage, RecordingMetadata, RecordingQueryService, RecordingReadPort,
    RecordingStatus, ShowRecording, ShowWindowRequest, UnavailableEvidence, list_recordings,
    show_recording,
};
