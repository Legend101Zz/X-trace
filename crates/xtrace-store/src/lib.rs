//! Bundled SQLite store, migrations, and port implementations.
//!
//! The store owns all SQL, the schema version gate, and the typed
//! repositories that implement [`xtrace_application::ProjectRepository`].
//! Every other crate speaks to the database only through the
//! application ports, so a future migration to a different storage
//! engine does not require editing domain types or application code.
//!
//! Slice 1A covers the minimum needed to prove the spine:
//!
//! - bundled SQLite (`rusqlite` with the `bundled` feature);
//! - one forward-only migration (`v0001_initial`) applied at open
//!   time when the on-disk schema is older than the binary expects;
//! - foreign keys, WAL mode, and a 5 second busy timeout;
//! - a `schema_meta` singleton row that records the version and the
//!   timestamp of the last successful migration;
//! - the [`SqliteStore`] handle that owns a connection and exposes
//!   the typed repository methods.
//!
//! All public surface returns typed errors; the store never panics on
//! invalid input.

#![allow(clippy::module_name_repetitions, reason = "store modules are named after their entities")]
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

pub mod catalog_discovery_store;
pub mod connection;
pub mod error;
pub mod idempotency_repository;
pub mod migrations;
pub mod project_repository;
pub mod recording_port;
pub mod recording_store;
pub mod xtf;

pub use catalog_discovery_store::SqliteCatalogDiscoveryStore;
pub use connection::{
    BusyTimeout, CURRENT_SCHEMA_VERSION, OpenOptions, STORE_ABI_VERSION, SqliteStore,
    StoreBootstrap,
};
pub use error::{StoreError, StoreErrorKind};
pub use idempotency_repository::SqliteIdempotencyStore;
pub use migrations::{MigrationRecord, Migrations};
pub use project_repository::SqliteProjectRepository;
pub use recording_port::{SqliteRecordingPersistence, SqliteRecordingReader};
pub use recording_store::{
    BeginRecordingDisposition, BeginRecordingReceipt, BeginRecordingRequest, RecordingStoreError,
    RecordingStoreErrorCategory, RecordingStoreErrorKind, SegmentCommitDisposition,
    SegmentCommitReceipt, SegmentCommitRequest, SqliteRecordingStore,
};
pub use xtf::{
    DecodedXtfSegment, EncodedXtfSegment, VerifiedXtfSegment, XtfCodecError, XtfSegmentInput,
    decode_compressed_segment, encode_segment, max_compressed_segment_bytes,
    max_logical_segment_bytes, verify_compressed_segment,
};
