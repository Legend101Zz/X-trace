//! Runtime session aggregate.
//!
//! A runtime session is one instrumented process and the negotiated
//! capability snapshot. Slice 1A captures enough state for the CLI to
//! report whether a session exists; the rest of the lifecycle is filled
//! in once the adapter protocol is exercised in Slice 1.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::ids::{ProjectId, RuntimeSessionId};
use crate::provenance::ProducerIdentity;
use crate::time::WallTime;

/// Lifecycle of a runtime session. Mirrors `03-program-design.md` §5.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSessionState {
    /// Session row created but no connection yet.
    Created,
    /// Adapter handshake in progress.
    Authenticating,
    /// Capability negotiation in progress.
    Negotiating,
    /// Session is active and may create recordings.
    Active,
    /// Session is draining; new recordings are rejected but completion
    /// markers are accepted.
    Draining,
    /// Session closed cleanly.
    Closed,
    /// Session failed; `close_reason` carries the reason.
    Failed,
}

impl RuntimeSessionState {
    /// Returns `true` if the session is allowed to create recordings.
    #[must_use]
    pub const fn accepts_recordings(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Authenticating => "authenticating",
            Self::Negotiating => "negotiating",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }
}

/// Negotiated capability set.
///
/// The full capability vocabulary is defined in `03b-protocol-and-api.md`.
/// Slice 1A persists the names of capabilities that were accepted so a
/// replay can show the historical surface it relied on.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Capability names that were accepted during negotiation.
    pub accepted: BTreeSet<String>,
    /// Capability names that were rejected or unsupported.
    pub rejected: BTreeSet<String>,
}

impl CapabilitySet {
    /// Returns an empty capability set, used when the session has not
    /// finished negotiating yet.
    #[must_use]
    pub fn empty() -> Self {
        Self { accepted: BTreeSet::new(), rejected: BTreeSet::new() }
    }
}

/// Runtime session aggregate root.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSession {
    /// Stable identifier.
    pub id: RuntimeSessionId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Producer identity that opened the session.
    pub producer: ProducerIdentity,
    /// Lifecycle state.
    pub state: RuntimeSessionState,
    /// Process identifier reported by the adapter.
    pub pid: Option<i64>,
    /// Process start time reported by the adapter. Used during
    /// recovery to confirm a discovery file still references a live
    /// process.
    pub process_start_time: Option<WallTime>,
    /// Adapter-reported runtime name (`java`, `node`, ...).
    pub runtime_name: String,
    /// Adapter-reported runtime version.
    pub runtime_version: String,
    /// Framework facts reported during negotiation, encoded as
    /// canonical JSON. The full vocabulary is defined by each language
    /// pack; Slice 1A stores the blob verbatim.
    pub framework_facts_json: String,
    /// Negotiated capabilities.
    pub capabilities: CapabilitySet,
    /// Wall-clock time the session was connected.
    pub connected_at: WallTime,
    /// Wall-clock time the session closed. `None` while still open.
    pub closed_at: Option<WallTime>,
    /// Reason the session closed. `None` while still open.
    pub close_reason: Option<String>,
}

impl RuntimeSession {
    /// Returns `true` if the session is in a state that can produce
    /// recordings.
    #[must_use]
    pub const fn can_capture(&self) -> bool {
        self.state.accepts_recordings()
    }
}
