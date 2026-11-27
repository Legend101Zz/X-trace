//! Parent-child runtime session linkage and explicit correlation gaps.
//!
//! Supported worker threads and child processes carry only bounded structural
//! identifiers and hashed correlation tokens. Raw command lines, `argv`,
//! environment maps, and raw bearer tokens are never represented or persisted.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::ids::{RecordingId, RuntimeSessionId, SessionLinkId};
use crate::recording::GapReason;

/// Maximum length in UTF-8 bytes accepted for a raw correlation token before hashing.
pub const MAX_CORRELATION_TOKEN_BYTES: usize = 256;

const CORRELATION_TOKEN_DOMAIN: &[u8] = b"xtrace.process-linkage.correlation-token.v1\0";

/// Runtime boundary that spawned a worker or child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnKind {
    /// Node.js `worker_threads.Worker`.
    NodeWorker,
    /// Node.js `child_process.{spawn,fork,execFile}`.
    NodeChildProcess,
    /// JVM child process started via `java.lang.ProcessBuilder.start()`.
    JvmFork,
}

impl SpawnKind {
    /// Returns the canonical snake_case wire and persistence tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeWorker => "node_worker",
            Self::NodeChildProcess => "node_child_process",
            Self::JvmFork => "jvm_fork",
        }
    }

    /// Parses a persisted snake_case spawn kind tag.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "node_worker" => Some(Self::NodeWorker),
            "node_child_process" => Some(Self::NodeChildProcess),
            "jvm_fork" => Some(Self::JvmFork),
            _ => None,
        }
    }
}

impl fmt::Display for SpawnKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of correlating a spawned worker or child runtime session with its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLinkStatus {
    /// Child runtime session authenticated and correlated to the parent session.
    Linked,
    /// Child spawned without instrumentation or after bootstrap consumption.
    UninstrumentedGap,
    /// Boundary was detached or correlation metadata was missing, invalid, or mismatched.
    CorrelationLost,
}

impl SessionLinkStatus {
    /// Returns the canonical snake_case persistence tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::UninstrumentedGap => "uninstrumented_gap",
            Self::CorrelationLost => "correlation_lost",
        }
    }

    /// Parses a persisted snake_case link status tag.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "linked" => Some(Self::Linked),
            "uninstrumented_gap" => Some(Self::UninstrumentedGap),
            "correlation_lost" => Some(Self::CorrelationLost),
            _ => None,
        }
    }
}

impl fmt::Display for SessionLinkStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validation failure for [`RuntimeSessionLink`] or correlation tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcessLinkValidationError {
    /// Correlation token was empty, oversized, or contained control characters.
    #[error("correlation token must be 1..=256 bytes without control characters")]
    InvalidCorrelationToken,
    /// A linked session lacked `child_session_id` or carried a gap reason.
    #[error("linked session records require child_session_id and no gap_reason")]
    InvalidLinkedState,
    /// An uninstrumented gap carried child session/recording IDs or an incompatible gap reason.
    #[error(
        "uninstrumented gap records require child_process_not_instrumented or bootstrap_consumed without child IDs"
    )]
    InvalidUninstrumentedGapState,
    /// A correlation-lost record carried a child recording ID or an incompatible gap reason.
    #[error(
        "correlation_lost records require gap_reason = correlation_lost and no child_recording_id"
    )]
    InvalidCorrelationLostState,
    /// Parent and child session or recording identifiers cannot be identical.
    #[error("parent and child identifiers must be distinct")]
    SelfLinkNotAllowed,
    /// Creation timestamp exceeded SQLite signed 64-bit integer bounds.
    #[error("created_at_ms exceeds representable timestamp bounds")]
    TimestampOutOfRange,
}

/// Computes the domain-separated BLAKE3-256 digest of a bounded correlation token.
///
/// # Errors
///
/// Returns [`ProcessLinkValidationError::InvalidCorrelationToken`] when the token is empty,
/// exceeds [`MAX_CORRELATION_TOKEN_BYTES`], or contains control characters.
pub fn hash_correlation_token(token: &str) -> Result<ContentHash, ProcessLinkValidationError> {
    if token.is_empty()
        || token.len() > MAX_CORRELATION_TOKEN_BYTES
        || token.chars().any(char::is_control)
    {
        return Err(ProcessLinkValidationError::InvalidCorrelationToken);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(CORRELATION_TOKEN_DOMAIN);
    hasher.update(token.as_bytes());
    Ok(ContentHash::from_blake3_digest(hasher.finalize()))
}

/// Bounded parent-child runtime session linkage or explicit gap record.
///
/// Holds strictly typed identifiers, closed enums, a millisecond timestamp, and an optional
/// 32-byte BLAKE3 token hash; raw `argv`, environment variables, and secrets are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSessionLink {
    /// Stable identifier of this link or gap record.
    pub link_id: SessionLinkId,
    /// Parent recording active at spawn time, if any.
    pub parent_recording_id: Option<RecordingId>,
    /// Parent runtime session identity.
    pub parent_session_id: RuntimeSessionId,
    /// Linked child recording identity, if one was explicitly bound.
    pub child_recording_id: Option<RecordingId>,
    /// Linked child runtime session identity when correlated.
    pub child_session_id: Option<RuntimeSessionId>,
    /// Runtime boundary kind that triggered the spawn.
    pub spawn_kind: SpawnKind,
    /// Correlation outcome.
    pub status: SessionLinkStatus,
    /// Explicit gap reason when `status` is not [`SessionLinkStatus::Linked`].
    pub gap_reason: Option<GapReason>,
    /// BLAKE3-256 digest of the correlation token (never raw token material).
    pub correlation_token_hash: Option<ContentHash>,
    /// Creation timestamp in Unix epoch milliseconds.
    pub created_at_ms: u64,
}

impl RuntimeSessionLink {
    /// Builds a validated linked parent-child session record.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessLinkValidationError`] if identifiers collide or timestamp overflows `i64`.
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor captures all typed columns of the linkage record directly"
    )]
    pub fn linked(
        link_id: SessionLinkId,
        parent_session_id: RuntimeSessionId,
        parent_recording_id: Option<RecordingId>,
        child_session_id: RuntimeSessionId,
        child_recording_id: Option<RecordingId>,
        spawn_kind: SpawnKind,
        correlation_token_hash: Option<ContentHash>,
        created_at_ms: u64,
    ) -> Result<Self, ProcessLinkValidationError> {
        let link = Self {
            link_id,
            parent_recording_id,
            parent_session_id,
            child_recording_id,
            child_session_id: Some(child_session_id),
            spawn_kind,
            status: SessionLinkStatus::Linked,
            gap_reason: None,
            correlation_token_hash,
            created_at_ms,
        };
        link.validate()?;
        Ok(link)
    }

    /// Builds a validated explicit uninstrumented-child gap record.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessLinkValidationError`] when `reason` is not
    /// [`GapReason::ChildProcessNotInstrumented`] or [`GapReason::BootstrapConsumed`], or
    /// `created_at_ms` overflows `i64`.
    pub fn uninstrumented_gap(
        link_id: SessionLinkId,
        parent_session_id: RuntimeSessionId,
        parent_recording_id: Option<RecordingId>,
        spawn_kind: SpawnKind,
        reason: GapReason,
        created_at_ms: u64,
    ) -> Result<Self, ProcessLinkValidationError> {
        let link = Self {
            link_id,
            parent_recording_id,
            parent_session_id,
            child_recording_id: None,
            child_session_id: None,
            spawn_kind,
            status: SessionLinkStatus::UninstrumentedGap,
            gap_reason: Some(reason),
            correlation_token_hash: None,
            created_at_ms,
        };
        link.validate()?;
        Ok(link)
    }

    /// Builds a validated explicit correlation-lost gap record.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessLinkValidationError`] if identifiers collide or `created_at_ms` overflows `i64`.
    pub fn correlation_lost(
        link_id: SessionLinkId,
        parent_session_id: RuntimeSessionId,
        parent_recording_id: Option<RecordingId>,
        child_session_id: Option<RuntimeSessionId>,
        spawn_kind: SpawnKind,
        correlation_token_hash: Option<ContentHash>,
        created_at_ms: u64,
    ) -> Result<Self, ProcessLinkValidationError> {
        let link = Self {
            link_id,
            parent_recording_id,
            parent_session_id,
            child_recording_id: None,
            child_session_id,
            spawn_kind,
            status: SessionLinkStatus::CorrelationLost,
            gap_reason: Some(GapReason::CorrelationLost),
            correlation_token_hash,
            created_at_ms,
        };
        link.validate()?;
        Ok(link)
    }

    /// Validates all structural invariants shared with SQLite schema constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessLinkValidationError`] naming the first violated invariant.
    pub fn validate(&self) -> Result<(), ProcessLinkValidationError> {
        if i64::try_from(self.created_at_ms).is_err() {
            return Err(ProcessLinkValidationError::TimestampOutOfRange);
        }
        if self.child_session_id == Some(self.parent_session_id) {
            return Err(ProcessLinkValidationError::SelfLinkNotAllowed);
        }
        if let (Some(parent_rec), Some(child_rec)) =
            (self.parent_recording_id, self.child_recording_id)
        {
            if parent_rec == child_rec {
                return Err(ProcessLinkValidationError::SelfLinkNotAllowed);
            }
        }
        match self.status {
            SessionLinkStatus::Linked => {
                if self.child_session_id.is_none() || self.gap_reason.is_some() {
                    return Err(ProcessLinkValidationError::InvalidLinkedState);
                }
            }
            SessionLinkStatus::UninstrumentedGap => {
                if self.child_session_id.is_some()
                    || self.child_recording_id.is_some()
                    || !matches!(
                        self.gap_reason,
                        Some(GapReason::ChildProcessNotInstrumented | GapReason::BootstrapConsumed)
                    )
                {
                    return Err(ProcessLinkValidationError::InvalidUninstrumentedGapState);
                }
            }
            SessionLinkStatus::CorrelationLost => {
                if self.child_recording_id.is_some()
                    || self.gap_reason != Some(GapReason::CorrelationLost)
                {
                    return Err(ProcessLinkValidationError::InvalidCorrelationLostState);
                }
            }
        }
        Ok(())
    }

    /// Returns `true` when the child session is linked cleanly without a gap.
    #[must_use]
    pub const fn is_linked(&self) -> bool {
        matches!(self.status, SessionLinkStatus::Linked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_kind_and_status_round_trip() {
        for kind in [SpawnKind::NodeWorker, SpawnKind::NodeChildProcess, SpawnKind::JvmFork] {
            let s = kind.as_str();
            assert_eq!(SpawnKind::parse(s), Some(kind));
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{s}\""));
        }
        for status in [
            SessionLinkStatus::Linked,
            SessionLinkStatus::UninstrumentedGap,
            SessionLinkStatus::CorrelationLost,
        ] {
            let s = status.as_str();
            assert_eq!(SessionLinkStatus::parse(s), Some(status));
            assert_eq!(serde_json::to_string(&status).unwrap(), format!("\"{s}\""));
        }
        assert_eq!(SpawnKind::parse("unknown"), None);
        assert_eq!(SessionLinkStatus::parse("unknown"), None);
    }

    #[test]
    fn token_hash_rejects_empty_oversized_and_control_tokens() {
        assert_eq!(
            hash_correlation_token(""),
            Err(ProcessLinkValidationError::InvalidCorrelationToken)
        );
        assert_eq!(
            hash_correlation_token("abc\n123"),
            Err(ProcessLinkValidationError::InvalidCorrelationToken)
        );
        assert_eq!(
            hash_correlation_token(&"x".repeat(MAX_CORRELATION_TOKEN_BYTES + 1)),
            Err(ProcessLinkValidationError::InvalidCorrelationToken)
        );
        let h1 = hash_correlation_token("tok-1").unwrap();
        let h2 = hash_correlation_token("tok-1").unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_correlation_token("tok-2").unwrap());
    }

    #[test]
    fn link_constructors_enforce_invariants() {
        let parent_sess = RuntimeSessionId::new();
        let child_sess = RuntimeSessionId::new();
        let parent_rec = RecordingId::new();
        let token_hash = hash_correlation_token("session-link-secret-token").unwrap();

        let linked = RuntimeSessionLink::linked(
            SessionLinkId::new(),
            parent_sess,
            Some(parent_rec),
            child_sess,
            None,
            SpawnKind::NodeWorker,
            Some(token_hash),
            1_700_000_000_000,
        )
        .unwrap();
        assert!(linked.is_linked());

        assert_eq!(
            RuntimeSessionLink::linked(
                SessionLinkId::new(),
                parent_sess,
                None,
                parent_sess,
                None,
                SpawnKind::JvmFork,
                None,
                10,
            ),
            Err(ProcessLinkValidationError::SelfLinkNotAllowed)
        );

        assert_eq!(
            RuntimeSessionLink::uninstrumented_gap(
                SessionLinkId::new(),
                parent_sess,
                None,
                SpawnKind::NodeChildProcess,
                GapReason::LineBudget,
                10,
            ),
            Err(ProcessLinkValidationError::InvalidUninstrumentedGapState)
        );

        let gap = RuntimeSessionLink::uninstrumented_gap(
            SessionLinkId::new(),
            parent_sess,
            Some(parent_rec),
            SpawnKind::JvmFork,
            GapReason::ChildProcessNotInstrumented,
            10,
        )
        .unwrap();
        assert!(!gap.is_linked());

        let lost = RuntimeSessionLink::correlation_lost(
            SessionLinkId::new(),
            parent_sess,
            Some(parent_rec),
            None,
            SpawnKind::NodeWorker,
            Some(token_hash),
            11,
        )
        .unwrap();
        assert_eq!(lost.gap_reason, Some(GapReason::CorrelationLost));
    }
}
