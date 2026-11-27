//! Application service and persistence port for parent-child runtime session linkage.
//!
//! Coordinates explicit parent/child session correlation, hashing correlation tokens before
//! persistence, and failing closed to explicit [`GapReason::ChildProcessNotInstrumented`] or
//! [`GapReason::CorrelationLost`] gaps whenever child instrumentation or matching correlation
//! evidence is missing or invalid.

use std::sync::Arc;

use xtrace_domain::{
    ContentHash, CorrelationId, GapReason, RecordingId, RuntimeSessionId, RuntimeSessionLink,
    SessionLinkId, SpawnKind, hash_correlation_token,
};

use crate::{PortError, PortErrorKind};

/// Persistence contract for parent-child runtime session links and explicit linkage gaps.
pub trait ProcessLinkagePort: Send + Sync {
    /// Persists one validated link or gap record idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Validation`] on invalid invariants, [`PortErrorKind::Conflict`]
    /// when `link_id` already exists with different fields or referenced recordings are invalid,
    /// and storage errors otherwise.
    fn record_session_link(
        &self,
        link: &RuntimeSessionLink,
    ) -> Result<RuntimeSessionLink, PortError>;

    /// Lists child links and explicit gaps emitted by `parent_session_id` in creation order.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PortError`] when storage cannot be queried.
    fn list_child_links(
        &self,
        parent_session_id: RuntimeSessionId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError>;

    /// Lists child links and explicit gaps associated with `parent_recording_id`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PortError`] when storage cannot be queried.
    fn list_child_links_for_recording(
        &self,
        parent_recording_id: RecordingId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError>;

    /// Finds the parent link record for `child_session_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PortError`] when storage cannot be queried.
    fn find_parent_link(
        &self,
        child_session_id: RuntimeSessionId,
    ) -> Result<Option<RuntimeSessionLink>, PortError>;

    /// Finds the parent link record for `child_recording_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns a typed [`PortError`] when storage cannot be queried.
    fn find_parent_link_by_recording(
        &self,
        child_recording_id: RecordingId,
    ) -> Result<Option<RuntimeSessionLink>, PortError>;
}

/// Request to record an explicit parent-child runtime session link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkChildSession {
    /// Optional caller-assigned link identity; generated when absent.
    pub link_id: Option<SessionLinkId>,
    /// Parent recording active at spawn, if any.
    pub parent_recording_id: Option<RecordingId>,
    /// Parent runtime session identity.
    pub parent_session_id: RuntimeSessionId,
    /// Linked child recording identity, if any.
    pub child_recording_id: Option<RecordingId>,
    /// Linked child runtime session identity.
    pub child_session_id: RuntimeSessionId,
    /// Spawn mechanism (`node_worker`, `node_child_process`, `jvm_fork`).
    pub spawn_kind: SpawnKind,
    /// Raw correlation token presented during handshake; hashed before storage and never kept raw.
    pub correlation_token: Option<String>,
    /// Creation timestamp in Unix epoch milliseconds.
    pub created_at_ms: u64,
}

/// Request to record an explicit process-boundary gap without fabricating a child link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordProcessGap {
    /// Optional caller-assigned link identity; generated when absent.
    pub link_id: Option<SessionLinkId>,
    /// Parent recording active at spawn, if any.
    pub parent_recording_id: Option<RecordingId>,
    /// Parent runtime session identity.
    pub parent_session_id: RuntimeSessionId,
    /// Optional child session identity when correlation failed after child handshake started.
    pub child_session_id: Option<RuntimeSessionId>,
    /// Spawn mechanism (`node_worker`, `node_child_process`, `jvm_fork`).
    pub spawn_kind: SpawnKind,
    /// Explicit gap reason (`ChildProcessNotInstrumented`, `BootstrapConsumed`, or `CorrelationLost`).
    pub reason: GapReason,
    /// Optional BLAKE3-256 hash of a correlation token involved in a failed handshake.
    pub correlation_token_hash: Option<ContentHash>,
    /// Creation timestamp in Unix epoch milliseconds.
    pub created_at_ms: u64,
}

/// Parent-side spawn expectation used when reconciling an incoming child runtime handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentSpawnClaim {
    /// Parent runtime session that spawned the child.
    pub parent_session_id: RuntimeSessionId,
    /// Parent recording active when the child spawned, if any.
    pub parent_recording_id: Option<RecordingId>,
    /// Expected spawn boundary kind.
    pub spawn_kind: SpawnKind,
    /// Expected BLAKE3-256 hash of the correlation token issued for this spawn.
    pub expected_token_hash: ContentHash,
}

/// Child-side handshake evidence presented for parent reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildHandshakeClaim {
    /// Child runtime session identity.
    pub child_session_id: RuntimeSessionId,
    /// Optional child recording identity associated with the spawn.
    pub child_recording_id: Option<RecordingId>,
    /// Spawn boundary kind declared by the child.
    pub spawn_kind: SpawnKind,
    /// Raw correlation token carried by the child, if any.
    pub correlation_token: Option<String>,
    /// Timestamp in Unix epoch milliseconds when the reconciliation occurred.
    pub created_at_ms: u64,
}

/// Use-case service managing parent-child runtime session links and fail-closed gap recording.
pub struct ProcessLinkageService<P: ProcessLinkagePort + ?Sized> {
    port: Arc<P>,
}

impl<P: ProcessLinkagePort + ?Sized> ProcessLinkageService<P> {
    /// Constructs a service over a [`ProcessLinkagePort`].
    #[must_use]
    pub const fn new(port: Arc<P>) -> Self {
        Self { port }
    }

    /// Validates, hashes any correlation token, and persists an explicit parent-child link.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Validation`] if the token or link invariants fail, or the port's
    /// persistence error.
    pub fn link_child_session(
        &self,
        request: LinkChildSession,
    ) -> Result<RuntimeSessionLink, PortError> {
        let token_hash = request
            .correlation_token
            .as_deref()
            .map(hash_correlation_token)
            .transpose()
            .map_err(|_| validation_error("correlation token is invalid"))?;
        let link = RuntimeSessionLink::linked(
            request.link_id.unwrap_or_default(),
            request.parent_session_id,
            request.parent_recording_id,
            request.child_session_id,
            request.child_recording_id,
            request.spawn_kind,
            token_hash,
            request.created_at_ms,
        )
        .map_err(|_| validation_error("process session link violates structural invariants"))?;
        self.port.record_session_link(&link)
    }

    /// Records an explicit uninstrumented-child gap (`child_process_not_instrumented` or
    /// `bootstrap_consumed`).
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Validation`] if `reason` is not an uninstrumented-child reason or
    /// the timestamp is out of bounds.
    pub fn record_uninstrumented_gap(
        &self,
        parent_session_id: RuntimeSessionId,
        parent_recording_id: Option<RecordingId>,
        spawn_kind: SpawnKind,
        reason: GapReason,
        created_at_ms: u64,
    ) -> Result<RuntimeSessionLink, PortError> {
        self.record_gap(RecordProcessGap {
            link_id: None,
            parent_recording_id,
            parent_session_id,
            child_session_id: None,
            spawn_kind,
            reason,
            correlation_token_hash: None,
            created_at_ms,
        })
    }

    /// Records an explicit `correlation_lost` gap for detached or uncorrelatable boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Validation`] on invalid invariants or the port's persistence error.
    pub fn record_correlation_lost(
        &self,
        parent_session_id: RuntimeSessionId,
        parent_recording_id: Option<RecordingId>,
        child_session_id: Option<RuntimeSessionId>,
        spawn_kind: SpawnKind,
        correlation_token_hash: Option<ContentHash>,
        created_at_ms: u64,
    ) -> Result<RuntimeSessionLink, PortError> {
        self.record_gap(RecordProcessGap {
            link_id: None,
            parent_recording_id,
            parent_session_id,
            child_session_id,
            spawn_kind,
            reason: GapReason::CorrelationLost,
            correlation_token_hash,
            created_at_ms,
        })
    }

    /// Persists an explicit process-linkage gap record (`ChildProcessNotInstrumented`,
    /// `BootstrapConsumed`, or `CorrelationLost`).
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Validation`] for unsupported gap reasons or invalid invariants.
    pub fn record_gap(&self, request: RecordProcessGap) -> Result<RuntimeSessionLink, PortError> {
        let link_id = request.link_id.unwrap_or_default();
        let link = match request.reason {
            GapReason::ChildProcessNotInstrumented | GapReason::BootstrapConsumed => {
                if request.child_session_id.is_some() || request.correlation_token_hash.is_some() {
                    return Err(validation_error(
                        "uninstrumented child gap cannot carry child_session_id or token hash",
                    ));
                }
                RuntimeSessionLink::uninstrumented_gap(
                    link_id,
                    request.parent_session_id,
                    request.parent_recording_id,
                    request.spawn_kind,
                    request.reason,
                    request.created_at_ms,
                )
            }
            GapReason::CorrelationLost => RuntimeSessionLink::correlation_lost(
                link_id,
                request.parent_session_id,
                request.parent_recording_id,
                request.child_session_id,
                request.spawn_kind,
                request.correlation_token_hash,
                request.created_at_ms,
            ),
            _ => {
                return Err(validation_error("unsupported gap reason for process linkage record"));
            }
        }
        .map_err(|_| validation_error("process linkage gap record violates invariants"))?;
        self.port.record_session_link(&link)
    }

    /// Reconciles an incoming child handshake against a known parent spawn claim.
    ///
    /// Only links when `parent` is present, the child's correlation token hashes to
    /// `parent.expected_token_hash`, `spawn_kind` matches, and parent/child IDs are distinct.
    /// Otherwise fails closed by recording an explicit [`GapReason::CorrelationLost`] gap on the
    /// parent session (when `parent` is `Some`), never guessing or fabricating a link.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::NotFound`] when `parent` is `None` (no parent session exists to
    /// attach a record to) or [`PortErrorKind::Validation`] / storage errors on invalid input.
    pub fn reconcile_child_session(
        &self,
        parent: Option<&ParentSpawnClaim>,
        child: &ChildHandshakeClaim,
    ) -> Result<RuntimeSessionLink, PortError> {
        let Some(parent) = parent else {
            return Err(PortError::new(
                PortErrorKind::NotFound,
                "parent session claim is absent; cannot correlate child session",
                CorrelationId::new(),
            ));
        };

        let token_hash = match child.correlation_token.as_deref() {
            Some(token) => match hash_correlation_token(token) {
                Ok(hash) => Some(hash),
                Err(_) => {
                    let lost = RuntimeSessionLink::correlation_lost(
                        SessionLinkId::new(),
                        parent.parent_session_id,
                        parent.parent_recording_id,
                        (child.child_session_id != parent.parent_session_id)
                            .then_some(child.child_session_id),
                        parent.spawn_kind,
                        None,
                        child.created_at_ms,
                    )
                    .map_err(|_| validation_error("invalid correlation_lost linkage state"))?;
                    return self.port.record_session_link(&lost);
                }
            },
            None => None,
        };

        let valid_match = token_hash == Some(parent.expected_token_hash)
            && child.spawn_kind == parent.spawn_kind
            && child.child_session_id != parent.parent_session_id
            && match (parent.parent_recording_id, child.child_recording_id) {
                (Some(p), Some(c)) => p != c,
                _ => true,
            };

        if valid_match {
            let linked = RuntimeSessionLink::linked(
                SessionLinkId::new(),
                parent.parent_session_id,
                parent.parent_recording_id,
                child.child_session_id,
                child.child_recording_id,
                parent.spawn_kind,
                token_hash,
                child.created_at_ms,
            )
            .map_err(|_| validation_error("invalid linked session state"))?;
            self.port.record_session_link(&linked)
        } else {
            let lost = RuntimeSessionLink::correlation_lost(
                SessionLinkId::new(),
                parent.parent_session_id,
                parent.parent_recording_id,
                (child.child_session_id != parent.parent_session_id)
                    .then_some(child.child_session_id),
                parent.spawn_kind,
                token_hash,
                child.created_at_ms,
            )
            .map_err(|_| validation_error("invalid correlation_lost linkage state"))?;
            self.port.record_session_link(&lost)
        }
    }

    /// Lists child links and explicit gaps emitted by `parent_session_id`.
    ///
    /// # Errors
    ///
    /// Propagates storage errors from [`ProcessLinkagePort::list_child_links`].
    pub fn list_child_links(
        &self,
        parent_session_id: RuntimeSessionId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        self.port.list_child_links(parent_session_id)
    }

    /// Lists child links and explicit gaps associated with `parent_recording_id`.
    ///
    /// # Errors
    ///
    /// Propagates storage errors from [`ProcessLinkagePort::list_child_links_for_recording`].
    pub fn list_child_links_for_recording(
        &self,
        parent_recording_id: RecordingId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        self.port.list_child_links_for_recording(parent_recording_id)
    }

    /// Finds the parent link for `child_session_id`, if recorded.
    ///
    /// # Errors
    ///
    /// Propagates storage errors from [`ProcessLinkagePort::find_parent_link`].
    pub fn find_parent_link(
        &self,
        child_session_id: RuntimeSessionId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        self.port.find_parent_link(child_session_id)
    }

    /// Finds the parent link for `child_recording_id`, if recorded.
    ///
    /// # Errors
    ///
    /// Propagates storage errors from [`ProcessLinkagePort::find_parent_link_by_recording`].
    pub fn find_parent_link_by_recording(
        &self,
        child_recording_id: RecordingId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        self.port.find_parent_link_by_recording(child_recording_id)
    }
}

fn validation_error(message: &'static str) -> PortError {
    PortError::new(PortErrorKind::Validation, message, CorrelationId::new())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use xtrace_domain::SessionLinkStatus;

    use super::*;

    #[derive(Default)]
    struct MemoryLinkPort {
        links: Mutex<Vec<RuntimeSessionLink>>,
    }

    impl ProcessLinkagePort for MemoryLinkPort {
        fn record_session_link(
            &self,
            link: &RuntimeSessionLink,
        ) -> Result<RuntimeSessionLink, PortError> {
            let mut guard = self.links.lock().unwrap();
            if let Some(existing) = guard.iter().find(|item| item.link_id == link.link_id) {
                if existing == link {
                    return Ok(*existing);
                }
                return Err(PortError::new(
                    PortErrorKind::Conflict,
                    "conflicting session link id",
                    CorrelationId::new(),
                ));
            }
            guard.push(*link);
            Ok(*link)
        }

        fn list_child_links(
            &self,
            parent_session_id: RuntimeSessionId,
        ) -> Result<Vec<RuntimeSessionLink>, PortError> {
            let guard = self.links.lock().unwrap();
            Ok(guard
                .iter()
                .copied()
                .filter(|item| item.parent_session_id == parent_session_id)
                .collect())
        }

        fn list_child_links_for_recording(
            &self,
            parent_recording_id: RecordingId,
        ) -> Result<Vec<RuntimeSessionLink>, PortError> {
            let guard = self.links.lock().unwrap();
            Ok(guard
                .iter()
                .copied()
                .filter(|item| item.parent_recording_id == Some(parent_recording_id))
                .collect())
        }

        fn find_parent_link(
            &self,
            child_session_id: RuntimeSessionId,
        ) -> Result<Option<RuntimeSessionLink>, PortError> {
            let guard = self.links.lock().unwrap();
            Ok(guard.iter().copied().find(|item| item.child_session_id == Some(child_session_id)))
        }

        fn find_parent_link_by_recording(
            &self,
            child_recording_id: RecordingId,
        ) -> Result<Option<RuntimeSessionLink>, PortError> {
            let guard = self.links.lock().unwrap();
            Ok(guard
                .iter()
                .copied()
                .find(|item| item.child_recording_id == Some(child_recording_id)))
        }
    }

    #[test]
    fn reconciliation_links_matching_token_and_fails_closed_otherwise() {
        let port = Arc::new(MemoryLinkPort::default());
        let service = ProcessLinkageService::new(port);

        let parent_session = RuntimeSessionId::new();
        let parent_recording = RecordingId::new();
        let child_session = RuntimeSessionId::new();
        let child_recording = RecordingId::new();
        let raw_token = "secret-worker-handshake-canary";
        let expected_hash = hash_correlation_token(raw_token).unwrap();

        let claim = ParentSpawnClaim {
            parent_session_id: parent_session,
            parent_recording_id: Some(parent_recording),
            spawn_kind: SpawnKind::NodeWorker,
            expected_token_hash: expected_hash,
        };

        // Valid match -> Linked with hashed token only.
        let linked = service
            .reconcile_child_session(
                Some(&claim),
                &ChildHandshakeClaim {
                    child_session_id: child_session,
                    child_recording_id: Some(child_recording),
                    spawn_kind: SpawnKind::NodeWorker,
                    correlation_token: Some(raw_token.to_string()),
                    created_at_ms: 100,
                },
            )
            .unwrap();
        assert_eq!(linked.status, SessionLinkStatus::Linked);
        assert_eq!(linked.correlation_token_hash, Some(expected_hash));
        assert_eq!(
            service.find_parent_link(child_session).unwrap().unwrap().parent_session_id,
            parent_session
        );
        assert_eq!(
            service.find_parent_link_by_recording(child_recording).unwrap().unwrap().link_id,
            linked.link_id
        );

        // Wrong token -> fails closed to CorrelationLost without child recording link.
        let mismatched = service
            .reconcile_child_session(
                Some(&claim),
                &ChildHandshakeClaim {
                    child_session_id: RuntimeSessionId::new(),
                    child_recording_id: Some(RecordingId::new()),
                    spawn_kind: SpawnKind::NodeWorker,
                    correlation_token: Some("wrong-token".to_string()),
                    created_at_ms: 200,
                },
            )
            .unwrap();
        assert_eq!(mismatched.status, SessionLinkStatus::CorrelationLost);
        assert_eq!(mismatched.gap_reason, Some(GapReason::CorrelationLost));
        assert_eq!(mismatched.child_recording_id, None);

        // Uninstrumented child -> explicit ChildProcessNotInstrumented gap.
        let gap = service
            .record_uninstrumented_gap(
                parent_session,
                Some(parent_recording),
                SpawnKind::JvmFork,
                GapReason::ChildProcessNotInstrumented,
                300,
            )
            .unwrap();
        assert_eq!(gap.status, SessionLinkStatus::UninstrumentedGap);
        assert_eq!(gap.gap_reason, Some(GapReason::ChildProcessNotInstrumented));
        assert_eq!(service.list_child_links(parent_session).unwrap().len(), 3);
        assert_eq!(service.list_child_links_for_recording(parent_recording).unwrap().len(), 3);
    }

    #[test]
    fn reconciliation_without_parent_claim_returns_not_found() {
        let port = Arc::new(MemoryLinkPort::default());
        let service = ProcessLinkageService::new(port);
        let err = service
            .reconcile_child_session(
                None,
                &ChildHandshakeClaim {
                    child_session_id: RuntimeSessionId::new(),
                    child_recording_id: None,
                    spawn_kind: SpawnKind::NodeChildProcess,
                    correlation_token: None,
                    created_at_ms: 1,
                },
            )
            .unwrap_err();
        assert_eq!(err.kind(), PortErrorKind::NotFound);
    }
}
