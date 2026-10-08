//! Bounded, versioned catalog-discovery proof inputs.
//!
//! These values describe a transcript. They do not authorize a producer or
//! prove that a source snapshot exists; the application/store must issue and
//! persist that authority before allocating a run.

use std::collections::BTreeSet;

use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ContentHash, RunId, SourceRevisionId, endpoint_identity::EndpointIdentity, ids::Id};

/// Canonical hash-layout version used by discovery transcripts.
pub const DISCOVERY_DIGEST_FORMAT_VERSION: u32 = 1;
/// Canonical schema version for discovery start requests.
pub const DISCOVERY_RUN_SCHEMA_VERSION: u32 = 1;
/// Maximum canonical claim payload.
pub const MAX_DISCOVERY_CLAIM_BYTES: usize = 8 * 1024;
/// Maximum source evidence items attached to one claim.
pub const MAX_CLAIM_SOURCE_EVIDENCE: usize = 8;
/// Maximum claims in one chunk.
pub const MAX_DISCOVERY_CHUNK_CLAIMS: usize = 64;
/// Maximum chunks in one run.
pub const MAX_DISCOVERY_RUN_CHUNKS: usize = 64;
/// Maximum claims in one run.
pub const MAX_DISCOVERY_RUN_CLAIMS: usize = 4096;
/// Maximum aggregate canonical claim bytes in one run.
pub const MAX_DISCOVERY_RUN_CLAIM_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded chunk bytes.
pub const MAX_DISCOVERY_CHUNK_BYTES: usize = 256 * 1024;

/// Declared static-source or runtime-registration coverage kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryScopeKind {
    /// Requested bounded scan over a source snapshot selected by the owner.
    StaticRepository,
    /// Requested bounded runtime-registration namespace.
    RuntimeRegistration,
}

impl DiscoveryScopeKind {
    const fn wire_value(self) -> u8 {
        match self {
            Self::StaticRepository => 1,
            Self::RuntimeRegistration => 2,
        }
    }
}

/// Stable coverage identity for comparing separate discovery runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryScope {
    /// Scope category.
    pub kind: DiscoveryScopeKind,
    /// Opaque requested source-root key, never a filesystem path.
    pub source_root_key: Option<String>,
    /// Owner-selected module or registration namespace.
    pub module_selector: String,
    /// Application component in the endpoint identity.
    pub application_component: String,
    /// Stable caller binding in the endpoint identity.
    pub binding_key: String,
    /// Framework family identifier.
    pub framework_family: String,
    /// Producer family identifier.
    pub producer_family: String,
    /// Digest of the exact discovery ruleset.
    pub ruleset_digest: ContentHash,
}

impl DiscoveryScope {
    /// Encodes the canonical v1 scope tuple after validating bounded fields.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        validate_ascii_identifier(&self.module_selector, 128)?;
        validate_ascii_identifier(&self.application_component, 128)?;
        validate_ascii_identifier(&self.binding_key, 128)?;
        validate_ascii_identifier(&self.framework_family, 64)?;
        validate_ascii_identifier(&self.producer_family, 64)?;
        match (self.kind, self.source_root_key.as_deref()) {
            (DiscoveryScopeKind::StaticRepository, Some(key)) => {
                validate_ascii_identifier(key, 128)?
            }
            (DiscoveryScopeKind::StaticRepository, None)
            | (DiscoveryScopeKind::RuntimeRegistration, Some(_)) => {
                return Err(DiscoveryProofError::InvalidScope);
            }
            (DiscoveryScopeKind::RuntimeRegistration, None) => {}
        }
        let mut bytes = Vec::with_capacity(256);
        let mut enc = Encoder::new(&mut bytes);
        enc.array(10)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str("xtrace.discovery-scope")
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u32(DISCOVERY_DIGEST_FORMAT_VERSION)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u8(self.kind.wire_value())
            .map_err(|_| DiscoveryProofError::Encoding)?;
        encode_optional_text(&mut enc, self.source_root_key.as_deref())?;
        enc.str(&self.module_selector)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&self.application_component)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&self.binding_key)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&self.framework_family)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&self.producer_family)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .bytes(self.ruleset_digest.as_bytes())
            .map_err(|_| DiscoveryProofError::Encoding)?;
        Ok(bytes)
    }

    /// BLAKE3 identity of this immutable coverage declaration.
    pub fn digest(&self) -> Result<ContentHash, DiscoveryProofError> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes()?))
    }
}

/// Structurally validated producer source-evidence claims.
///
/// These variants do not establish source authority. The application/store
/// must independently bind static bytes or loaded-class metadata before any
/// persisted or displayed value can be called verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimSourceEvidence {
    /// Producer claim shaped like evidence from an immutable source revision.
    StaticSnapshot {
        /// Immutable source revision the producer claims the range belongs to.
        source_revision_id: SourceRevisionId,
        /// Repository-relative path of the source file within that revision.
        relative_path: String,
        /// Digest of the source bytes as recorded by the producer.
        recorded_source_digest: ContentHash,
        /// 1-based first line of the cited range.
        start_line: u32,
        /// 1-based first column of the cited range.
        start_column: u32,
        /// 1-based last line of the cited range.
        end_line: u32,
        /// 1-based last column of the cited range.
        end_column: u32,
    },
    /// Producer claim shaped like a loaded-class attestation.
    LoadedClassBound {
        /// Digest of the loaded class bytes the producer attests to.
        loaded_class_digest: ContentHash,
        /// Repository-relative path of the source file the class maps to.
        relative_path: String,
        /// Digest of the source bytes as recorded by the producer.
        recorded_source_digest: ContentHash,
        /// 1-based first line of the cited range.
        start_line: u32,
        /// 1-based first column of the cited range.
        start_column: u32,
        /// 1-based last line of the cited range.
        end_line: u32,
        /// 1-based last column of the cited range.
        end_column: u32,
    },
    /// Unverified producer location hint.
    RuntimeHint {
        /// Repository-relative path the runtime reported, when it reported one.
        relative_path: Option<String>,
        /// Source digest the runtime reported, when it reported one.
        reported_source_digest: Option<ContentHash>,
        // Runtime hints may omit all coordinates or provide a 1-based start
        // pair with an optional 1-based end pair; an end without a start is invalid.
        /// Optional 1-based first line of the hinted range.
        start_line: Option<u32>,
        /// Optional 1-based first column of the hinted range.
        start_column: Option<u32>,
        /// Optional 1-based last line of the hinted range.
        end_line: Option<u32>,
        /// Optional 1-based last column of the hinted range.
        end_column: Option<u32>,
    },
    /// Creation-time absence or denial with an optional prior digest.
    Unavailable {
        /// Closed-vocabulary code explaining why evidence could not be captured.
        reason_code: String,
        /// Repository-relative path involved, when known.
        relative_path: Option<String>,
        /// Previously recorded source digest, when one existed.
        recorded_source_digest: Option<ContentHash>,
    },
}

impl ClaimSourceEvidence {
    fn canonical_bytes(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        let mut bytes = Vec::with_capacity(256);
        let mut enc = Encoder::new(&mut bytes);
        match self {
            Self::StaticSnapshot {
                source_revision_id,
                relative_path,
                recorded_source_digest,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                validate_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(8)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str("static-snapshot")
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(source_revision_id.as_uuid().as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(relative_path)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(recorded_source_digest.as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
            }
            Self::LoadedClassBound {
                loaded_class_digest,
                relative_path,
                recorded_source_digest,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                validate_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(8)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str("loaded-class-bound")
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(loaded_class_digest.as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(relative_path)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(recorded_source_digest.as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
            }
            Self::RuntimeHint {
                relative_path,
                reported_source_digest,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                if let Some(path) = relative_path {
                    validate_relative_path(path)?;
                }
                validate_optional_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(7)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str("runtime-hint")
                    .map_err(|_| DiscoveryProofError::Encoding)?;
                encode_optional_text(&mut enc, relative_path.as_deref())?;
                encode_optional_hash(&mut enc, reported_source_digest.as_ref())?;
                encode_optional_u32(&mut enc, *start_line)?;
                encode_optional_u32(&mut enc, *start_column)?;
                encode_optional_u32(&mut enc, *end_line)?;
                encode_optional_u32(&mut enc, *end_column)?;
            }
            Self::Unavailable { reason_code, relative_path, recorded_source_digest } => {
                validate_unavailable_reason(reason_code)?;
                if let Some(path) = relative_path {
                    validate_relative_path(path)?;
                }
                enc.array(4)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str("unavailable")
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(reason_code)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
                encode_optional_text(&mut enc, relative_path.as_deref())?;
                encode_optional_hash(&mut enc, recorded_source_digest.as_ref())?;
            }
        }
        Ok(bytes)
    }
}

/// Claim provenance values fixed by XTP-Agent v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimProvenance {
    /// Inferred from static analysis of source without running the program.
    StaticInferred,
    /// Discovered from a running program's own registration or metadata.
    RuntimeDiscovered,
    /// Backed by a complete recorded observation; needs a recording proof.
    Observed,
    /// Backed by an incomplete recorded observation; needs a recording proof.
    PartialObservation,
    /// Taken from an imported API specification.
    ImportedSpec,
    /// Declared directly by a user.
    UserDeclared,
}

impl ClaimProvenance {
    const fn wire_value(self) -> u8 {
        match self {
            Self::StaticInferred => 1,
            Self::RuntimeDiscovered => 2,
            Self::Observed => 3,
            Self::PartialObservation => 4,
            Self::ImportedSpec => 5,
            Self::UserDeclared => 6,
        }
    }
}

/// Structurally validated and canonicalized claim input.
///
/// The immutable cached bytes prevent proof drift after construction. This
/// type does not establish authority or prove its source-evidence variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEndpointClaim {
    /// Producer-local retry hint; not a public claim ID.
    claim_hint: String,
    /// Exact operation identity, fingerprinted with ADR-0001 v1.
    operation: EndpointIdentity,
    /// Claim provenance.
    provenance: ClaimProvenance,
    /// Optional bounded handler symbol, excluded from operation identity.
    handler_symbol: Option<String>,
    /// Exact f32-to-basis-point conversion, or null for the -1 sentinel.
    confidence_basis_points: Option<u16>,
    /// Sorted and deduplicated closed-vocabulary limitation codes.
    limitation_codes: Vec<String>,
    /// Structurally validated source-evidence claims.
    source_evidence: Vec<ClaimSourceEvidence>,
    /// Canonical bytes are internal and are not part of any client DTO.
    canonical_bytes: Vec<u8>,
    /// Digest of these immutable canonical input bytes.
    digest: Option<ContentHash>,
}

impl ValidatedEndpointClaim {
    /// Validates bounds and canonicalizes the immutable claim evidence.
    pub fn new(
        claim_hint: String,
        operation: EndpointIdentity,
        provenance: ClaimProvenance,
        handler_symbol: Option<String>,
        confidence: f32,
        mut limitation_codes: Vec<String>,
        mut source_evidence: Vec<ClaimSourceEvidence>,
    ) -> Result<Self, DiscoveryProofError> {
        validate_ascii_identifier(&claim_hint, 128)?;
        validate_ascii_identifier(&operation.application_component, 128)?;
        validate_ascii_identifier(&operation.binding_key, 128)?;
        validate_relative_route(&operation.route_template)?;
        if let Some(symbol) = &handler_symbol {
            if symbol.is_empty()
                || symbol.len() > 512
                || !symbol.is_ascii()
                || symbol.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(DiscoveryProofError::InvalidClaim);
            }
        }
        // P03A does not have a persisted recording-to-claim proof port yet.
        // A RecordingId supplied by a producer would be a claim, not authority.
        if matches!(provenance, ClaimProvenance::Observed | ClaimProvenance::PartialObservation) {
            return Err(DiscoveryProofError::RecordingProofRequired);
        }
        let confidence_basis_points = confidence_to_basis_points(confidence)?;
        if source_evidence.len() > MAX_CLAIM_SOURCE_EVIDENCE {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        let mut seen = BTreeSet::new();
        let mut keyed_evidence = Vec::with_capacity(source_evidence.len());
        for evidence in source_evidence {
            let semantic_key = evidence.semantic_key()?;
            if !seen.insert(semantic_key) {
                return Err(DiscoveryProofError::DuplicateSourceEvidence);
            }
            let canonical = evidence.canonical_bytes()?;
            keyed_evidence.push((canonical, evidence));
        }
        keyed_evidence.sort_by(|left, right| left.0.cmp(&right.0));
        source_evidence = keyed_evidence.into_iter().map(|(_, evidence)| evidence).collect();
        if limitation_codes.len() > 64 {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        for code in &limitation_codes {
            validate_limitation_code(code)?;
        }
        limitation_codes.sort();
        limitation_codes.dedup();
        let identity_bytes =
            operation.canonical_bytes().map_err(|_| DiscoveryProofError::Encoding)?;
        let mut canonical_bytes = Vec::with_capacity(512);
        let mut enc = Encoder::new(&mut canonical_bytes);
        enc.array(9)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str("xtrace.discovery-claim")
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u32(DISCOVERY_DIGEST_FORMAT_VERSION)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&claim_hint)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .bytes(&identity_bytes)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u8(provenance.wire_value())
            .map_err(|_| DiscoveryProofError::Encoding)?;
        encode_optional_text(&mut enc, handler_symbol.as_deref())?;
        encode_optional_u16(&mut enc, confidence_basis_points)?;
        enc.array(limitation_codes.len() as u64).map_err(|_| DiscoveryProofError::Encoding)?;
        for code in &limitation_codes {
            enc.str(code).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        enc.array(source_evidence.len() as u64).map_err(|_| DiscoveryProofError::Encoding)?;
        for evidence in &source_evidence {
            let tuple = evidence.canonical_bytes()?;
            enc.writer_mut().extend_from_slice(&tuple);
        }
        if canonical_bytes.len() > MAX_DISCOVERY_CLAIM_BYTES {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        let digest = ContentHash::of_bytes(&canonical_bytes);
        Ok(Self {
            claim_hint,
            operation,
            provenance,
            handler_symbol,
            confidence_basis_points,
            limitation_codes,
            source_evidence,
            canonical_bytes,
            digest: Some(digest),
        })
    }

    /// Rebuilds a persisted typed claim through the same validator used for
    /// inbound data. Stored rows are not trusted merely because their JSON
    /// deserializes; the canonical bytes and digest are regenerated.
    pub fn from_persisted(
        claim_hint: String,
        operation: EndpointIdentity,
        provenance: ClaimProvenance,
        handler_symbol: Option<String>,
        confidence_basis_points: Option<u16>,
        limitation_codes: Vec<String>,
        source_evidence: Vec<ClaimSourceEvidence>,
    ) -> Result<Self, DiscoveryProofError> {
        let confidence =
            confidence_basis_points.map_or(-1.0, |basis_points| f32::from(basis_points) / 10_000.0);
        let claim = Self::new(
            claim_hint,
            operation,
            provenance,
            handler_symbol,
            confidence,
            limitation_codes,
            source_evidence,
        )?;
        if claim.confidence_basis_points != confidence_basis_points {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        Ok(claim)
    }

    /// Canonical v1 claim bytes used by the store and transcript hashes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Producer-local retry hint; not a public claim ID.
    #[must_use]
    pub fn claim_hint(&self) -> &str {
        &self.claim_hint
    }

    /// Endpoint identity under the unchanged ADR-0001 v1 tuple.
    #[must_use]
    pub const fn operation(&self) -> &EndpointIdentity {
        &self.operation
    }

    /// Structurally validated provenance declaration.
    #[must_use]
    pub const fn provenance(&self) -> ClaimProvenance {
        self.provenance
    }

    /// Bounded handler label, if present. It is not source verification.
    #[must_use]
    pub fn handler_symbol(&self) -> Option<&str> {
        self.handler_symbol.as_deref()
    }

    /// Exact f32 confidence conversion, or `None` for the -1 sentinel.
    #[must_use]
    pub const fn confidence_basis_points(&self) -> Option<u16> {
        self.confidence_basis_points
    }

    /// Validated finite limitation codes.
    #[must_use]
    pub fn limitation_codes(&self) -> &[String] {
        &self.limitation_codes
    }

    /// Structurally validated source-evidence claims, not verified source.
    #[must_use]
    pub fn source_evidence(&self) -> &[ClaimSourceEvidence] {
        &self.source_evidence
    }

    /// BLAKE3 digest of the immutable canonical input bytes.
    #[must_use]
    pub const fn digest(&self) -> Option<ContentHash> {
        self.digest
    }
}

/// Structurally validated chunk of claim inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryChunk {
    /// Claimed run identity, checked against the admitted run by the application.
    pub run_id: crate::RunId,
    /// Zero-based ordered index.
    pub chunk_index: u32,
    /// Claims in producer order.
    pub claims: Vec<ValidatedEndpointClaim>,
}

impl DiscoveryChunk {
    /// Encodes a bounded chunk retaining claim order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        if self.chunk_index as usize >= MAX_DISCOVERY_RUN_CHUNKS
            || self.claims.is_empty()
            || self.claims.len() > MAX_DISCOVERY_CHUNK_CLAIMS
        {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        let mut payload_bytes = 0_usize;
        for claim in &self.claims {
            payload_bytes = payload_bytes
                .checked_add(claim.canonical_bytes.len())
                .ok_or(DiscoveryProofError::LimitExceeded)?;
            if payload_bytes > MAX_DISCOVERY_CHUNK_BYTES {
                return Err(DiscoveryProofError::LimitExceeded);
            }
        }
        let mut bytes = Vec::with_capacity(128 + self.claims.len() * 32);
        let mut enc = Encoder::new(&mut bytes);
        enc.array(5)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str("xtrace.discovery-chunk")
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u32(DISCOVERY_DIGEST_FORMAT_VERSION)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .bytes(self.run_id.as_uuid().as_bytes())
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u32(self.chunk_index)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .array(self.claims.len() as u64)
            .map_err(|_| DiscoveryProofError::Encoding)?;
        for claim in &self.claims {
            enc.bytes(claim.digest.ok_or(DiscoveryProofError::InvalidClaim)?.as_bytes())
                .map_err(|_| DiscoveryProofError::Encoding)?;
        }
        if bytes.len() > MAX_DISCOVERY_CHUNK_BYTES {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// BLAKE3 digest of the ordered chunk transcript.
    pub fn digest(&self) -> Result<ContentHash, DiscoveryProofError> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes()?))
    }
}

/// Declared terminal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryCompletion {
    /// Exact scope fully enumerated.
    Complete,
    /// Bounded, known gaps remain.
    Incomplete,
    /// Producer reported terminal failure.
    Failed,
}

/// Producer-declared terminal data, validated against the staged typed chunks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRunFinish {
    /// Claimed run identity, checked against the admitted run by the application.
    pub run_id: RunId,
    /// Expected contiguous chunk count.
    pub expected_chunk_count: u32,
    /// Declared accepted claims.
    pub accepted_claim_count: u32,
    /// Declared rejected claims.
    pub rejected_claim_count: u32,
    /// Final digest of ordered chunk proofs and terminal fields.
    pub final_digest: ContentHash,
    /// Declared terminal completeness.
    pub completion: DiscoveryCompletion,
    /// Sorted, deduplicated closed-vocabulary declared gap codes.
    pub limitation_codes: Vec<String>,
}

impl DiscoveryRunFinish {
    /// Checks the declaration against the supplied immutable typed transcript.
    /// This structural proof is not a persisted run or owner-authorization.
    pub fn validate_against(
        &self,
        scope: &DiscoveryScope,
        source_revision_id: Option<SourceRevisionId>,
        chunks: &[DiscoveryChunk],
    ) -> Result<(), DiscoveryProofError> {
        if self.limitation_codes.len() > 64
            || self.limitation_codes.iter().any(|code| validate_limitation_code(code).is_err())
            || self.limitation_codes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        if (scope.kind == DiscoveryScopeKind::StaticRepository) != source_revision_id.is_some() {
            return Err(DiscoveryProofError::InvalidScope);
        }
        if self.expected_chunk_count as usize != chunks.len() {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        let expected = final_digest(
            self.run_id,
            scope,
            source_revision_id,
            chunks,
            self.rejected_claim_count,
            self.completion,
        )?;
        if expected != self.final_digest {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        let accepted = chunks.iter().try_fold(0_usize, |total, chunk| {
            total.checked_add(chunk.claims.len()).ok_or(DiscoveryProofError::LimitExceeded)
        })?;
        if accepted != self.accepted_claim_count as usize {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        if self.completion == DiscoveryCompletion::Complete
            && (self.rejected_claim_count != 0 || !self.limitation_codes.is_empty())
        {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        Ok(())
    }
}

/// Computes the v1 final digest after checking the ordered typed run payload.
pub fn final_digest(
    run_id: RunId,
    scope: &DiscoveryScope,
    source_revision_id: Option<SourceRevisionId>,
    chunks: &[DiscoveryChunk],
    rejected_claim_count: u32,
    completion: DiscoveryCompletion,
) -> Result<ContentHash, DiscoveryProofError> {
    if chunks.len() > MAX_DISCOVERY_RUN_CHUNKS
        || (scope.kind == DiscoveryScopeKind::StaticRepository) != source_revision_id.is_some()
    {
        return Err(DiscoveryProofError::LimitExceeded);
    }
    let mut chunk_digests = Vec::with_capacity(chunks.len());
    let mut accepted_claim_count = 0_usize;
    let mut accepted_claim_bytes = 0_usize;
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.run_id != run_id || chunk.chunk_index as usize != index {
            return Err(DiscoveryProofError::InvalidClaim);
        }
        let chunk_bytes = chunk.canonical_bytes()?;
        accepted_claim_count = accepted_claim_count
            .checked_add(chunk.claims.len())
            .ok_or(DiscoveryProofError::LimitExceeded)?;
        for claim in &chunk.claims {
            accepted_claim_bytes = accepted_claim_bytes
                .checked_add(claim.canonical_bytes.len())
                .ok_or(DiscoveryProofError::LimitExceeded)?;
        }
        if accepted_claim_count > MAX_DISCOVERY_RUN_CLAIMS
            || accepted_claim_bytes > MAX_DISCOVERY_RUN_CLAIM_BYTES
        {
            return Err(DiscoveryProofError::LimitExceeded);
        }
        chunk_digests.push(ContentHash::of_bytes(&chunk_bytes));
    }
    let rejected = rejected_claim_count as usize;
    if accepted_claim_count.checked_add(rejected).ok_or(DiscoveryProofError::LimitExceeded)?
        > MAX_DISCOVERY_RUN_CLAIMS
        || completion == DiscoveryCompletion::Complete && rejected != 0
    {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    let scope_digest = scope.digest()?;
    let bytes = final_canonical_bytes(
        run_id,
        scope_digest,
        source_revision_id,
        &chunk_digests,
        accepted_claim_count as u32,
        rejected_claim_count,
        completion,
    )?;
    Ok(ContentHash::of_bytes(&bytes))
}

fn final_canonical_bytes(
    run_id: RunId,
    scope_digest: ContentHash,
    source_revision_id: Option<SourceRevisionId>,
    chunk_digests: &[ContentHash],
    accepted_claim_count: u32,
    rejected_claim_count: u32,
    completion: DiscoveryCompletion,
) -> Result<Vec<u8>, DiscoveryProofError> {
    let mut bytes = Vec::with_capacity(160 + chunk_digests.len() * 34);
    let mut enc = Encoder::new(&mut bytes);
    enc.array(9)
        .map_err(|_| DiscoveryProofError::Encoding)?
        .str("xtrace.discovery-final")
        .map_err(|_| DiscoveryProofError::Encoding)?
        .u32(DISCOVERY_DIGEST_FORMAT_VERSION)
        .map_err(|_| DiscoveryProofError::Encoding)?
        .bytes(run_id.as_uuid().as_bytes())
        .map_err(|_| DiscoveryProofError::Encoding)?
        .bytes(scope_digest.as_bytes())
        .map_err(|_| DiscoveryProofError::Encoding)?;
    match source_revision_id {
        Some(id) => {
            enc.bytes(id.as_uuid().as_bytes()).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        None => {
            enc.null().map_err(|_| DiscoveryProofError::Encoding)?;
        }
    }
    enc.array(chunk_digests.len() as u64).map_err(|_| DiscoveryProofError::Encoding)?;
    for digest in chunk_digests {
        enc.bytes(digest.as_bytes()).map_err(|_| DiscoveryProofError::Encoding)?;
    }
    enc.u32(accepted_claim_count)
        .map_err(|_| DiscoveryProofError::Encoding)?
        .u32(rejected_claim_count)
        .map_err(|_| DiscoveryProofError::Encoding)?
        .u8(match completion {
            DiscoveryCompletion::Complete => 1,
            DiscoveryCompletion::Incomplete => 2,
            DiscoveryCompletion::Failed => 3,
        })
        .map_err(|_| DiscoveryProofError::Encoding)?;
    Ok(bytes)
}

/// Untrusted start request to validate before any core identifier is allocated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRunStartRequest {
    /// Fixed canonical request schema version.
    pub schema_version: u32,
    /// Producer-local retry hint.
    pub run_hint: String,
    /// Requested immutable coverage.
    pub requested_scope: DiscoveryScope,
    /// Opaque requested owner-selection reference; not authorization itself.
    pub owner_selection_ref: Option<String>,
}

impl DiscoveryRunStartRequest {
    /// Validates bounded request fields. This does not authorize the owner scope.
    pub fn validate(&self) -> Result<(), DiscoveryProofError> {
        if self.schema_version != DISCOVERY_RUN_SCHEMA_VERSION {
            return Err(DiscoveryProofError::InvalidScope);
        }
        validate_ascii_identifier(&self.run_hint, 128)?;
        self.requested_scope.canonical_bytes()?;
        if let Some(owner_ref) = &self.owner_selection_ref {
            validate_ascii_identifier(owner_ref, 128)?;
        }
        Ok(())
    }

    /// Encodes the exact bounded request tuple used for retry identity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        self.validate()?;
        let scope = self.requested_scope.canonical_bytes()?;
        let mut bytes = Vec::with_capacity(64 + scope.len());
        let mut enc = Encoder::new(&mut bytes);
        enc.array(5)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str("xtrace.discovery-start")
            .map_err(|_| DiscoveryProofError::Encoding)?
            .u32(self.schema_version)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .str(&self.run_hint)
            .map_err(|_| DiscoveryProofError::Encoding)?
            .bytes(&scope)
            .map_err(|_| DiscoveryProofError::Encoding)?;
        encode_optional_text(&mut enc, self.owner_selection_ref.as_deref())?;
        Ok(bytes)
    }
}

/// Structural shape for an admission result or safe refusal.
///
/// Constructing or deserializing this value does not issue a run ID or prove
/// that an owner selection was persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoveryRunGrant {
    /// Claimed admission fields; only the application transaction can issue them.
    Admitted {
        /// Claimed core-issued run ID; this DTO does not issue it.
        run_id: RunId,
        /// Resolved stable scope identity.
        scope_digest: ContentHash,
        /// Claimed resolved static snapshot revision.
        source_revision_id: Option<SourceRevisionId>,
    },
    /// Refusal leaves catalog and public IDs unchanged.
    Refused {
        /// Stable closed reason.
        reason: DiscoveryRefusal,
    },
}

/// Closed reasons why discovery cannot be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryRefusal {
    /// Manifest lacks independent verification.
    UnverifiedManifest,
    /// No immutable owner selection authorizes scope.
    OwnerSelectionRequired,
    /// Negotiated capability is absent.
    CapabilityNotNegotiated,
    /// Requested scope differs from selection.
    ScopeNotAuthorized,
    /// Pinned source revision is unavailable.
    SourceSnapshotUnavailable,
}

/// Safe closed failures for canonical discovery proofs.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DiscoveryProofError {
    /// Canonical CBOR encoding failed.
    #[error("discovery proof encoding failed")]
    Encoding,
    /// Scope or endpoint identity has invalid bounded fields.
    #[error("discovery scope is invalid")]
    InvalidScope,
    /// Claim data is invalid or has untrusted proof metadata.
    #[error("discovery claim is invalid")]
    InvalidClaim,
    /// Recording-backed provenance requires durable recording evidence.
    #[error("recording evidence is required")]
    RecordingProofRequired,
    /// Duplicate semantic source evidence was supplied.
    #[error("duplicate source evidence")]
    DuplicateSourceEvidence,
    /// A declared size or count bound was exceeded.
    #[error("discovery proof exceeds a bounded limit")]
    LimitExceeded,
}

/// Converts an IEEE-754 f32 to exact ties-to-even basis points.
pub fn confidence_to_basis_points(value: f32) -> Result<Option<u16>, DiscoveryProofError> {
    let bits = value.to_bits();
    if bits == (-1.0_f32).to_bits() {
        return Ok(None);
    }
    if bits == (-0.0_f32).to_bits() {
        return Ok(Some(0));
    }
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    let exponent = ((bits >> 23) & 0xff) as i32;
    let fraction = bits & 0x7f_ffff;
    let (significand, power) = if exponent == 0 {
        (u128::from(fraction), -149_i32)
    } else {
        (u128::from((1 << 23) | fraction), exponent - 127 - 23)
    };
    let numerator = significand * 10_000;
    let rounded = if power >= 0 {
        numerator << power as u32
    } else {
        let shift = (-power) as u32;
        if shift >= 128 {
            0
        } else {
            let denominator = 1_u128 << shift;
            let quotient = numerator / denominator;
            let remainder = numerator % denominator;
            if remainder * 2 > denominator || (remainder * 2 == denominator && quotient % 2 == 1) {
                quotient + 1
            } else {
                quotient
            }
        }
    };
    u16::try_from(rounded).map(Some).map_err(|_| DiscoveryProofError::InvalidClaim)
}

fn validate_ascii_identifier(value: &str, max: usize) -> Result<(), DiscoveryProofError> {
    if value.is_empty()
        || value.len() > max
        || !value.is_ascii()
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(DiscoveryProofError::InvalidScope);
    }
    Ok(())
}
const DISCOVERY_LIMITATION_CODES: &[&str] = &[
    "backpressure_dropped",
    "capability_unsupported",
    "daemon_shed",
    "debug_metadata_absent",
    "generated_source_skipped",
    "handler_unresolved",
    "missing_body_schema",
    "missing_response_schema",
    "missing_source_map",
    "no_local_variable_table",
    "route_constraint_unresolved",
    "scan_budget_exceeded",
    "session_ended_early",
    "source_attestation_missing",
    "source_hash_mismatch",
    "source_range_unavailable",
    "unsupported_mapping",
];

const SOURCE_UNAVAILABLE_REASONS: &[&str] = &[
    "attestation_missing",
    "debug_metadata_absent",
    "not_bound",
    "not_reported",
    "source_denied",
    "source_metadata_invalid",
    "source_mismatch",
];

fn validate_limitation_code(value: &str) -> Result<(), DiscoveryProofError> {
    if DISCOVERY_LIMITATION_CODES.contains(&value) {
        Ok(())
    } else {
        Err(DiscoveryProofError::InvalidClaim)
    }
}

fn validate_unavailable_reason(value: &str) -> Result<(), DiscoveryProofError> {
    if SOURCE_UNAVAILABLE_REASONS.contains(&value) {
        Ok(())
    } else {
        Err(DiscoveryProofError::InvalidClaim)
    }
}
fn validate_relative_path(path: &str) -> Result<(), DiscoveryProofError> {
    let bytes = path.as_bytes();
    let is_drive_qualified = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || is_drive_qualified
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    Ok(())
}
fn validate_relative_route(route: &str) -> Result<(), DiscoveryProofError> {
    if route.is_empty()
        || route.len() > 1024
        || !route.starts_with('/')
        || route.bytes().any(|b| b.is_ascii_control())
        || route.contains('?')
        || route.contains('#')
    {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    Ok(())
}
fn validate_range(sl: u32, sc: u32, el: u32, ec: u32) -> Result<(), DiscoveryProofError> {
    if sl == 0 || sc == 0 || el == 0 || ec == 0 || el < sl || (el == sl && ec < sc) {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    Ok(())
}
fn validate_optional_range(
    sl: Option<u32>,
    sc: Option<u32>,
    el: Option<u32>,
    ec: Option<u32>,
) -> Result<(), DiscoveryProofError> {
    if sl.is_some() != sc.is_some() || el.is_some() != ec.is_some() || el.is_some() && sl.is_none()
    {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    match (sl, sc, el, ec) {
        (None, None, None, None) => {}
        (Some(sl), Some(sc), None, None) => {
            if sl == 0 || sc == 0 {
                return Err(DiscoveryProofError::InvalidClaim);
            }
        }
        (Some(sl), Some(sc), Some(el), Some(ec)) => validate_range(sl, sc, el, ec)?,
        _ => return Err(DiscoveryProofError::InvalidClaim),
    }
    Ok(())
}
impl ClaimSourceEvidence {
    fn semantic_key(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        let mut bytes = Vec::with_capacity(128);
        let mut enc = Encoder::new(&mut bytes);
        match self {
            Self::StaticSnapshot {
                source_revision_id,
                relative_path,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                validate_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(7)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(1)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(source_revision_id.as_uuid().as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(relative_path)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
            }
            Self::LoadedClassBound {
                loaded_class_digest,
                relative_path,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                validate_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(7)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(2)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .bytes(loaded_class_digest.as_bytes())
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(relative_path)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*start_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_line)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u32(*end_column)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
            }
            Self::RuntimeHint {
                relative_path,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                if let Some(path) = relative_path {
                    validate_relative_path(path)?;
                }
                validate_optional_range(*start_line, *start_column, *end_line, *end_column)?;
                enc.array(6)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(3)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
                encode_optional_text(&mut enc, relative_path.as_deref())?;
                encode_optional_u32(&mut enc, *start_line)?;
                encode_optional_u32(&mut enc, *start_column)?;
                encode_optional_u32(&mut enc, *end_line)?;
                encode_optional_u32(&mut enc, *end_column)?;
            }
            Self::Unavailable { reason_code, relative_path, .. } => {
                validate_unavailable_reason(reason_code)?;
                if let Some(path) = relative_path {
                    validate_relative_path(path)?;
                }
                enc.array(2)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(4)
                    .map_err(|_| DiscoveryProofError::Encoding)?;
                encode_optional_text(&mut enc, relative_path.as_deref())?;
            }
        }
        Ok(bytes)
    }
}
fn encode_optional_text(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: Option<&str>,
) -> Result<(), DiscoveryProofError> {
    match value {
        Some(text) => {
            enc.str(text).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        None => {
            enc.null().map_err(|_| DiscoveryProofError::Encoding)?;
        }
    }
    Ok(())
}
fn encode_optional_hash(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: Option<&ContentHash>,
) -> Result<(), DiscoveryProofError> {
    match value {
        Some(hash) => {
            enc.bytes(hash.as_bytes()).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        None => {
            enc.null().map_err(|_| DiscoveryProofError::Encoding)?;
        }
    }
    Ok(())
}
fn encode_optional_u32(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: Option<u32>,
) -> Result<(), DiscoveryProofError> {
    match value {
        Some(value) => {
            enc.u32(value).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        None => {
            enc.null().map_err(|_| DiscoveryProofError::Encoding)?;
        }
    }
    Ok(())
}
fn encode_optional_u16(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: Option<u16>,
) -> Result<(), DiscoveryProofError> {
    match value {
        Some(value) => {
            enc.u16(value).map_err(|_| DiscoveryProofError::Encoding)?;
        }
        None => {
            enc.null().map_err(|_| DiscoveryProofError::Encoding)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "fixed public fixtures")]
mod tests {
    use super::*;
    use crate::{
        ProjectId,
        catalog::{HttpMethod, Transport},
    };
    use uuid::Uuid;
    fn project() -> ProjectId {
        ProjectId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap())
    }
    fn scope() -> DiscoveryScope {
        DiscoveryScope {
            kind: DiscoveryScopeKind::StaticRepository,
            source_root_key: Some("fixture-root".to_owned()),
            module_selector: "orders".to_owned(),
            application_component: "spring-fixture".to_owned(),
            binding_key: "default".to_owned(),
            framework_family: "spring-mvc".to_owned(),
            producer_family: "java".to_owned(),
            ruleset_digest: ContentHash::from_digest_bytes(&[0x11; 32]).unwrap(),
        }
    }
    fn identity() -> EndpointIdentity {
        EndpointIdentity {
            project_id: project(),
            application_component: "spring-fixture".to_owned(),
            binding_key: "default".to_owned(),
            transport: Transport::Http,
            method: HttpMethod::Post,
            route_template: "/orders".to_owned(),
        }
    }
    fn claim(confidence: f32) -> ValidatedEndpointClaim {
        ValidatedEndpointClaim::new(
            "post-orders".to_owned(),
            identity(),
            ClaimProvenance::StaticInferred,
            Some("OrdersController#create".to_owned()),
            confidence,
            vec!["missing_body_schema".to_owned(); 2],
            vec![ClaimSourceEvidence::Unavailable {
                reason_code: "not_bound".to_owned(),
                relative_path: None,
                recorded_source_digest: None,
            }],
        )
        .unwrap()
    }

    fn fixture_claim(confidence: f32) -> ValidatedEndpointClaim {
        ValidatedEndpointClaim::new(
            "post-orders".to_owned(),
            identity(),
            ClaimProvenance::StaticInferred,
            Some("OrdersController#create".to_owned()),
            confidence,
            Vec::new(),
            vec![ClaimSourceEvidence::StaticSnapshot {
                source_revision_id: SourceRevisionId::from_uuid(
                    Uuid::parse_str("018f0000-0000-7000-8000-000000000003").unwrap(),
                ),
                relative_path: "src/Orders.java".to_owned(),
                recorded_source_digest: ContentHash::from_digest_bytes(&[0x22; 32]).unwrap(),
                start_line: 1,
                start_column: 1,
                end_line: 2,
                end_column: 1,
            }],
        )
        .unwrap()
    }

    fn large_claim(seed: u32) -> ValidatedEndpointClaim {
        let evidence = (0..MAX_CLAIM_SOURCE_EVIDENCE)
            .map(|index| ClaimSourceEvidence::StaticSnapshot {
                source_revision_id: SourceRevisionId::from_uuid(Uuid::from_u128(
                    0x018f_0000_0000_7000_8000_0000_0000_0003
                        + u128::try_from(index).expect("evidence index fits u128"),
                )),
                relative_path: format!("src/{seed:04}/{index:02}/{}", "x".repeat(480)),
                recorded_source_digest: ContentHash::from_digest_bytes(&[index as u8; 32]).unwrap(),
                start_line: 1,
                start_column: 1,
                end_line: 2,
                end_column: 1,
            })
            .collect();
        ValidatedEndpointClaim::new(
            format!("claim-{seed}"),
            identity(),
            ClaimProvenance::StaticInferred,
            None,
            -1.0,
            Vec::new(),
            evidence,
        )
        .unwrap()
    }

    fn run_id() -> RunId {
        RunId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap())
    }

    fn source_revision() -> SourceRevisionId {
        SourceRevisionId::from_uuid(
            Uuid::parse_str("018f0000-0000-7000-8000-000000000003").unwrap(),
        )
    }
    #[test]
    fn confidence_uses_exact_rational_ties_to_even_and_sentinel() {
        assert_eq!(confidence_to_basis_points(-1.0).unwrap(), None);
        assert_eq!(confidence_to_basis_points(0.0).unwrap(), Some(0));
        assert_eq!(confidence_to_basis_points(-0.0).unwrap(), Some(0));
        assert_eq!(confidence_to_basis_points(0.5).unwrap(), Some(5000));
        assert_eq!(confidence_to_basis_points(1.0).unwrap(), Some(10000));
        assert_eq!(confidence_to_basis_points(f32::from_bits(0x3d00_0000)).unwrap(), Some(312));
        assert_eq!(confidence_to_basis_points(f32::from_bits(0x3dc0_0000)).unwrap(), Some(938));
        for value in [f32::NAN, f32::INFINITY, -0.25, 1.01] {
            assert_eq!(confidence_to_basis_points(value), Err(DiscoveryProofError::InvalidClaim));
        }
    }
    #[test]
    fn digests_are_computed_from_actual_canonical_bytes() {
        let scope = scope();
        assert_eq!(
            scope.digest().unwrap(),
            ContentHash::of_bytes(&scope.canonical_bytes().unwrap())
        );
        let value = claim(0.5);
        assert_eq!(value.digest(), Some(ContentHash::of_bytes(value.canonical_bytes())));
        assert_eq!(value.limitation_codes(), &["missing_body_schema".to_owned()]);
        assert_ne!(value.digest(), claim(0.0).digest());
    }

    #[test]
    fn canonical_bytes_match_literal_public_layout_vectors() {
        let scope_hex = "8a767874726163652e646973636f766572792d73636f706501016c666978747572652d726f6f74666f72646572736e737072696e672d666978747572656764656661756c746a737072696e672d6d7663646a61766158201111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(hex::encode(scope().canonical_bytes().unwrap()), scope_hex);

        let evidence = ClaimSourceEvidence::StaticSnapshot {
            source_revision_id: SourceRevisionId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000003").unwrap(),
            ),
            relative_path: "src/Orders.java".to_owned(),
            recorded_source_digest: ContentHash::from_digest_bytes(&[0x22; 32]).unwrap(),
            start_line: 1,
            start_column: 1,
            end_line: 2,
            end_column: 1,
        };
        assert_eq!(
            hex::encode(evidence.canonical_bytes().unwrap()),
            "886f7374617469632d736e617073686f7450018f00000000700080000000000000036f7372632f4f72646572732e6a6176615820222222222222222222222222222222222222222222222222222222222222222201010201"
        );

        let prefix = "89767874726163652e646973636f766572792d636c61696d016b706f73742d6f7264657273585988781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706764656661756c7464504f5354672f6f726465727301774f7264657273436f6e74726f6c6c657223637265617465";
        let suffix = "8081886f7374617469632d736e617073686f7450018f00000000700080000000000000036f7372632f4f72646572732e6a6176615820222222222222222222222222222222222222222222222222222222222222222201010201";
        let vectors = [
            (-1.0_f32, "f6", 244_usize),
            (0.0_f32, "00", 244),
            (-0.0_f32, "00", 244),
            (0.5_f32, "191388", 246),
            (1.0_f32, "192710", 246),
            (f32::from_bits(0x3d00_0000), "190138", 246),
            (f32::from_bits(0x3dc0_0000), "1903aa", 246),
        ];
        for (confidence, slot, length) in vectors {
            let claim = fixture_claim(confidence);
            let actual = hex::encode(claim.canonical_bytes());
            assert_eq!(actual, format!("{prefix}{slot}{suffix}"));
            assert_eq!(claim.canonical_bytes().len(), length);
        }
    }

    #[test]
    fn placeholder_chunk_and_final_vectors_check_layout_only() {
        // The placeholder claim digest is deliberately not a valid transcript proof.
        let mut claim = fixture_claim(-1.0);
        claim.digest = Some(ContentHash::from_digest_bytes(&[0xcc; 32]).unwrap());
        let run_id = run_id();
        let chunk = DiscoveryChunk { run_id, chunk_index: 0, claims: vec![claim] };
        assert_eq!(
            hex::encode(chunk.canonical_bytes().unwrap()),
            "85767874726163652e646973636f766572792d6368756e6b0150018f000000007000800000000000000200815820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );

        let scope_digest = ContentHash::from_digest_bytes(&[0xaa; 32]).unwrap();
        let source_revision_id = Some(source_revision());
        assert_eq!(
            hex::encode(
                final_canonical_bytes(
                    run_id,
                    scope_digest,
                    source_revision_id,
                    &[ContentHash::from_digest_bytes(&[0xbb; 32]).unwrap()],
                    1,
                    0,
                    DiscoveryCompletion::Complete,
                )
                .unwrap()
            ),
            "89767874726163652e646973636f766572792d66696e616c0150018f00000000700080000000000000025820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa50018f0000000070008000000000000003815820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb010001"
        );
        assert_eq!(
            hex::encode(
                final_canonical_bytes(
                    run_id,
                    scope_digest,
                    source_revision_id,
                    &[],
                    0,
                    0,
                    DiscoveryCompletion::Complete,
                )
                .unwrap()
            ),
            "89767874726163652e646973636f766572792d66696e616c0150018f00000000700080000000000000025820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa50018f000000007000800000000000000380000001"
        );
    }

    #[test]
    fn public_independent_blake3_catalog_vectors_match_claim_chunk_and_final() {
        // These literals were checked against the separately implemented
        // public CBOR reference at reference revision 3fde72e and the official
        // BLAKE3 vectors. They are fixed bytes/digests, not producer receipts.
        let scope_value = scope();
        assert_eq!(
            hex::encode(scope_value.digest().unwrap().as_bytes()),
            "f24011314fa70910aab9defaf5f578075c080a894b8b0249ac21eb60425feae5"
        );
        let claim_value = fixture_claim(-1.0);
        assert_eq!(
            hex::encode(claim_value.digest().unwrap().as_bytes()),
            "07fc9ac933a4384462049bbe1d34f22d952eb7bca220c9d88b11521e1fbfed0a"
        );
        assert_eq!(
            hex::encode(claim_value.canonical_bytes()),
            "89767874726163652e646973636f766572792d636c61696d016b706f73742d6f7264657273585988781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706764656661756c7464504f5354672f6f726465727301774f7264657273436f6e74726f6c6c657223637265617465f68081886f7374617469632d736e617073686f7450018f00000000700080000000000000036f7372632f4f72646572732e6a6176615820222222222222222222222222222222222222222222222222222222222222222201010201"
        );
        let chunk_value =
            DiscoveryChunk { run_id: run_id(), chunk_index: 0, claims: vec![claim_value] };
        assert_eq!(
            hex::encode(chunk_value.digest().unwrap().as_bytes()),
            "12eba3b438d34f5bff5b7425b58d4c63c60b99b9615f40247365869d0b3f989c"
        );
        assert_eq!(
            hex::encode(
                final_digest(
                    run_id(),
                    &scope_value,
                    Some(source_revision()),
                    &[chunk_value],
                    0,
                    DiscoveryCompletion::Complete,
                )
                .unwrap()
                .as_bytes()
            ),
            "63b86229ff62e4c31f1f6ce38fa40ba4e46480d0b3220d18b2e80f89475ccf69"
        );
    }

    #[test]
    fn persisted_claim_rebuild_rechecks_canonical_digest() {
        let original = fixture_claim(0.5);
        let rebuilt = ValidatedEndpointClaim::from_persisted(
            original.claim_hint().to_owned(),
            original.operation().clone(),
            original.provenance(),
            original.handler_symbol().map(str::to_owned),
            original.confidence_basis_points(),
            original.limitation_codes().to_vec(),
            original.source_evidence().to_vec(),
        )
        .unwrap();
        assert_eq!(rebuilt.canonical_bytes(), original.canonical_bytes());
        assert_eq!(rebuilt.digest(), original.digest());
        assert_eq!(
            ValidatedEndpointClaim::from_persisted(
                original.claim_hint().to_owned(),
                original.operation().clone(),
                original.provenance(),
                original.handler_symbol().map(str::to_owned),
                Some(10_001),
                original.limitation_codes().to_vec(),
                original.source_evidence().to_vec(),
            ),
            Err(DiscoveryProofError::InvalidClaim)
        );
    }

    #[test]
    fn validated_claim_is_immutable_and_limits_codes_to_closed_vocabulary() {
        let mut hint = "post-orders".to_owned();
        let mut operation = identity();
        let input_evidence = ClaimSourceEvidence::Unavailable {
            reason_code: "not_bound".to_owned(),
            relative_path: None,
            recorded_source_digest: None,
        };
        let mut evidence = vec![input_evidence.clone()];
        let mut limits = vec!["handler_unresolved".to_owned()];
        let claim = ValidatedEndpointClaim::new(
            hint.clone(),
            operation.clone(),
            ClaimProvenance::StaticInferred,
            None,
            -1.0,
            limits.clone(),
            evidence.clone(),
        )
        .unwrap();
        let original = claim.canonical_bytes().to_vec();
        hint.clear();
        operation.route_template.push_str("/changed");
        limits[0].push_str("_changed");
        evidence.clear();
        assert_eq!(claim.canonical_bytes(), original);
        assert_eq!(claim.claim_hint(), "post-orders");
        assert_eq!(claim.operation().route_template, "/orders");
        assert_eq!(claim.limitation_codes(), &["handler_unresolved".to_owned()]);
        assert_eq!(claim.source_evidence(), &[input_evidence]);

        for secret_like in ["/private/path", "oops_new_status", "A1"] {
            assert_eq!(
                ValidatedEndpointClaim::new(
                    "x".to_owned(),
                    identity(),
                    ClaimProvenance::StaticInferred,
                    None,
                    -1.0,
                    vec![secret_like.to_owned()],
                    Vec::new(),
                ),
                Err(DiscoveryProofError::InvalidClaim),
            );
        }
        for unknown in ["private_path", "new_status"] {
            let unavailable = ClaimSourceEvidence::Unavailable {
                reason_code: unknown.to_owned(),
                relative_path: None,
                recorded_source_digest: None,
            };
            assert_eq!(
                ValidatedEndpointClaim::new(
                    "x".to_owned(),
                    identity(),
                    ClaimProvenance::StaticInferred,
                    None,
                    -1.0,
                    Vec::new(),
                    vec![unavailable],
                ),
                Err(DiscoveryProofError::InvalidClaim),
            );
        }
    }

    #[test]
    fn utf8_relative_paths_and_partial_runtime_hints_are_exact_and_bounded() {
        for allowed in ["src/注文.java", "src/Orders.java", "src/Orders.java#method"] {
            assert!(validate_relative_path(allowed).is_ok());
        }
        for rejected in [
            "C:/src/Orders.java",
            "c:relative.java",
            "../Orders.java",
            "/src/Orders.java",
            "src\\Orders.java",
            "src/line\nfeed.java",
        ] {
            assert_eq!(validate_relative_path(rejected), Err(DiscoveryProofError::InvalidClaim));
        }
        assert!(validate_optional_range(None, None, None, None).is_ok());
        assert!(validate_optional_range(Some(1), Some(1), None, None).is_ok());
        assert!(validate_optional_range(Some(1), Some(1), Some(2), Some(1)).is_ok());
        for invalid in [
            (Some(0), Some(1), None, None),
            (Some(1), Some(0), None, None),
            (None, None, Some(2), Some(1)),
            (Some(1), Some(1), Some(2), Some(0)),
            (Some(2), Some(1), Some(1), Some(1)),
        ] {
            assert_eq!(
                validate_optional_range(invalid.0, invalid.1, invalid.2, invalid.3),
                Err(DiscoveryProofError::InvalidClaim)
            );
        }
        assert_eq!(validate_range(1, 1, 2, 0), Err(DiscoveryProofError::InvalidClaim));
        assert_eq!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::StaticInferred,
                Some("OrdersController\nInjected".to_owned()),
                -1.0,
                Vec::new(),
                Vec::new(),
            ),
            Err(DiscoveryProofError::InvalidClaim),
        );
    }

    #[test]
    fn source_evidence_duplicate_key_includes_binding_but_excludes_claimed_reason_and_digest() {
        let revision_a = source_revision();
        let revision_b =
            SourceRevisionId::from_uuid(Uuid::from_u128(0x018f0000000070008000000000000004));
        let static_item = |revision, digest| ClaimSourceEvidence::StaticSnapshot {
            source_revision_id: revision,
            relative_path: "src/Orders.java".to_owned(),
            recorded_source_digest: ContentHash::from_digest_bytes(&[digest; 32]).unwrap(),
            start_line: 1,
            start_column: 1,
            end_line: 2,
            end_column: 1,
        };
        assert_eq!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::StaticInferred,
                None,
                -1.0,
                Vec::new(),
                vec![static_item(revision_a, 1), static_item(revision_a, 2)],
            ),
            Err(DiscoveryProofError::DuplicateSourceEvidence),
        );
        assert!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::StaticInferred,
                None,
                -1.0,
                Vec::new(),
                vec![static_item(revision_a, 1), static_item(revision_b, 1)],
            )
            .is_ok()
        );

        let unavailable = |reason: &str, digest: u8| ClaimSourceEvidence::Unavailable {
            reason_code: reason.to_owned(),
            relative_path: Some("src/Orders.java".to_owned()),
            recorded_source_digest: Some(ContentHash::from_digest_bytes(&[digest; 32]).unwrap()),
        };
        assert_eq!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::StaticInferred,
                None,
                -1.0,
                Vec::new(),
                vec![unavailable("source_denied", 1), unavailable("source_mismatch", 2)],
            ),
            Err(DiscoveryProofError::DuplicateSourceEvidence),
        );
    }

    #[test]
    fn chunk_and_run_limits_cover_actual_claim_payload_and_terminal_gaps() {
        let oversized = DiscoveryChunk {
            run_id: run_id(),
            chunk_index: 0,
            claims: (0..u32::try_from(MAX_DISCOVERY_CHUNK_CLAIMS)
                .expect("chunk claim limit fits u32"))
                .map(large_claim)
                .collect(),
        };
        assert_eq!(oversized.canonical_bytes(), Err(DiscoveryProofError::LimitExceeded));
        assert_eq!(
            DiscoveryChunk { run_id: run_id(), chunk_index: 64, claims: vec![claim(0.5)] }
                .canonical_bytes(),
            Err(DiscoveryProofError::LimitExceeded)
        );

        let aggregate: Vec<_> = (0..33)
            .map(|chunk_index| DiscoveryChunk {
                run_id: run_id(),
                chunk_index,
                claims: (0..32).map(|item| large_claim(chunk_index * 32 + item)).collect(),
            })
            .collect();
        assert_eq!(
            final_digest(
                run_id(),
                &scope(),
                Some(source_revision()),
                &aggregate,
                0,
                DiscoveryCompletion::Incomplete
            ),
            Err(DiscoveryProofError::LimitExceeded),
        );

        let maximum_count: Vec<_> = (0..64)
            .map(|chunk_index| DiscoveryChunk {
                run_id: run_id(),
                chunk_index,
                claims: vec![claim(0.5); 64],
            })
            .collect();
        assert_eq!(
            final_digest(
                run_id(),
                &scope(),
                Some(source_revision()),
                &maximum_count,
                1,
                DiscoveryCompletion::Incomplete
            ),
            Err(DiscoveryProofError::InvalidClaim),
        );
        assert_eq!(
            final_digest(
                run_id(),
                &scope(),
                Some(source_revision()),
                &[],
                1,
                DiscoveryCompletion::Complete
            ),
            Err(DiscoveryProofError::InvalidClaim),
        );
    }

    #[test]
    fn start_and_finish_validators_enforce_versions_scope_and_complete_gaps() {
        let mut start = DiscoveryRunStartRequest {
            schema_version: 1,
            run_hint: "retry-1".to_owned(),
            requested_scope: scope(),
            owner_selection_ref: Some("selection-1".to_owned()),
        };
        assert!(start.validate().is_ok());
        start.schema_version = 2;
        assert_eq!(start.validate(), Err(DiscoveryProofError::InvalidScope));

        let chunk = DiscoveryChunk { run_id: run_id(), chunk_index: 0, claims: vec![claim(0.5)] };
        let chunks = vec![chunk];
        let digest = final_digest(
            run_id(),
            &scope(),
            Some(source_revision()),
            &chunks,
            0,
            DiscoveryCompletion::Complete,
        )
        .unwrap();
        let finish = DiscoveryRunFinish {
            run_id: run_id(),
            expected_chunk_count: 1,
            accepted_claim_count: 1,
            rejected_claim_count: 0,
            final_digest: digest,
            completion: DiscoveryCompletion::Complete,
            limitation_codes: Vec::new(),
        };
        assert!(finish.validate_against(&scope(), Some(source_revision()), &chunks).is_ok());
        let mut incomplete_claim = finish.clone();
        incomplete_claim.accepted_claim_count = 0;
        assert_eq!(
            incomplete_claim.validate_against(&scope(), Some(source_revision()), &chunks),
            Err(DiscoveryProofError::InvalidClaim)
        );
        let mut complete_with_gap = finish;
        complete_with_gap.limitation_codes.push("source_hash_mismatch".to_owned());
        assert_eq!(
            complete_with_gap.validate_against(&scope(), Some(source_revision()), &chunks),
            Err(DiscoveryProofError::InvalidClaim)
        );
    }
    #[test]
    fn duplicate_semantic_evidence_is_rejected_before_canonical_sort() {
        let evidence = ClaimSourceEvidence::Unavailable {
            reason_code: "not_bound".to_owned(),
            relative_path: None,
            recorded_source_digest: None,
        };
        assert_eq!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::StaticInferred,
                None,
                -1.0,
                Vec::new(),
                vec![evidence.clone(), evidence]
            ),
            Err(DiscoveryProofError::DuplicateSourceEvidence)
        );
    }
    #[test]
    fn recording_claim_requires_a_durable_proof() {
        assert_eq!(
            ValidatedEndpointClaim::new(
                "x".to_owned(),
                identity(),
                ClaimProvenance::Observed,
                None,
                -1.0,
                Vec::new(),
                Vec::new()
            ),
            Err(DiscoveryProofError::RecordingProofRequired)
        );
    }
}
