//! Bounded, versioned catalog-discovery proof inputs.
//!
//! These values describe a transcript. They do not authorize a producer or
//! prove that a source snapshot exists; the application/store must issue and
//! persist that authority before allocating a run.

use std::collections::BTreeSet;

use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContentHash, ProjectId, RunId, SourceRevisionId,
    catalog::{HttpMethod, Transport},
    endpoint_identity::EndpointIdentity,
    ids::Id,
};

/// Canonical hash-layout version used by discovery transcripts.
pub const DISCOVERY_DIGEST_FORMAT_VERSION: u32 = 1;
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

/// Static source scan or runtime registration enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryScopeKind {
    /// Bounded scan of an owner-selected immutable source snapshot.
    StaticRepository,
    /// Bounded runtime registration namespace.
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
    /// Opaque owner-selected root key, never a filesystem path.
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

/// Closed creation-time source-evidence facts for a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimSourceEvidence {
    /// Bytes opened from the exact immutable source revision by the core.
    StaticSnapshot {
        source_revision_id: SourceRevisionId,
        relative_path: String,
        recorded_source_digest: ContentHash,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    },
    /// Compile-time loaded-class attestation bound by the core.
    LoadedClassBound {
        loaded_class_digest: ContentHash,
        relative_path: String,
        recorded_source_digest: ContentHash,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    },
    /// Unverified producer location hint.
    RuntimeHint {
        relative_path: Option<String>,
        reported_source_digest: Option<ContentHash>,
        start_line: Option<u32>,
        start_column: Option<u32>,
        end_line: Option<u32>,
        end_column: Option<u32>,
    },
    /// Creation-time absence or denial with an optional prior digest.
    Unavailable {
        reason_code: String,
        relative_path: Option<String>,
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
                validate_code(reason_code)?;
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
    StaticInferred,
    RuntimeDiscovered,
    Observed,
    PartialObservation,
    ImportedSpec,
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

/// Fully validated and canonicalized immutable claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEndpointClaim {
    /// Producer-local retry hint; not a public claim ID.
    pub claim_hint: String,
    /// Exact operation identity, fingerprinted with ADR-0001 v1.
    pub operation: EndpointIdentity,
    /// Claim provenance.
    pub provenance: ClaimProvenance,
    /// Optional bounded handler symbol, excluded from operation identity.
    pub handler_symbol: Option<String>,
    /// Exact f32-to-basis-point conversion, or null for the -1 sentinel.
    pub confidence_basis_points: Option<u16>,
    /// Sorted and deduplicated stable limitation codes.
    pub limitation_codes: Vec<String>,
    /// Closed creation-time source evidence.
    pub source_evidence: Vec<ClaimSourceEvidence>,
    /// Canonical bytes are internal and are not part of any client DTO.
    canonical_bytes: Vec<u8>,
    /// Core-computed digest; never accepted from the producer.
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
            if symbol.is_empty() || symbol.len() > 512 || !symbol.is_ascii() {
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
            validate_code(code)?;
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

    /// Canonical v1 claim bytes used by the store and transcript hashes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Core-computed immutable BLAKE3 claim digest.
    #[must_use]
    pub const fn digest(&self) -> Option<ContentHash> {
        self.digest
    }
}

/// Verified contiguous chunk of claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryChunk {
    /// Core-issued run identity.
    pub run_id: crate::RunId,
    /// Zero-based ordered index.
    pub chunk_index: u32,
    /// Claims in producer order.
    pub claims: Vec<ValidatedEndpointClaim>,
}

impl DiscoveryChunk {
    /// Encodes a bounded chunk retaining claim order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        if self.claims.is_empty() || self.claims.len() > MAX_DISCOVERY_CHUNK_CLAIMS {
            return Err(DiscoveryProofError::LimitExceeded);
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

/// Verified terminal state.
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

/// Core-verified terminal request data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRunFinish {
    /// Core-issued run identity.
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
    /// Sorted, deduplicated stable codes.
    pub limitation_codes: Vec<String>,
}

/// Computes the v1 final digest over ordered, already-verified chunk digests.
pub fn final_digest(
    run_id: RunId,
    scope_digest: ContentHash,
    source_revision_id: Option<SourceRevisionId>,
    chunk_digests: &[ContentHash],
    accepted_claim_count: u32,
    rejected_claim_count: u32,
    completion: DiscoveryCompletion,
) -> Result<ContentHash, DiscoveryProofError> {
    if chunk_digests.len() > MAX_DISCOVERY_RUN_CHUNKS as usize {
        return Err(DiscoveryProofError::LimitExceeded);
    }
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
    Ok(ContentHash::of_bytes(&bytes))
}

/// Start request keyed by authenticated runtime and producer-local hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRunStartRequest {
    /// Producer-local retry hint.
    pub run_hint: String,
    /// Requested immutable coverage.
    pub requested_scope: DiscoveryScope,
    /// Opaque admitted owner-selection reference.
    pub owner_selection_ref: Option<String>,
}

/// Core-issued admission or safe refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoveryRunGrant {
    /// Durably admitted, core-issued run.
    Admitted {
        /// Core-issued run ID.
        run_id: RunId,
        /// Resolved stable scope identity.
        scope_digest: ContentHash,
        /// Core-resolved static snapshot revision.
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
    if !value.is_finite() || value < 0.0 || value > 1.0 {
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
fn validate_code(value: &str) -> Result<(), DiscoveryProofError> {
    if value.is_empty()
        || value.len() > 64
        || !value.is_ascii()
        || !value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    Ok(())
}
fn validate_relative_path(path: &str) -> Result<(), DiscoveryProofError> {
    if path.is_empty()
        || path.len() > 512
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b.is_ascii_control())
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
    if sl == 0 || sc == 0 || el < sl || (el == sl && ec < sc) {
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
    if let (Some(sl), Some(sc), Some(el), Some(ec)) = (sl, sc, el, ec) {
        validate_range(sl, sc, el, ec)?;
    } else if sl.is_some() != sc.is_some() || el.is_some() != ec.is_some() {
        return Err(DiscoveryProofError::InvalidClaim);
    }
    Ok(())
}
impl ClaimSourceEvidence {
    fn semantic_key(&self) -> Result<Vec<u8>, DiscoveryProofError> {
        let mut bytes = Vec::with_capacity(128);
        let mut enc = Encoder::new(&mut bytes);
        match self {
            Self::StaticSnapshot {
                relative_path,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                enc.array(6)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(1)
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
                relative_path,
                start_line,
                start_column,
                end_line,
                end_column,
                ..
            } => {
                validate_relative_path(relative_path)?;
                enc.array(6)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(2)
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
                validate_code(reason_code)?;
                enc.array(3)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .u8(4)
                    .map_err(|_| DiscoveryProofError::Encoding)?
                    .str(reason_code)
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
            ruleset_digest: ContentHash::of_bytes(b"public-rules"),
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
        assert_eq!(value.limitation_codes, vec!["missing_body_schema".to_owned()]);
        assert_ne!(value.digest(), claim(0.0).digest());
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
