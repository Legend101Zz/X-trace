//! Static-analyzer claim contract (ST-2).
//!
//! A static analyzer (Java, Node) is a separate subprocess. It never executes
//! the code it reads and talks to the Rust scanner through JSON lines on its
//! standard output. Each line is one [`AnalyzerLine`]:
//!
//! ```text
//! {"type":"header","contractVersion":1,"analyzerName":"xtrace-java-static", ...}
//! {"type":"claim","method":"GET","routeParts":["/owners","/{ownerId}"], ...}
//! {"type":"diagnostic","code":"parse_error","path":"src/Broken.java"}
//! {"type":"end","claims":1,"filesScanned":12,"complete":false,"incompleteReasons":["parse_error"]}
//! ```
//!
//! The analyzer sends raw route parts. The scanner joins and normalizes them
//! with [`crate::endpoint_normalization`] so there is a single normalizer, and
//! it hashes the analyzed files itself (BLAKE3), so an analyzer cannot lie
//! about a source digest. A transcript without an `end` line is incomplete.
//!
//! Confidence conventions ([`RouteBasis`]): a route written as a literal in an
//! annotation or call is 0.90, a route assembled from literals or resolved
//! constants is 0.50, a computed route is 0.30. These are the only values
//! analyzers can produce, which keeps the claim digest stable across scans.
//!
//! The vocabularies in this module are mirrored in
//! `schema/fixtures/static-claim-contract.json`, which the analyzers read in
//! their own tests; a Rust test keeps both in step.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContentHash, ProjectId, SourceRevisionId,
    catalog::{HttpMethod, Transport},
    catalog_discovery::{
        ClaimProvenance, ClaimSourceEvidence, DiscoveryProofError, ValidatedEndpointClaim,
        is_discovery_limitation_code,
    },
    endpoint_identity::EndpointIdentity,
    endpoint_normalization::{RouteFramework, RouteNormalizationError, join_and_normalize},
};

/// Version of the analyzer JSON-lines contract.
pub const STATIC_CLAIM_CONTRACT_VERSION: u32 = 1;
/// Most route parts one claim may carry (class prefix, mount path, method path...).
pub const MAX_ROUTE_PARTS: usize = 8;
/// Longest `rulesetId`, in bytes.
pub const MAX_RULESET_ID_BYTES: usize = 64;

/// Framework families a static analyzer may declare, with the route syntax each uses.
pub const STATIC_FRAMEWORK_FAMILIES: &[(&str, RouteFramework)] = &[
    ("spring-mvc", RouteFramework::SpringMvc),
    ("spring-webflux", RouteFramework::SpringMvc),
    ("jaxrs", RouteFramework::JaxRs),
    ("express", RouteFramework::Express),
    ("fastify", RouteFramework::Fastify),
    ("nest", RouteFramework::Nest),
];

/// Closed diagnostic codes an analyzer may report for one file.
pub const ANALYZER_DIAGNOSTIC_CODES: &[&str] =
    &["budget_exceeded", "file_too_large", "file_unreadable", "parse_error", "unsupported_syntax"];

/// Closed reasons an analyzer transcript can be incomplete.
pub const ANALYZER_INCOMPLETE_REASONS: &[&str] =
    &["budget_exceeded", "file_unreadable", "parse_error", "timeout", "unsupported_syntax"];

/// How the analyzer obtained the route text of a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteBasis {
    /// Written as a string literal in the mapping annotation or call.
    Literal,
    /// Assembled from literals or constants the analyzer resolved.
    Concatenated,
    /// Computed at run time; the analyzer could not resolve the text.
    Computed,
}

impl RouteBasis {
    /// Confidence in basis points (10,000 = 1.0).
    #[must_use]
    pub const fn confidence_basis_points(self) -> u16 {
        match self {
            Self::Literal => 9_000,
            Self::Concatenated => 5_000,
            Self::Computed => 3_000,
        }
    }

    /// Wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Concatenated => "concatenated",
            Self::Computed => "computed",
        }
    }
}

/// First line of a transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerHeader {
    /// Must equal [`STATIC_CLAIM_CONTRACT_VERSION`].
    pub contract_version: u32,
    /// Analyzer product name (ASCII identifier).
    pub analyzer_name: String,
    /// Analyzer version (ASCII identifier).
    pub analyzer_version: String,
    /// Identifier of the rule set the analyzer applied (for example `spring-mvc-annotations/1`).
    pub ruleset_id: String,
    /// One of [`STATIC_FRAMEWORK_FAMILIES`].
    pub framework: String,
}

/// Source range of a claim. Lines and columns are 1-based.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerEvidence {
    /// Source-root-relative path with `/` separators.
    pub path: String,
    /// First line.
    pub start_line: u32,
    /// First column.
    pub start_column: u32,
    /// Last line.
    pub end_line: u32,
    /// Last column.
    pub end_column: u32,
}

/// One endpoint claim found in source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerClaim {
    /// HTTP method, upper case.
    pub method: String,
    /// Raw route parts in declaration order; the scanner joins and normalizes them.
    pub route_parts: Vec<String>,
    /// How the route text was obtained.
    pub route_basis: RouteBasis,
    /// Handler symbol (`com.example.OwnerController#showOwner`), when known.
    #[serde(default)]
    pub handler: Option<String>,
    /// Closed limitation codes (`schema/fixtures/static-claim-contract.json`).
    #[serde(default)]
    pub limitations: Vec<String>,
    /// Where the mapping is written.
    pub evidence: AnalyzerEvidence,
}

/// A file the analyzer could not fully read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerDiagnostic {
    /// One of [`ANALYZER_DIAGNOSTIC_CODES`].
    pub code: String,
    /// Source-root-relative path, when the diagnostic concerns one file.
    #[serde(default)]
    pub path: Option<String>,
}

/// Last line of a transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerEnd {
    /// Number of claim lines the analyzer wrote.
    pub claims: u32,
    /// Number of source files the analyzer read.
    pub files_scanned: u32,
    /// The analyzer read every source file it selected and applied every rule.
    pub complete: bool,
    /// Subset of [`ANALYZER_INCOMPLETE_REASONS`]; empty when complete.
    #[serde(default)]
    pub incomplete_reasons: Vec<String>,
}

/// One JSON line of an analyzer transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnalyzerLine {
    /// Transcript header.
    Header(AnalyzerHeader),
    /// An endpoint claim.
    Claim(AnalyzerClaim),
    /// A per-file diagnostic.
    Diagnostic(AnalyzerDiagnostic),
    /// Transcript trailer.
    End(AnalyzerEnd),
}

/// Failure to accept analyzer output. Every variant is a safe closed code.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StaticClaimError {
    /// The header declares another contract version.
    #[error("analyzer contract version is not supported")]
    UnsupportedContractVersion,
    /// A header field is empty, too long or not an ASCII identifier.
    #[error("analyzer header field is invalid")]
    InvalidHeader,
    /// The framework family is not in the closed list.
    #[error("analyzer framework family is unknown")]
    UnknownFramework,
    /// The HTTP method is not a known verb.
    #[error("claim method is unknown")]
    UnknownMethod,
    /// Route parts are missing, too many or too long.
    #[error("claim route parts are invalid")]
    InvalidRouteParts,
    /// The route cannot be normalized.
    #[error("claim route cannot be normalized")]
    Route(RouteNormalizationError),
    /// A limitation, diagnostic or incomplete-reason code is outside its closed list.
    #[error("code is outside the closed vocabulary")]
    UnknownCode,
    /// The evidence path or range is invalid.
    #[error("claim evidence is invalid")]
    InvalidEvidence,
    /// The scanner has no digest for the file the claim cites.
    #[error("no digest for the cited file")]
    MissingFileDigest,
    /// A complete transcript lists incomplete reasons, or an incomplete one lists none.
    #[error("transcript completeness is inconsistent")]
    InconsistentCompleteness,
    /// The discovery validator rejected the assembled claim.
    #[error("assembled claim was rejected")]
    Rejected(DiscoveryProofError),
}

impl AnalyzerHeader {
    /// Checks version, identifiers and the framework family.
    pub fn validate(&self) -> Result<RouteFramework, StaticClaimError> {
        if self.contract_version != STATIC_CLAIM_CONTRACT_VERSION {
            return Err(StaticClaimError::UnsupportedContractVersion);
        }
        for (value, max) in [
            (&self.analyzer_name, 64),
            (&self.analyzer_version, 64),
            (&self.ruleset_id, MAX_RULESET_ID_BYTES),
        ] {
            let valid = !value.is_empty()
                && value.len() <= max
                && value.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'/')
                });
            if !valid {
                return Err(StaticClaimError::InvalidHeader);
            }
        }
        framework_syntax(&self.framework)
    }
}

/// Route syntax used by a framework family.
pub fn framework_syntax(family: &str) -> Result<RouteFramework, StaticClaimError> {
    STATIC_FRAMEWORK_FAMILIES
        .iter()
        .find(|(name, _)| *name == family)
        .map(|(_, syntax)| *syntax)
        .ok_or(StaticClaimError::UnknownFramework)
}

impl AnalyzerDiagnostic {
    /// Checks the closed code.
    pub fn validate(&self) -> Result<(), StaticClaimError> {
        if ANALYZER_DIAGNOSTIC_CODES.contains(&self.code.as_str()) {
            Ok(())
        } else {
            Err(StaticClaimError::UnknownCode)
        }
    }
}

impl AnalyzerEnd {
    /// Checks the incomplete reasons against the closed list and `complete`.
    pub fn validate(&self) -> Result<(), StaticClaimError> {
        if self
            .incomplete_reasons
            .iter()
            .any(|r| !ANALYZER_INCOMPLETE_REASONS.contains(&r.as_str()))
        {
            return Err(StaticClaimError::UnknownCode);
        }
        if self.complete != self.incomplete_reasons.is_empty() {
            return Err(StaticClaimError::InconsistentCompleteness);
        }
        Ok(())
    }
}

/// What the scanner knows when it turns an analyzer claim into a validated one.
pub struct StaticClaimContext<'a> {
    /// Project being scanned.
    pub project_id: ProjectId,
    /// Application component of the scanned source.
    pub application_component: &'a str,
    /// Binding key of the scanned source.
    pub binding_key: &'a str,
    /// Route syntax from [`AnalyzerHeader::validate`].
    pub route_syntax: RouteFramework,
    /// Pinned source snapshot the evidence belongs to.
    pub source_revision_id: SourceRevisionId,
}

impl AnalyzerClaim {
    /// Builds the validated discovery claim. `digest_of` returns the BLAKE3 of
    /// the cited file's bytes as the scanner read them.
    pub fn into_validated(
        &self,
        context: &StaticClaimContext<'_>,
        digest_of: &dyn Fn(&str) -> Option<ContentHash>,
    ) -> Result<ValidatedEndpointClaim, StaticClaimError> {
        let method = HttpMethod::parse(&self.method).ok_or(StaticClaimError::UnknownMethod)?;
        if self.method != method.as_str() {
            return Err(StaticClaimError::UnknownMethod);
        }
        if self.route_parts.is_empty() || self.route_parts.len() > MAX_ROUTE_PARTS {
            return Err(StaticClaimError::InvalidRouteParts);
        }
        let parts: Vec<&str> = self.route_parts.iter().map(String::as_str).collect();
        let route =
            join_and_normalize(context.route_syntax, &parts).map_err(StaticClaimError::Route)?;

        let mut limitations = Vec::with_capacity(self.limitations.len() + 2);
        for code in &self.limitations {
            if !is_discovery_limitation_code(code) {
                return Err(StaticClaimError::UnknownCode);
            }
            limitations.push(code.clone());
        }
        if route.wildcard {
            limitations.push("route_wildcard".to_owned());
        }
        if route.params.iter().any(|param| param.optional) {
            limitations.push("route_optional_parameter".to_owned());
        }
        if self.route_basis == RouteBasis::Computed {
            limitations.push("route_computed".to_owned());
        }

        let evidence = &self.evidence;
        let recorded_source_digest =
            digest_of(&evidence.path).ok_or(StaticClaimError::MissingFileDigest)?;
        let source = ClaimSourceEvidence::StaticSnapshot {
            source_revision_id: context.source_revision_id,
            relative_path: evidence.path.clone(),
            recorded_source_digest,
            start_line: evidence.start_line,
            start_column: evidence.start_column,
            end_line: evidence.end_line,
            end_column: evidence.end_column,
        };

        let operation = EndpointIdentity {
            project_id: context.project_id,
            application_component: context.application_component.to_owned(),
            binding_key: context.binding_key.to_owned(),
            transport: Transport::Http,
            method,
            route_template: route.identity,
        };
        let confidence = f32::from(self.route_basis.confidence_basis_points()) / 10_000.0;
        ValidatedEndpointClaim::new(
            claim_hint(evidence, method, &self.route_parts),
            operation,
            ClaimProvenance::StaticInferred,
            self.handler.clone(),
            confidence,
            limitations,
            vec![source],
        )
        .map_err(StaticClaimError::Rejected)
    }
}

/// Producer-local retry hint: stable across scans while the mapping text and
/// position are unchanged, independent of unrelated files.
fn claim_hint(evidence: &AnalyzerEvidence, method: HttpMethod, route_parts: &[String]) -> String {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(b"xtrace.static-claim-hint\0");
    input.extend_from_slice(evidence.path.as_bytes());
    for number in [evidence.start_line, evidence.start_column] {
        input.push(0);
        input.extend_from_slice(&number.to_be_bytes());
    }
    input.push(0);
    input.extend_from_slice(method.as_str().as_bytes());
    for part in route_parts {
        input.push(0);
        input.extend_from_slice(part.as_bytes());
    }
    let digest = blake3::hash(&input);
    format!("st-{}", &hex::encode(digest.as_bytes())[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn context() -> StaticClaimContext<'static> {
        StaticClaimContext {
            project_id: ProjectId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            ),
            application_component: "petclinic",
            binding_key: "default",
            route_syntax: RouteFramework::SpringMvc,
            source_revision_id: SourceRevisionId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-0000000000aa").unwrap(),
            ),
        }
    }

    fn digest(path: &str) -> Option<ContentHash> {
        (path == "src/Owner.java").then(|| ContentHash::of_bytes(b"owner"))
    }

    fn claim() -> AnalyzerClaim {
        AnalyzerClaim {
            method: "GET".to_owned(),
            route_parts: vec!["/owners".to_owned(), "/{ownerId}".to_owned()],
            route_basis: RouteBasis::Literal,
            handler: Some("org.example.OwnerController#showOwner".to_owned()),
            limitations: Vec::new(),
            evidence: AnalyzerEvidence {
                path: "src/Owner.java".to_owned(),
                start_line: 12,
                start_column: 5,
                end_line: 12,
                end_column: 40,
            },
        }
    }

    #[test]
    fn confidence_conventions_literal_concat_computed() {
        assert_eq!(RouteBasis::Literal.confidence_basis_points(), 9_000);
        assert_eq!(RouteBasis::Concatenated.confidence_basis_points(), 5_000);
        assert_eq!(RouteBasis::Computed.confidence_basis_points(), 3_000);
        for basis in [RouteBasis::Literal, RouteBasis::Concatenated, RouteBasis::Computed] {
            let mut input = claim();
            input.route_basis = basis;
            let validated = input.into_validated(&context(), &digest).unwrap();
            assert_eq!(validated.confidence_basis_points(), Some(basis.confidence_basis_points()));
        }
    }

    #[test]
    fn analyzer_claim_becomes_static_inferred_claim_with_normalized_identity() {
        let validated = claim().into_validated(&context(), &digest).unwrap();
        assert_eq!(validated.provenance(), ClaimProvenance::StaticInferred);
        assert_eq!(validated.operation().route_template, "/owners/{id}");
        assert_eq!(validated.operation().method, HttpMethod::Get);
        assert_eq!(validated.handler_symbol(), Some("org.example.OwnerController#showOwner"));
        assert_eq!(validated.source_evidence().len(), 1);
        assert!(validated.limitation_codes().is_empty());
    }

    #[test]
    fn claim_hint_is_stable_and_position_sensitive() {
        let first = claim().into_validated(&context(), &digest).unwrap();
        let second = claim().into_validated(&context(), &digest).unwrap();
        assert_eq!(first.claim_hint(), second.claim_hint());
        assert_eq!(first.digest(), second.digest());
        let mut moved = claim();
        moved.evidence.start_line = 13;
        moved.evidence.end_line = 13;
        let moved = moved.into_validated(&context(), &digest).unwrap();
        assert_ne!(first.claim_hint(), moved.claim_hint());
    }

    #[test]
    fn param_rename_in_source_keeps_operation_identity() {
        let a = claim().into_validated(&context(), &digest).unwrap();
        let mut renamed = claim();
        renamed.route_parts = vec!["/owners".to_owned(), "/{id}".to_owned()];
        let b = renamed.into_validated(&context(), &digest).unwrap();
        assert_eq!(
            a.operation().fingerprint().unwrap().as_bytes(),
            b.operation().fingerprint().unwrap().as_bytes()
        );
    }

    #[test]
    fn derived_limitations_are_added_without_analyzer_help() {
        let mut input = claim();
        input.route_parts = vec!["/files/{*rest}".to_owned()];
        input.route_basis = RouteBasis::Computed;
        let validated = input.into_validated(&context(), &digest).unwrap();
        assert_eq!(validated.limitation_codes(), ["route_computed", "route_wildcard"]);
    }

    #[test]
    fn unknown_codes_methods_and_files_are_rejected() {
        let mut input = claim();
        input.limitations = vec!["made_up".to_owned()];
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::UnknownCode
        );
        let mut input = claim();
        input.method = "get".to_owned();
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::UnknownMethod
        );
        let mut input = claim();
        input.method = "FETCH".to_owned();
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::UnknownMethod
        );
        let mut input = claim();
        input.evidence.path = "src/Other.java".to_owned();
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::MissingFileDigest
        );
        let mut input = claim();
        input.route_parts.clear();
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::InvalidRouteParts
        );
        let mut input = claim();
        input.route_parts = vec!["/a?x".to_owned()];
        assert_eq!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::Route(RouteNormalizationError::QueryOrFragment)
        );
        let mut input = claim();
        input.evidence.start_line = 0;
        assert!(matches!(
            input.into_validated(&context(), &digest).unwrap_err(),
            StaticClaimError::Rejected(_)
        ));
    }

    #[test]
    fn header_and_end_validation() {
        let header = AnalyzerHeader {
            contract_version: 1,
            analyzer_name: "xtrace-java-static".to_owned(),
            analyzer_version: "0.0.1".to_owned(),
            ruleset_id: "spring-mvc-annotations/1".to_owned(),
            framework: "spring-mvc".to_owned(),
        };
        assert_eq!(header.validate(), Ok(RouteFramework::SpringMvc));
        let mut bad = header.clone();
        bad.contract_version = 2;
        assert_eq!(bad.validate(), Err(StaticClaimError::UnsupportedContractVersion));
        let mut bad = header.clone();
        bad.framework = "rails".to_owned();
        assert_eq!(bad.validate(), Err(StaticClaimError::UnknownFramework));
        let mut bad = header;
        bad.ruleset_id = "has space".to_owned();
        assert_eq!(bad.validate(), Err(StaticClaimError::InvalidHeader));

        let complete = AnalyzerEnd {
            claims: 1,
            files_scanned: 1,
            complete: true,
            incomplete_reasons: Vec::new(),
        };
        assert_eq!(complete.validate(), Ok(()));
        let inconsistent = AnalyzerEnd {
            complete: true,
            incomplete_reasons: vec!["timeout".to_owned()],
            ..complete.clone()
        };
        assert_eq!(inconsistent.validate(), Err(StaticClaimError::InconsistentCompleteness));
        let silent = AnalyzerEnd { complete: false, ..complete.clone() };
        assert_eq!(silent.validate(), Err(StaticClaimError::InconsistentCompleteness));
        let unknown = AnalyzerEnd {
            complete: false,
            incomplete_reasons: vec!["boom".to_owned()],
            ..complete
        };
        assert_eq!(unknown.validate(), Err(StaticClaimError::UnknownCode));
        assert_eq!(
            AnalyzerDiagnostic { code: "parse_error".to_owned(), path: None }.validate(),
            Ok(())
        );
        assert_eq!(
            AnalyzerDiagnostic { code: "oops".to_owned(), path: None }.validate(),
            Err(StaticClaimError::UnknownCode)
        );
    }

    #[test]
    fn json_lines_round_trip_and_reject_unknown_fields() {
        let line = r#"{"type":"claim","method":"GET","routeParts":["/a"],"routeBasis":"literal","evidence":{"path":"A.java","startLine":1,"startColumn":1,"endLine":1,"endColumn":9}}"#;
        let parsed: AnalyzerLine = serde_json::from_str(line).unwrap();
        assert!(matches!(
            &parsed,
            AnalyzerLine::Claim(claim)
                if claim.route_basis == RouteBasis::Literal && claim.limitations.is_empty()
        ));
        let again: AnalyzerLine =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(again, parsed);
        for bad in [
            r#"{"type":"claim","method":"GET","routeParts":["/a"],"routeBasis":"literal","extra":1,"evidence":{"path":"A.java","startLine":1,"startColumn":1,"endLine":1,"endColumn":9}}"#,
            r#"{"type":"mystery"}"#,
            r#"{"type":"end","claims":1,"filesScanned":1,"complete":true,"surprise":true}"#,
        ] {
            assert!(serde_json::from_str::<AnalyzerLine>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn limitation_codes_closed_set() {
        use crate::catalog_discovery::DISCOVERY_LIMITATION_CODES;
        let mut sorted = DISCOVERY_LIMITATION_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, DISCOVERY_LIMITATION_CODES, "closed list stays sorted and unique");
        assert!(!is_discovery_limitation_code("made_up"));
        for code in [
            "mapping_method_unconstrained",
            "route_constant_unresolved",
            "route_computed",
            "route_wildcard",
            "route_optional_parameter",
            "mount_unresolved",
            "dynamic_registration",
        ] {
            assert!(is_discovery_limitation_code(code), "{code}");
        }
    }

    #[test]
    fn shared_contract_file_matches_the_rust_vocabularies() {
        use crate::catalog_discovery::DISCOVERY_LIMITATION_CODES;
        let text = include_str!("../../../schema/fixtures/static-claim-contract.json");
        let document: serde_json::Value = serde_json::from_str(text).unwrap();
        let strings = |key: &str| -> Vec<String> {
            document[key]
                .as_array()
                .expect("contract key is an array")
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(document["contractVersion"], STATIC_CLAIM_CONTRACT_VERSION);
        let limitation: Vec<&str> = DISCOVERY_LIMITATION_CODES.to_vec();
        assert_eq!(strings("limitationCodes"), limitation);
        assert_eq!(strings("diagnosticCodes"), ANALYZER_DIAGNOSTIC_CODES);
        assert_eq!(strings("incompleteReasons"), ANALYZER_INCOMPLETE_REASONS);
        let families: Vec<&str> = STATIC_FRAMEWORK_FAMILIES.iter().map(|(n, _)| *n).collect();
        assert_eq!(strings("frameworkFamilies"), families);
        for basis in [RouteBasis::Literal, RouteBasis::Concatenated, RouteBasis::Computed] {
            assert_eq!(
                document["routeBasisConfidenceBasisPoints"][basis.as_str()],
                basis.confidence_basis_points()
            );
        }
        // Every example line in the contract file must parse and validate.
        for line in document["exampleLines"].as_array().unwrap() {
            let parsed: AnalyzerLine = serde_json::from_value(line.clone()).unwrap();
            match parsed {
                AnalyzerLine::Header(header) => assert!(header.validate().is_ok()),
                AnalyzerLine::Diagnostic(diagnostic) => assert!(diagnostic.validate().is_ok()),
                AnalyzerLine::End(end) => assert!(end.validate().is_ok()),
                AnalyzerLine::Claim(claim) => {
                    let all = |_: &str| Some(ContentHash::of_bytes(b"x"));
                    assert!(claim.into_validated(&context(), &all).is_ok());
                }
            }
        }
    }
}
