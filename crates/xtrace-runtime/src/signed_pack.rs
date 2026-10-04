//! Strict signed language-pack JSON and cryptographic framing primitives.
//!
//! This module accepts only the integer/string/array/object subset used by the
//! closed v1 pack schema. Duplicate keys are rejected before a value is
//! materialized, and signed bytes are always derived from the parsed tree.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use thiserror::Error;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 8 * 1024;
const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ARTIFACTS: usize = 96;
const BUILD_HASH_DOMAIN: &[u8] = b"XTRACE-PACK-BUILD-v1\0";
const SIGNED_MESSAGE_DOMAIN: &[u8] = b"XTRACE-PACK-v1\0";

/// Sanitized failure while reading or verifying a signed language pack.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignedPackError {
    /// The manifest is oversized, malformed, duplicate-bearing, or noncanonical.
    #[error("language pack manifest is invalid")]
    InvalidManifest,
    /// The manifest does not match the closed v1 contract.
    #[error("language pack manifest does not match the supported contract")]
    UnsupportedManifest,
    /// The pack bytes do not match the signed inventory.
    #[error("language pack inventory does not match")]
    InventoryMismatch,
    /// The pack build hash does not match the canonical inventory frame.
    #[error("language pack build hash does not match")]
    BuildHashMismatch,
    /// The signature is malformed or invalid for its trusted key.
    #[error("language pack signature is invalid")]
    InvalidSignature,
    /// No fixed, active release key is configured for this key identifier.
    #[error("no trusted release key is available for this pack")]
    TrustUnavailable,
    /// A bounded operation would exceed the supported resource limit.
    #[error("language pack exceeds a supported size limit")]
    ResourceLimit,
    /// The owner-enforced private snapshot could not be established.
    #[error("language pack private snapshot is unavailable")]
    PrivateSnapshotUnavailable,
    /// The private snapshot did not match the exact signed file inventory.
    #[error("language pack private snapshot is incomplete")]
    SnapshotIncomplete,
    /// Cleanup could not prove that an owned partial snapshot was removed.
    #[error("language pack private snapshot cleanup is uncertain")]
    SnapshotCleanupUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

/// Immutable facts structurally parsed from a canonical schema-1 manifest.
///
/// These declarations are not a verification receipt and grant no runtime
/// capability. Only the future verified-snapshot boundary may construct a
/// verified pack state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackManifest {
    schema_version: u64,
    pack_name: String,
    pack_version: String,
    build_hash: [u8; 32],
    release_minimum: String,
    release_maximum: String,
    protocol_minimum: (u32, u32),
    protocol_maximum: (u32, u32),
    runtime_language: String,
    runtime_range: (u32, u32),
    tested_runtime_majors: Vec<u32>,
    artifact_digests: Vec<ArtifactDigest>,
    platforms: ValidatedJson,
    entrypoints: ValidatedJson,
    framework_modules: ValidatedJson,
    capabilities: ValidatedJson,
    known_limitations: ValidatedJson,
    key_id: String,
    signature: [u8; 64],
}

/// Canonical JSON bytes for one closed-schema declaration validated by this
/// parser. Callers can retain or compare the facts, but cannot construct one
/// from arbitrary bytes or treat a declaration as observed runtime evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedJson(Vec<u8>);

impl ValidatedJson {
    /// Returns the canonical UTF-8 JSON representation of the validated value.
    #[must_use]
    pub fn as_canonical_json(&self) -> &[u8] {
        &self.0
    }
}

impl PackManifest {
    /// Schema version of this structurally validated manifest.
    #[must_use]
    pub const fn schema_version(&self) -> u64 {
        self.schema_version
    }

    /// Machine-readable language-pack name.
    #[must_use]
    pub fn pack_name(&self) -> &str {
        &self.pack_name
    }

    /// Release-facing pack version, independent of source-development labels.
    #[must_use]
    pub fn pack_version(&self) -> &str {
        &self.pack_version
    }

    /// Declared BLAKE3 build hash of the sorted outer inventory.
    #[must_use]
    pub const fn build_hash(&self) -> &[u8; 32] {
        &self.build_hash
    }

    /// The fixed trusted-key lookup hint; it is not itself authority.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Bounded sorted artifact digest facts from the manifest.
    #[must_use]
    pub fn artifact_digests(&self) -> &[ArtifactDigest] {
        &self.artifact_digests
    }

    /// Runtime language declared by the pack.
    #[must_use]
    pub fn runtime_language(&self) -> &str {
        &self.runtime_language
    }

    /// Exact declared X-trace release range, currently fixed to v0.0.1.
    #[must_use]
    pub fn release_range(&self) -> (&str, &str) {
        (&self.release_minimum, &self.release_maximum)
    }

    /// Numeric protocol interval declared by this pack.
    #[must_use]
    pub const fn protocol_range(&self) -> ((u32, u32), (u32, u32)) {
        (self.protocol_minimum, self.protocol_maximum)
    }

    /// Runtime major interval declared by the pack.
    #[must_use]
    pub const fn runtime_range(&self) -> (u32, u32) {
        self.runtime_range
    }

    /// Runtime majors named as tested by the pack; this remains an unverified declaration.
    #[must_use]
    pub fn tested_runtime_majors(&self) -> &[u32] {
        &self.tested_runtime_majors
    }

    /// Signed platform tuples, retained after closed-registry validation.
    #[must_use]
    pub const fn platforms(&self) -> &ValidatedJson {
        &self.platforms
    }

    /// Returns whether the signed platform list contains this validated host tuple.
    #[must_use]
    pub fn supports_platform(&self, os: &str, arch: &str) -> bool {
        let Ok(JsonValue::Array(platforms)) = parse_canonical_value(self.platforms.as_canonical_json())
        else {
            return false;
        };
        platforms.iter().any(|platform| {
            let JsonValue::Object(fields) = platform else { return false };
            matches!(fields.get("os"), Some(JsonValue::String(value)) if value == os)
                && matches!(fields.get("arch"), Some(JsonValue::String(value)) if value == arch)
        })
    }

    /// Signed entrypoint declarations, retained after inventory-reference validation.
    #[must_use]
    pub const fn entrypoints(&self) -> &ValidatedJson {
        &self.entrypoints
    }

    /// Signed framework descriptors, retained for later compatibility checks.
    #[must_use]
    pub const fn framework_modules(&self) -> &ValidatedJson {
        &self.framework_modules
    }

    /// Signed capability upper bounds; these do not prove runtime readiness.
    #[must_use]
    pub const fn capabilities(&self) -> &ValidatedJson {
        &self.capabilities
    }

    /// Signed stable limitation codes, not per-recording limitation evidence.
    #[must_use]
    pub const fn known_limitations(&self) -> &ValidatedJson {
        &self.known_limitations
    }

    /// The Ed25519 signature bytes carried by the manifest.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Parses one bounded, canonical schema-1 manifest into immutable typed facts.
pub fn parse_canonical_manifest(bytes: &[u8]) -> Result<PackManifest, SignedPackError> {
    let value = parse_canonical_value(bytes)?;
    validate_schema(&value)
}

fn parse_canonical_value(bytes: &[u8]) -> Result<JsonValue, SignedPackError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES || std::str::from_utf8(bytes).is_err() {
        return Err(SignedPackError::InvalidManifest);
    }
    let mut parser = Parser { bytes, position: 0, nodes: 0 };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.position != bytes.len() {
        return Err(SignedPackError::InvalidManifest);
    }
    let mut canonical = Vec::with_capacity(bytes.len());
    write_canonical(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(SignedPackError::InvalidManifest);
    }
    Ok(value)
}

fn validate_schema(value: &JsonValue) -> Result<PackManifest, SignedPackError> {
    let top = object_with_keys(
        value,
        &[
            "schemaVersion",
            "pack",
            "release",
            "protocol",
            "runtime",
            "platforms",
            "entrypoints",
            "frameworkModules",
            "capabilities",
            "knownLimitations",
            "artifacts",
            "signature",
        ],
    )?;
    if unsigned(required(top, "schemaVersion")?)? != 1 {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let pack = object_with_keys(required(top, "pack")?, &["name", "version", "buildHash"])?;
    let pack_name = string(required(pack, "name")?)?;
    if pack_name != "java" && pack_name != "node" {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let pack_version = string(required(pack, "version")?)?;
    if pack_version != "0.0.1" {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let build_hash_text = string(required(pack, "buildHash")?)?;
    let build_hash = parse_prefixed_digest(build_hash_text)?;

    let release = object_with_keys(required(top, "release")?, &["min", "max"])?;
    let release_minimum = string(required(release, "min")?)?;
    let release_maximum = string(required(release, "max")?)?;
    if parse_semver(release_minimum)? != (0, 0, 1) || parse_semver(release_maximum)? != (0, 0, 1) {
        return Err(SignedPackError::UnsupportedManifest);
    }

    let protocol = object_with_keys(required(top, "protocol")?, &["min", "max"])?;
    let protocol_minimum = parse_protocol_version(string(required(protocol, "min")?)?)?;
    let protocol_maximum = parse_protocol_version(string(required(protocol, "max")?)?)?;
    if protocol_minimum > protocol_maximum {
        return Err(SignedPackError::UnsupportedManifest);
    }

    let runtime =
        object_with_keys(required(top, "runtime")?, &["language", "versionRange", "testedMajors"])?;
    let runtime_language = string(required(runtime, "language")?)?;
    if runtime_language != pack_name {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let runtime_range = parse_runtime_range(string(required(runtime, "versionRange")?)?)?;
    let tested_runtime_majors = unsigned_array(required(runtime, "testedMajors")?, 1, 16)?;
    if tested_runtime_majors.windows(2).any(|pair| pair[0] >= pair[1])
        || tested_runtime_majors
            .iter()
            .any(|major| *major < runtime_range.0 || *major >= runtime_range.1)
    {
        return Err(SignedPackError::UnsupportedManifest);
    }

    let platforms = required(top, "platforms")?;
    validate_platforms(platforms)?;
    let artifact_digests = parse_artifacts(required(top, "artifacts")?)?;
    let entrypoints = required(top, "entrypoints")?;
    validate_entrypoints(entrypoints, pack_name, &artifact_digests)?;
    let framework_modules = required(top, "frameworkModules")?;
    validate_framework_modules(framework_modules, pack_name)?;
    let capabilities = required(top, "capabilities")?;
    validate_capabilities(capabilities)?;
    let known_limitations = required(top, "knownLimitations")?;
    validate_known_limitations(known_limitations)?;

    let signature =
        object_with_keys(required(top, "signature")?, &["algorithm", "keyId", "value"])?;
    if string(required(signature, "algorithm")?)? != "Ed25519" {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let key_id = string(required(signature, "keyId")?)?;
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let signature_text = string(required(signature, "value")?)?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_text)
        .map_err(|_| SignedPackError::InvalidSignature)?;
    if signature_bytes.len() != 64
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes)
            != signature_text
    {
        return Err(SignedPackError::InvalidSignature);
    }
    let mut signature_value = [0; 64];
    signature_value.copy_from_slice(&signature_bytes);

    Ok(PackManifest {
        schema_version: 1,
        pack_name: pack_name.to_owned(),
        pack_version: pack_version.to_owned(),
        build_hash,
        release_minimum: release_minimum.to_owned(),
        release_maximum: release_maximum.to_owned(),
        protocol_minimum,
        protocol_maximum,
        runtime_language: runtime_language.to_owned(),
        runtime_range,
        tested_runtime_majors,
        artifact_digests,
        platforms: validated_json(platforms)?,
        entrypoints: validated_json(entrypoints)?,
        framework_modules: validated_json(framework_modules)?,
        capabilities: validated_json(capabilities)?,
        known_limitations: validated_json(known_limitations)?,
        key_id: key_id.to_owned(),
        signature: signature_value,
    })
}

fn validated_json(value: &JsonValue) -> Result<ValidatedJson, SignedPackError> {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes)?;
    Ok(ValidatedJson(bytes))
}

fn object_with_keys<'a>(
    value: &'a JsonValue,
    keys: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, SignedPackError> {
    let JsonValue::Object(fields) = value else { return Err(SignedPackError::UnsupportedManifest) };
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(fields)
}

fn required<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<&'a JsonValue, SignedPackError> {
    fields.get(key).ok_or(SignedPackError::UnsupportedManifest)
}

fn string(value: &JsonValue) -> Result<&str, SignedPackError> {
    match value {
        JsonValue::String(value) => Ok(value),
        _ => Err(SignedPackError::UnsupportedManifest),
    }
}

fn unsigned(value: &JsonValue) -> Result<u64, SignedPackError> {
    match value {
        JsonValue::Unsigned(value) => Ok(*value),
        _ => Err(SignedPackError::UnsupportedManifest),
    }
}

fn parse_prefixed_digest(value: &str) -> Result<[u8; 32], SignedPackError> {
    let Some(hex) = value.strip_prefix("b3:") else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let mut output = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(byte: u8) -> Result<u8, SignedPackError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SignedPackError::UnsupportedManifest),
    }
}

fn parse_decimal(value: &str, maximum: u32) -> Result<u32, SignedPackError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let number = value.parse::<u32>().map_err(|_| SignedPackError::UnsupportedManifest)?;
    if number > maximum {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(number)
}

fn parse_semver(value: &str) -> Result<(u32, u32, u32), SignedPackError> {
    let mut parts = value.split('.');
    let parsed = (
        parse_decimal(parts.next().ok_or(SignedPackError::UnsupportedManifest)?, 65_535)?,
        parse_decimal(parts.next().ok_or(SignedPackError::UnsupportedManifest)?, 65_535)?,
        parse_decimal(parts.next().ok_or(SignedPackError::UnsupportedManifest)?, 65_535)?,
    );
    if parts.next().is_some() {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(parsed)
}

fn parse_protocol_version(value: &str) -> Result<(u32, u32), SignedPackError> {
    let mut parts = value.split('.');
    let parsed = (
        parse_decimal(parts.next().ok_or(SignedPackError::UnsupportedManifest)?, 65_535)?,
        parse_decimal(parts.next().ok_or(SignedPackError::UnsupportedManifest)?, 65_535)?,
    );
    if parts.next().is_some() {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(parsed)
}

fn parse_runtime_range(value: &str) -> Result<(u32, u32), SignedPackError> {
    let Some((lower, upper)) = value.split_once(' ') else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    let lower = lower.strip_prefix(">=").ok_or(SignedPackError::UnsupportedManifest)?;
    let upper = upper.strip_prefix('<').ok_or(SignedPackError::UnsupportedManifest)?;
    let range = (parse_decimal(lower, 65_535)?, parse_decimal(upper, 65_535)?);
    if range.0 >= range.1 {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(range)
}

fn unsigned_array(
    value: &JsonValue,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u32>, SignedPackError> {
    let JsonValue::Array(values) = value else { return Err(SignedPackError::UnsupportedManifest) };
    if values.len() < minimum || values.len() > maximum {
        return Err(SignedPackError::UnsupportedManifest);
    }
    values
        .iter()
        .map(|item| {
            let raw = unsigned(item)?;
            u32::try_from(raw).map_err(|_| SignedPackError::UnsupportedManifest)
        })
        .collect()
}

fn validate_platforms(value: &JsonValue) -> Result<(), SignedPackError> {
    let JsonValue::Array(platforms) = value else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    if platforms.is_empty() || platforms.len() > 8 {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let mut previous = None;
    for platform in platforms {
        let fields = object_with_keys(platform, &["os", "arch"])?;
        let os = string(required(fields, "os")?)?;
        let arch = string(required(fields, "arch")?)?;
        if !matches!(os, "macos" | "linux") || !matches!(arch, "aarch64" | "x86_64") {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let current = (os, arch);
        if previous.is_some_and(|item| item >= current) {
            return Err(SignedPackError::UnsupportedManifest);
        }
        previous = Some(current);
    }
    Ok(())
}

fn parse_artifacts(value: &JsonValue) -> Result<Vec<ArtifactDigest>, SignedPackError> {
    let JsonValue::Array(artifacts) = value else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(SignedPackError::ResourceLimit);
    }
    let mut parsed = Vec::with_capacity(artifacts.len());
    let mut previous: Option<String> = None;
    let mut folded = BTreeSet::new();
    for artifact in artifacts {
        let fields = object_with_keys(artifact, &["path", "hash"])?;
        let path = string(required(fields, "path")?)?;
        if !valid_artifact_path(path) || previous.as_deref().is_some_and(|value| value >= path) {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let lower = path.to_ascii_lowercase();
        if !folded.insert(lower) {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let digest = parse_prefixed_digest(string(required(fields, "hash")?)?)?;
        previous = Some(path.to_owned());
        parsed.push(ArtifactDigest { path: path.to_owned(), digest });
    }
    Ok(parsed)
}

fn validate_entrypoints(
    value: &JsonValue,
    language: &str,
    artifacts: &[ArtifactDigest],
) -> Result<(), SignedPackError> {
    let fields = object_with_keys(value, &["launch", "attach", "staticDiscovery"])?;
    let mut referenced = Vec::new();
    if language == "java" {
        referenced.push(string(required(fields, "launch")?)?);
        referenced.push(string(required(fields, "attach")?)?);
    } else {
        let launch = object_with_keys(required(fields, "launch")?, &["commonJs", "esModule"])?;
        referenced.push(string(required(launch, "commonJs")?)?);
        referenced.push(string(required(launch, "esModule")?)?);
        if required(fields, "attach")? != &JsonValue::Null {
            return Err(SignedPackError::UnsupportedManifest);
        }
    }
    match required(fields, "staticDiscovery")? {
        JsonValue::Null => {}
        JsonValue::String(path) => referenced.push(path),
        _ => return Err(SignedPackError::UnsupportedManifest),
    }
    for path in referenced {
        if !valid_artifact_path(path) || !artifacts.iter().any(|artifact| artifact.path == path) {
            return Err(SignedPackError::UnsupportedManifest);
        }
    }
    Ok(())
}

fn validate_framework_modules(value: &JsonValue, language: &str) -> Result<(), SignedPackError> {
    let JsonValue::Array(modules) = value else { return Err(SignedPackError::UnsupportedManifest) };
    if modules.len() > 64 {
        return Err(SignedPackError::ResourceLimit);
    }
    let mut ids = Vec::with_capacity(modules.len());
    let mut dependency_edges: Vec<Vec<String>> = Vec::with_capacity(modules.len());
    let mut conflict_edges: Vec<Vec<String>> = Vec::with_capacity(modules.len());
    const FEATURES: &[&str] = &[
        "java_retransform",
        "java_debug_tables",
        "java_module_open",
        "node_cjs_preload",
        "node_esm_loader",
        "node_async_local_storage",
        "node_source_map",
        "native_http",
    ];
    const CAPABILITIES: &[&str] = &[
        "method_frames",
        "line_cursor",
        "locals",
        "async_correlation",
        "database_interaction",
        "outbound_http",
        "source_maps",
    ];
    let mut previous_id: Option<String> = None;
    for module in modules {
        let fields = object_with_keys(
            module,
            &[
                "id",
                "framework",
                "packageMarkers",
                "versionRange",
                "testedVersions",
                "status",
                "discoveryCapabilities",
                "captureCapabilities",
                "requiredRuntimeFeatures",
                "matcherIds",
                "conflicts",
                "after",
                "posture",
                "fixtureIds",
            ],
        )?;
        let id = string(required(fields, "id")?)?;
        if !valid_ascii_id(id, 64) || previous_id.as_deref().is_some_and(|previous| previous >= id)
        {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let framework = required(fields, "framework")?;
        validate_framework_id(framework, language)?;
        validate_string_array(required(fields, "packageMarkers")?, 1, 16, valid_package_marker)?;
        let range = parse_semver_range(string(required(fields, "versionRange")?)?)?;
        let tested = string_array(required(fields, "testedVersions")?, 1, 32)?;
        if tested.windows(2).any(|pair| pair[0] >= pair[1])
            || tested.iter().any(|version| {
                parse_semver(version).map_or(true, |parsed| parsed < range.0 || parsed >= range.1)
            })
        {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let status = string(required(fields, "status")?)?;
        if !matches!(status, "supported" | "preview" | "experimental") {
            return Err(SignedPackError::UnsupportedManifest);
        }
        validate_string_array(required(fields, "discoveryCapabilities")?, 0, 16, |item| {
            item == "endpoint_discovery"
        })?;
        let capture = string_array(required(fields, "captureCapabilities")?, 0, 16)?;
        if capture.windows(2).any(|pair| pair[0] >= pair[1])
            || capture.iter().any(|item| !CAPABILITIES.contains(&item.as_str()))
        {
            return Err(SignedPackError::UnsupportedManifest);
        }
        validate_string_array(required(fields, "requiredRuntimeFeatures")?, 0, 16, |item| {
            FEATURES.contains(&item)
        })?;
        let matchers = string_array(required(fields, "matcherIds")?, 0, 128)?;
        validate_sorted_ids(&matchers, 64)?;
        if status == "supported" && !capture.is_empty() && matchers.is_empty() {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let conflicts = string_array(required(fields, "conflicts")?, 0, 32)?;
        let after = string_array(required(fields, "after")?, 0, 32)?;
        validate_sorted_ids(&conflicts, 64)?;
        validate_sorted_ids(&after, 64)?;
        if conflicts.iter().chain(&after).any(|dependency| dependency == id) {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let posture = string(required(fields, "posture")?)?;
        if !matches!(posture, "public_hook" | "reviewed_internal") {
            return Err(SignedPackError::UnsupportedManifest);
        }
        let fixtures = string_array(required(fields, "fixtureIds")?, 0, 64)?;
        if fixtures.windows(2).any(|pair| pair[0] >= pair[1])
            || fixtures.iter().any(|item| !valid_ascii_id(item, 96))
            || (status == "supported" && fixtures.is_empty())
        {
            return Err(SignedPackError::UnsupportedManifest);
        }
        previous_id = Some(id.to_owned());
        ids.push(id.to_owned());
        conflict_edges.push(conflicts);
        dependency_edges.push(after);
    }
    for references in conflict_edges.iter().chain(&dependency_edges) {
        if references.iter().any(|dependency| ids.binary_search(dependency).is_err()) {
            return Err(SignedPackError::UnsupportedManifest);
        }
    }
    let mut marks = vec![0_u8; ids.len()];
    for index in 0..ids.len() {
        visit_dependency_graph(index, &ids, &dependency_edges, &mut marks)?;
    }
    Ok(())
}

fn visit_dependency_graph(
    index: usize,
    ids: &[String],
    edges: &[Vec<String>],
    marks: &mut [u8],
) -> Result<(), SignedPackError> {
    match marks.get(index).copied() {
        Some(1) => return Err(SignedPackError::UnsupportedManifest),
        Some(2) => return Ok(()),
        Some(0) => {}
        _ => return Err(SignedPackError::UnsupportedManifest),
    }
    marks[index] = 1;
    for dependency in &edges[index] {
        let target =
            ids.binary_search(dependency).map_err(|_| SignedPackError::UnsupportedManifest)?;
        visit_dependency_graph(target, ids, edges, marks)?;
    }
    marks[index] = 2;
    Ok(())
}

fn validate_framework_id(value: &JsonValue, language: &str) -> Result<(), SignedPackError> {
    let JsonValue::Object(fields) = value else { return Err(SignedPackError::UnsupportedManifest) };
    match string(required(fields, "ecosystem")?)? {
        "maven" => {
            if language != "java" {
                return Err(SignedPackError::UnsupportedManifest);
            }
            object_with_keys(value, &["ecosystem", "group", "artifact"])?;
            for key in ["group", "artifact"] {
                let value = string(required(fields, key)?)?;
                if value.is_empty()
                    || value.len() > 128
                    || !value.is_ascii()
                    || value.contains("..")
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                    })
                {
                    return Err(SignedPackError::UnsupportedManifest);
                }
            }
        }
        "npm" => {
            if language != "node" {
                return Err(SignedPackError::UnsupportedManifest);
            }
            object_with_keys(value, &["ecosystem", "packageName"])?;
            let package = string(required(fields, "packageName")?)?;
            if package.len() > 128 || !valid_npm_name(package) {
                return Err(SignedPackError::UnsupportedManifest);
            }
        }
        "node_builtin" => {
            if language != "node" {
                return Err(SignedPackError::UnsupportedManifest);
            }
            object_with_keys(value, &["ecosystem", "specifier"])?;
            if !matches!(string(required(fields, "specifier")?)?, "node:http" | "node:https") {
                return Err(SignedPackError::UnsupportedManifest);
            }
        }
        _ => return Err(SignedPackError::UnsupportedManifest),
    }
    Ok(())
}

fn valid_npm_name(value: &str) -> bool {
    if !value.is_ascii() || value.is_empty() {
        return false;
    }
    let (scope, name) = match value.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, name)) if !scope.is_empty() && !name.is_empty() && !name.contains('/') => {
                (Some(scope), name)
            }
            _ => return false,
        },
        None if !value.contains('/') => (None, value),
        None => return false,
    };
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && !segment.contains("..")
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    };
    scope.is_none_or(valid_segment) && valid_segment(name)
}

fn valid_package_marker(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value.is_ascii()
        && !value.contains("..")
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'.' | b'$' | b'/' | b'@' | b':' | b'-')
        })
}

fn parse_semver_range(value: &str) -> Result<((u32, u32, u32), (u32, u32, u32)), SignedPackError> {
    let Some((lower, upper)) = value.split_once(' ') else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    let lower = lower.strip_prefix(">=").ok_or(SignedPackError::UnsupportedManifest)?;
    let upper = upper.strip_prefix('<').ok_or(SignedPackError::UnsupportedManifest)?;
    let range = (parse_semver(lower)?, parse_semver(upper)?);
    if range.0 >= range.1 {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(range)
}

fn string_array(
    value: &JsonValue,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<String>, SignedPackError> {
    let JsonValue::Array(values) = value else { return Err(SignedPackError::UnsupportedManifest) };
    if values.len() < minimum || values.len() > maximum {
        return Err(SignedPackError::UnsupportedManifest);
    }
    values.iter().map(|item| string(item).map(str::to_owned)).collect()
}

fn validate_sorted_ids(values: &[String], maximum_width: usize) -> Result<(), SignedPackError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| !valid_ascii_id(value, maximum_width))
    {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(())
}

fn valid_ascii_id(value: &str, maximum_width: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_width
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_string_array(
    value: &JsonValue,
    minimum: usize,
    maximum: usize,
    valid: impl Fn(&str) -> bool,
) -> Result<(), SignedPackError> {
    let values = string_array(value, minimum, maximum)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) || values.iter().any(|item| !valid(item)) {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(())
}

fn validate_capabilities(value: &JsonValue) -> Result<(), SignedPackError> {
    let JsonValue::Object(capabilities) = value else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    const ALLOWED: &[&str] = &[
        "endpoint_discovery",
        "launch",
        "attach",
        "method_frames",
        "line_cursor",
        "locals",
        "async_correlation",
        "database_interaction",
        "outbound_http",
        "source_maps",
        "retransmit",
    ];
    if capabilities.len() > ALLOWED.len() {
        return Err(SignedPackError::UnsupportedManifest);
    }
    for (name, state) in capabilities {
        if !ALLOWED.contains(&name.as_str())
            || !matches!(string(state)?, "unavailable" | "preview" | "supported")
        {
            return Err(SignedPackError::UnsupportedManifest);
        }
    }
    Ok(())
}

fn validate_known_limitations(value: &JsonValue) -> Result<(), SignedPackError> {
    let JsonValue::Array(values) = value else { return Err(SignedPackError::UnsupportedManifest) };
    const ALLOWED: &[&str] = &[
        "attach_disabled",
        "backpressure_dropped",
        "capability_unsupported",
        "daemon_shed",
        "debug_metadata_absent",
        "generated_source_skipped",
        "handler_unresolved",
        "late_attach_partial",
        "missing_body_schema",
        "missing_response_schema",
        "missing_source_map",
        "native_image_unsupported",
        "no_local_variable_table",
        "route_constraint_unresolved",
        "scan_budget_exceeded",
        "session_ended_early",
        "source_attestation_missing",
        "source_hash_mismatch",
        "source_range_unavailable",
        "unsupported_mapping",
        "unverified_framework_version",
    ];
    if values.len() > 64 {
        return Err(SignedPackError::ResourceLimit);
    }
    let mut previous: Option<&str> = None;
    for value in values {
        let code = string(value)?;
        if !ALLOWED.contains(&code) || previous.is_some_and(|value| value >= code) {
            return Err(SignedPackError::UnsupportedManifest);
        }
        previous = Some(code);
    }
    Ok(())
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, SignedPackError> {
        if depth > MAX_JSON_DEPTH || self.nodes >= MAX_JSON_NODES {
            return Err(SignedPackError::ResourceLimit);
        }
        self.nodes += 1;
        match self.peek() {
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'0'..=b'9') => self.parse_unsigned(),
            _ => Err(SignedPackError::InvalidManifest),
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, SignedPackError> {
        self.position += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume_if(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            if values.len() >= MAX_JSON_NODES {
                return Err(SignedPackError::ResourceLimit);
            }
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.consume_if(b']') {
                return Ok(JsonValue::Array(values));
            }
            if !self.consume_if(b',') {
                return Err(SignedPackError::InvalidManifest);
            }
            self.skip_whitespace();
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, SignedPackError> {
        self.position += 1;
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        let mut keys = BTreeSet::new();
        if self.consume_if(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(SignedPackError::InvalidManifest);
            }
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(SignedPackError::InvalidManifest);
            }
            self.skip_whitespace();
            if !self.consume_if(b':') {
                return Err(SignedPackError::InvalidManifest);
            }
            self.skip_whitespace();
            let value = self.parse_value(depth)?;
            values.insert(key, value);
            self.skip_whitespace();
            if self.consume_if(b'}') {
                return Ok(JsonValue::Object(values));
            }
            if !self.consume_if(b',') {
                return Err(SignedPackError::InvalidManifest);
            }
            self.skip_whitespace();
        }
    }

    fn parse_unsigned(&mut self) -> Result<JsonValue, SignedPackError> {
        let start = self.position;
        if self.consume_if(b'0') {
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(SignedPackError::InvalidManifest);
            }
        } else {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'+' | b'-')) {
            return Err(SignedPackError::InvalidManifest);
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| SignedPackError::InvalidManifest)?;
        let number = text.parse::<u64>().map_err(|_| SignedPackError::InvalidManifest)?;
        if number > MAX_JSON_SAFE_INTEGER {
            return Err(SignedPackError::InvalidManifest);
        }
        Ok(JsonValue::Unsigned(number))
    }

    fn parse_string(&mut self) -> Result<String, SignedPackError> {
        if !self.consume_if(b'"') {
            return Err(SignedPackError::InvalidManifest);
        }
        let mut output = String::new();
        let mut raw_start = self.position;
        loop {
            let byte = self.peek().ok_or(SignedPackError::InvalidManifest)?;
            match byte {
                b'"' => {
                    self.push_utf8_range(&mut output, raw_start, self.position)?;
                    self.position += 1;
                    if output.len() > MAX_JSON_STRING_BYTES {
                        return Err(SignedPackError::ResourceLimit);
                    }
                    return Ok(output);
                }
                b'\\' => {
                    self.push_utf8_range(&mut output, raw_start, self.position)?;
                    self.position += 1;
                    let escape = self.peek().ok_or(SignedPackError::InvalidManifest)?;
                    self.position += 1;
                    match escape {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let first = self.parse_hex_quad()?;
                            let scalar = match first {
                                0xd800..=0xdbff => {
                                    if self.bytes.get(self.position..self.position + 2)
                                        != Some(b"\\u")
                                    {
                                        return Err(SignedPackError::InvalidManifest);
                                    }
                                    self.position += 2;
                                    let second = self.parse_hex_quad()?;
                                    if !(0xdc00..=0xdfff).contains(&second) {
                                        return Err(SignedPackError::InvalidManifest);
                                    }
                                    0x10000
                                        + (((first - 0xd800) as u32) << 10)
                                        + (second - 0xdc00) as u32
                                }
                                0xdc00..=0xdfff => return Err(SignedPackError::InvalidManifest),
                                value => value as u32,
                            };
                            let character =
                                char::from_u32(scalar).ok_or(SignedPackError::InvalidManifest)?;
                            output.push(character);
                        }
                        _ => return Err(SignedPackError::InvalidManifest),
                    }
                    if output.len() > MAX_JSON_STRING_BYTES {
                        return Err(SignedPackError::ResourceLimit);
                    }
                    raw_start = self.position;
                }
                0x00..=0x1f => return Err(SignedPackError::InvalidManifest),
                _ => self.position += 1,
            }
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, SignedPackError> {
        let end = self.position.checked_add(4).ok_or(SignedPackError::InvalidManifest)?;
        let digits = self.bytes.get(self.position..end).ok_or(SignedPackError::InvalidManifest)?;
        let mut value = 0u16;
        for digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(SignedPackError::InvalidManifest),
            };
            value = (value << 4) | u16::from(nibble);
        }
        self.position = end;
        Ok(value)
    }

    fn push_utf8_range(
        &self,
        output: &mut String,
        start: usize,
        end: usize,
    ) -> Result<(), SignedPackError> {
        let text = std::str::from_utf8(
            self.bytes.get(start..end).ok_or(SignedPackError::InvalidManifest)?,
        )
        .map_err(|_| SignedPackError::InvalidManifest)?;
        output.push_str(text);
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), SignedPackError> {
        let end =
            self.position.checked_add(literal.len()).ok_or(SignedPackError::InvalidManifest)?;
        if self.bytes.get(self.position..end) != Some(literal) {
            return Err(SignedPackError::InvalidManifest);
        }
        self.position = end;
        Ok(())
    }

    fn consume_if(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
}

fn write_canonical(value: &JsonValue, output: &mut Vec<u8>) -> Result<(), SignedPackError> {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(true) => output.extend_from_slice(b"true"),
        JsonValue::Bool(false) => output.extend_from_slice(b"false"),
        JsonValue::Unsigned(number) => output.extend_from_slice(number.to_string().as_bytes()),
        JsonValue::String(text) => write_string(text, output),
        JsonValue::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        JsonValue::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_string(key, output);
                output.push(b':');
                let item = values.get(*key).ok_or(SignedPackError::InvalidManifest)?;
                write_canonical(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn write_string(text: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in text.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{0009}' => output.extend_from_slice(b"\\t"),
            '\u{000a}' => output.extend_from_slice(b"\\n"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\u{000d}' => output.extend_from_slice(b"\\r"),
            value if value <= '\u{001f}' => {
                let code = value as u32;
                output.extend_from_slice(b"\\u00");
                output.push(hex_digit(((code >> 4) & 0xf) as u8));
                output.push(hex_digit((code & 0xf) as u8));
            }
            value => {
                let mut encoded = [0; 4];
                output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

/// Returns the canonical signed message with only `signature.value` omitted.
pub fn signed_message(manifest: &[u8]) -> Result<Vec<u8>, SignedPackError> {
    let _parsed = parse_canonical_manifest(manifest)?;
    let mut value = parse_canonical_value(manifest)?;
    let JsonValue::Object(fields) = &mut value else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    let signature = fields.get_mut("signature").ok_or(SignedPackError::UnsupportedManifest)?;
    let JsonValue::Object(signature_fields) = signature else {
        return Err(SignedPackError::UnsupportedManifest);
    };
    if signature_fields.remove("value").is_none() {
        return Err(SignedPackError::UnsupportedManifest);
    }
    let mut message = SIGNED_MESSAGE_DOMAIN.to_vec();
    write_canonical(&value, &mut message)?;
    Ok(message)
}

/// Computes the separately named outer BLAKE3 digest of a signed JCS manifest.
pub fn outer_manifest_digest(manifest: &[u8]) -> Result<[u8; 32], SignedPackError> {
    let _parsed = parse_canonical_manifest(manifest)?;
    let value = parse_canonical_value(manifest)?;
    let mut canonical = Vec::with_capacity(manifest.len());
    write_canonical(&value, &mut canonical)?;
    Ok(*blake3::hash(&canonical).as_bytes())
}

/// A path and BLAKE3 digest in the signed outer artifact inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDigest {
    /// Relative slash-separated inventory path.
    pub path: String,
    /// BLAKE3-256 of the exact artifact bytes.
    pub digest: [u8; 32],
}

/// Encodes the fixed v1 build-hash frame from sorted artifact rows.
pub fn build_hash_frame(artifacts: &[ArtifactDigest]) -> Result<Vec<u8>, SignedPackError> {
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(SignedPackError::ResourceLimit);
    }
    let count = u32::try_from(artifacts.len()).map_err(|_| SignedPackError::ResourceLimit)?;
    let mut previous: Option<&str> = None;
    let mut frame = Vec::new();
    frame.extend_from_slice(BUILD_HASH_DOMAIN);
    frame.extend_from_slice(&count.to_be_bytes());
    for artifact in artifacts {
        if !valid_artifact_path(&artifact.path)
            || previous.is_some_and(|value| value >= artifact.path.as_str())
        {
            return Err(SignedPackError::InventoryMismatch);
        }
        previous = Some(&artifact.path);
        let path_bytes = artifact.path.as_bytes();
        let path_length =
            u32::try_from(path_bytes.len()).map_err(|_| SignedPackError::ResourceLimit)?;
        frame.extend_from_slice(&path_length.to_be_bytes());
        frame.extend_from_slice(path_bytes);
        frame.extend_from_slice(&artifact.digest);
    }
    Ok(frame)
}

/// Computes the v1 BLAKE3 build hash from canonical inventory rows.
pub fn build_hash(artifacts: &[ArtifactDigest]) -> Result<[u8; 32], SignedPackError> {
    Ok(*blake3::hash(&build_hash_frame(artifacts)?).as_bytes())
}

/// Confirms that the manifest's declared build hash matches its canonical rows.
pub fn verify_declared_build_hash(manifest: &[u8]) -> Result<PackManifest, SignedPackError> {
    let parsed = parse_canonical_manifest(manifest)?;
    if build_hash(&parsed.artifact_digests)? != parsed.build_hash {
        return Err(SignedPackError::BuildHashMismatch);
    }
    Ok(parsed)
}

fn valid_artifact_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 255
        || !path.is_ascii()
        || path.to_ascii_lowercase() == "xtrace-pack.json"
    {
        return false;
    }
    path.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

/// Fixed keys compiled into an independently accepted X-trace core binary.
///
/// This source checkpoint contains no release public key, so every signed
/// release request remains unavailable until an authorized key is supplied.
const TRUSTED_RELEASE_KEYS: &[TrustedReleaseKey] = &[];

struct TrustedReleaseKey {
    key_id: &'static str,
    public_key: [u8; 32],
    minimum_release: (u32, u32, u32),
    maximum_release: (u32, u32, u32),
    revoked: bool,
}

/// Verifies the signed projection using only the fixed core-binary trust table.
pub fn verify_with_installed_trust(manifest: &[u8]) -> Result<(), SignedPackError> {
    let parsed = parse_canonical_manifest(manifest)?;
    let key = TRUSTED_RELEASE_KEYS
        .iter()
        .find(|candidate| candidate.key_id == parsed.key_id)
        .ok_or(SignedPackError::TrustUnavailable)?;
    let release = parse_semver(parsed.release_minimum.as_str())?;
    if key.revoked || release < key.minimum_release || release > key.maximum_release {
        return Err(SignedPackError::TrustUnavailable);
    }
    let message = signed_message(manifest)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key.public_key)
        .verify(&message, &parsed.signature)
        .map_err(|_| SignedPackError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] = concat!(
        "{\"artifacts\":[{\"hash\":\"b3:0000000000000000000000000000000000000000000000000000000000000000\",\"path\":\"pack.manifest\"}],",
        "\"capabilities\":{},\"entrypoints\":{\"attach\":\"pack.manifest\",\"launch\":\"pack.manifest\",\"staticDiscovery\":null},",
        "\"frameworkModules\":[],\"knownLimitations\":[],\"pack\":{\"buildHash\":\"b3:0000000000000000000000000000000000000000000000000000000000000000\",\"name\":\"java\",\"version\":\"0.0.1\"},",
        "\"platforms\":[{\"arch\":\"aarch64\",\"os\":\"macos\"}],\"protocol\":{\"max\":\"1.2\",\"min\":\"1.0\"},",
        "\"release\":{\"max\":\"0.0.1\",\"min\":\"0.0.1\"},\"runtime\":{\"language\":\"java\",\"testedMajors\":[17,21],\"versionRange\":\">=17 <22\"},",
        "\"schemaVersion\":1,\"signature\":{\"algorithm\":\"Ed25519\",\"keyId\":\"release-2026\",\"value\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}"
    ).as_bytes();

    #[test]
    fn accepts_canonical_closed_subset_and_rejects_noncanonical_bytes() {
        let parsed = parse_canonical_manifest(MANIFEST);
        assert!(parsed.is_ok());
        if let Ok(facts) = parsed {
            assert_eq!(facts.schema_version(), 1);
            assert_eq!(facts.pack_name(), "java");
            assert_eq!(facts.pack_version(), "0.0.1");
            assert_eq!(facts.runtime_language(), "java");
            assert_eq!(facts.tested_runtime_majors(), &[17, 21]);
            assert_eq!(
                facts.platforms().as_canonical_json(),
                br#"[{"arch":"aarch64","os":"macos"}]"#
            );
            assert_eq!(
                facts.entrypoints().as_canonical_json(),
                br#"{"attach":"pack.manifest","launch":"pack.manifest","staticDiscovery":null}"#
            );
            assert_eq!(facts.framework_modules().as_canonical_json(), b"[]");
            assert_eq!(facts.capabilities().as_canonical_json(), b"{}");
            assert_eq!(facts.known_limitations().as_canonical_json(), b"[]");
        }
        assert!(parse_canonical_value(br#"{"a":1,"b":"x"}"#).is_ok());
        for bytes in [
            br#"{ "a":1,"b":"x"}"#.as_slice(),
            br#"{"b":"x","a":1}"#,
            br#"{"a":01}"#,
            br#"{"a":-1}"#,
            br#"{"a":1.0}"#,
            br#"{"a":1e0}"#,
            br#"{"a":9007199254740992}"#,
        ] {
            assert_eq!(parse_canonical_value(bytes), Err(SignedPackError::InvalidManifest));
        }
    }

    #[test]
    fn rejects_duplicates_unknown_unicode_escapes_and_unpaired_surrogates() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":"\uD800"}"#,
            br#"{"a":"\uDC00"}"#,
            "{\"a\":\"\\u００41\"}".as_bytes(),
            br#"{"a":"\/"}"#,
            br#"{"a":1} trailing"#,
        ] {
            assert_eq!(parse_canonical_value(bytes), Err(SignedPackError::InvalidManifest));
        }
        assert!(parse_canonical_value(br#"{"a":"/"}"#).is_ok());
    }

    #[test]
    fn schema_rejects_unknown_fields_and_runtime_majors_outside_the_declared_range() {
        let with_unknown = MANIFEST
            .strip_suffix(b"}")
            .map(|prefix| [prefix, b",\"unknown\":0}".as_slice()].concat());
        assert_eq!(
            with_unknown.as_deref().map(parse_canonical_manifest),
            Some(Err(SignedPackError::UnsupportedManifest))
        );
        let changed_runtime = replace_once(MANIFEST, b"[17,21]", b"[17,23]");
        assert_eq!(
            parse_canonical_manifest(&changed_runtime),
            Err(SignedPackError::UnsupportedManifest)
        );
        let changed_version = replace_once(MANIFEST, b"\">=17 <22\"", b"\">=017 <22\"");
        assert_eq!(
            parse_canonical_manifest(&changed_version),
            Err(SignedPackError::UnsupportedManifest)
        );
    }

    #[test]
    fn framework_module_framework_tags_are_closed_and_node_https_is_allowed() {
        let https =
            parse_canonical_value(br#"{"ecosystem":"node_builtin","specifier":"node:https"}"#);
        assert!(https.is_ok());
        if let Ok(value) = https {
            assert!(validate_framework_id(&value, "node").is_ok());
            assert_eq!(
                validate_framework_id(&value, "java"),
                Err(SignedPackError::UnsupportedManifest)
            );
        }
        let unknown_builtin =
            parse_canonical_value(br#"{"ecosystem":"node_builtin","specifier":"node:fs"}"#);
        assert_eq!(
            unknown_builtin.map(|value| validate_framework_id(&value, "node")),
            Ok(Err(SignedPackError::UnsupportedManifest))
        );
    }

    #[test]
    fn framework_module_capture_capability_registry_is_exact() {
        for allowed in [
            "method_frames",
            "line_cursor",
            "locals",
            "async_correlation",
            "database_interaction",
            "outbound_http",
            "source_maps",
        ] {
            assert!(parse_canonical_manifest(&manifest_with_module_capture(allowed)).is_ok());
        }
        for forbidden in ["launch", "attach", "retransmit", "endpoint_discovery"] {
            assert_eq!(
                parse_canonical_manifest(&manifest_with_module_capture(forbidden)),
                Err(SignedPackError::UnsupportedManifest),
                "module capture must reject pack-level capability {forbidden}"
            );
        }
    }

    #[test]
    fn npm_coordinates_reject_dot_and_traversal_segments() {
        for accepted in ["react", "@scope/package", "pkg_name-1", "@scope/pkg.name"] {
            assert!(valid_npm_name(accepted), "expected valid npm coordinate {accepted}");
        }
        for rejected in [".", "..", "foo..bar", "@../..", "@scope/..", "@../package", "@scope/."] {
            assert!(
                !valid_npm_name(rejected),
                "expected traversal-like coordinate {rejected} to fail"
            );
        }
    }

    #[test]
    fn signed_message_omits_only_signature_value() {
        let expected = concat!(
            "XTRACE-PACK-v1\0",
            "{\"artifacts\":[{\"hash\":\"b3:0000000000000000000000000000000000000000000000000000000000000000\",\"path\":\"pack.manifest\"}],",
            "\"capabilities\":{},\"entrypoints\":{\"attach\":\"pack.manifest\",\"launch\":\"pack.manifest\",\"staticDiscovery\":null},",
            "\"frameworkModules\":[],\"knownLimitations\":[],\"pack\":{\"buildHash\":\"b3:0000000000000000000000000000000000000000000000000000000000000000\",\"name\":\"java\",\"version\":\"0.0.1\"},",
            "\"platforms\":[{\"arch\":\"aarch64\",\"os\":\"macos\"}],\"protocol\":{\"max\":\"1.2\",\"min\":\"1.0\"},",
            "\"release\":{\"max\":\"0.0.1\",\"min\":\"0.0.1\"},\"runtime\":{\"language\":\"java\",\"testedMajors\":[17,21],\"versionRange\":\">=17 <22\"},",
            "\"schemaVersion\":1,\"signature\":{\"algorithm\":\"Ed25519\",\"keyId\":\"release-2026\"}}"
        );
        assert_eq!(signed_message(MANIFEST).as_deref(), Ok(expected.as_bytes()));
        assert!(parse_canonical_manifest(MANIFEST).is_ok());
    }

    #[test]
    fn build_frame_uses_literal_domain_count_path_and_digest_bytes() {
        let rows = [ArtifactDigest { path: "a".to_owned(), digest: [0; 32] }];
        let expected =
            [b"XTRACE-PACK-BUILD-v1\0\0\0\0\x01\0\0\0\x01a".as_slice(), &[0; 32]].concat();
        assert_eq!(build_hash_frame(&rows), Ok(expected));
        let digest = build_hash(&rows);
        assert_eq!(
            digest.map(|value| {
                let encoded = value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
                format!("b3:{encoded}")
            }),
            Ok("b3:94dc4d7b11900871f9161a2c0892224c59eb04d974ae99648cb7284ece868d72".to_owned())
        );
    }

    #[test]
    fn build_frame_rejects_unsorted_and_unsafe_inventory_paths() {
        let first = ArtifactDigest { path: "b".to_owned(), digest: [0; 32] };
        let second = ArtifactDigest { path: "a".to_owned(), digest: [0; 32] };
        assert_eq!(build_hash_frame(&[first, second]), Err(SignedPackError::InventoryMismatch));
        for path in ["../a", "a//b", "/a", "a\\b", "a/./b", "a/../b"] {
            let row = ArtifactDigest { path: path.to_owned(), digest: [0; 32] };
            assert_eq!(build_hash_frame(&[row]), Err(SignedPackError::InventoryMismatch));
        }
    }

    #[test]
    fn verifies_public_rfc8032_ed25519_vector_without_a_signing_key() {
        let public_key =
            decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = decode_hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert!(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key)
                .verify(b"", &signature)
                .is_ok()
        );
    }

    #[test]
    fn verifies_second_public_rfc8032_ed25519_vector() {
        let public_key =
            decode_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let signature = decode_hex(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ));
        assert!(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key)
                .verify(&[0x72], &signature)
                .is_ok()
        );
    }

    #[test]
    fn missing_fixed_release_key_never_accepts_pack_supplied_trust() {
        assert_eq!(verify_with_installed_trust(MANIFEST), Err(SignedPackError::TrustUnavailable));
    }

    fn replace_once(source: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let Some(position) = source.windows(from.len()).position(|window| window == from) else {
            return source.to_vec();
        };
        let mut output = Vec::with_capacity(source.len() + to.len());
        output.extend_from_slice(&source[..position]);
        output.extend_from_slice(to);
        output.extend_from_slice(&source[position + from.len()..]);
        output
    }

    fn manifest_with_module_capture(capability: &str) -> Vec<u8> {
        let module = format!(
            concat!(
                "[{{\"after\":[],\"captureCapabilities\":[\"{capability}\"],",
                "\"conflicts\":[],\"discoveryCapabilities\":[],\"fixtureIds\":[],",
                "\"framework\":{{\"artifact\":\"spring-web\",\"ecosystem\":\"maven\",",
                "\"group\":\"org.springframework\"}},\"id\":\"spring.web\",",
                "\"matcherIds\":[],\"packageMarkers\":[\"org.springframework\"],",
                "\"posture\":\"public_hook\",\"requiredRuntimeFeatures\":[],",
                "\"status\":\"experimental\",\"testedVersions\":[\"6.0.0\"],",
                "\"versionRange\":\">=6.0.0 <7.0.0\"}}]"
            ),
            capability = capability
        );
        let changed = replace_once(MANIFEST, b"\"frameworkModules\":[]", module.as_bytes());
        assert_ne!(changed, MANIFEST, "fixture placeholder must be present");
        changed
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().chunks_exact(2) {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            bytes.push((high << 4) | low);
        }
        bytes
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => 0,
        }
    }
}
