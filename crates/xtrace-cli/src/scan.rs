//! `xtrace scan` (lane K): static endpoint discovery.
//!
//! The scan runs a static analyzer as a separate subprocess (never a shell, never the analyzed
//! code), reads its JSON-lines transcript, normalizes and validates every claim with the domain
//! contract, hashes the cited source files itself, and reports what a catalog revision would
//! contain: operations, provenance, confidence, limitation codes and completeness.
//!
//! A scan inside an initialized project is persisted as a catalog discovery run (AD-1): the
//! invoking owner's own command is the owner selection, recorded with a revocation epoch before any
//! claim is written, and the cited source files are re-read when claims are submitted. A complete
//! scan publishes an immutable catalog revision (exit 0); an incomplete one records the run only
//! and never a revision (exit 10), so absence in an incomplete scan can never look like removal.
//! Without an initialized project the scan still analyzes and prints, says why it did not
//! persist, and exits 10. Every revision made here is `dev_unsigned`. Static path hypotheses
//! (call graphs) are not produced at all.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use uuid::Uuid;
use xtrace_domain::catalog_discovery::ValidatedEndpointClaim;
use xtrace_domain::static_claims::{
    ANALYZER_INCOMPLETE_REASONS, AnalyzerLine, StaticClaimContext, StaticClaimError,
    framework_syntax,
};
use xtrace_domain::{ContentHash, ProjectId, SourceRevisionId};

use crate::error::CliError;
use crate::output::write_success;

/// Largest analyzer transcript read, in bytes.
const MAX_TRANSCRIPT_BYTES: usize = 16 * 1024 * 1024;
/// Largest source file hashed for claim evidence, in bytes.
const MAX_HASHED_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Most claims one scan keeps (the discovery run limit).
const MAX_CLAIMS: usize = xtrace_domain::catalog_discovery::MAX_DISCOVERY_RUN_CLAIMS;

/// Arguments for `xtrace scan`.
#[derive(Clone, Debug, clap::Args)]
pub struct ScanArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Source tree to analyze. Must be inside the project directory.
    #[arg(long, value_name = "DIR")]
    pub source: PathBuf,
    /// Framework family: spring-mvc, spring-webflux, express, fastify or nest.
    #[arg(long, value_name = "FAMILY")]
    pub framework: String,
    /// Analyzer executable. Defaults to `XTRACE_JAVA_ANALYZER` (Spring) or
    /// `XTRACE_NODE_ANALYZER` (Node).
    #[arg(long, value_name = "PATH")]
    pub analyzer: Option<PathBuf>,
    /// Application component recorded in every operation identity.
    #[arg(long = "application-component", value_name = "NAME", default_value = "default")]
    pub application_component: String,
    /// Binding key recorded in every operation identity.
    #[arg(long = "binding-key", value_name = "KEY", default_value = "default")]
    pub binding_key: String,
    /// Analyzer wall-clock limit in seconds.
    #[arg(long = "timeout-secs", value_name = "N", default_value_t = 300)]
    pub timeout_secs: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// Why a scan is not a complete picture of the source. Closed vocabulary.
const CLI_INCOMPLETE_REASONS: &[&str] = &[
    "analyzer_diagnostic_unreconciled",
    "analyzer_failed",
    "analyzer_timeout",
    "claim_budget_exceeded",
    "claim_rejected",
    "transcript_invalid",
    "transcript_truncated",
];

/// One operation the scan found, with every claim that contributes to it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScannedOperation {
    /// HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
    /// Always `static_inferred` for a static scan.
    pub provenance: &'static str,
    /// Highest claim confidence in basis points.
    pub confidence_basis_points: u16,
    /// Union of the limitation codes of its claims, sorted.
    pub limitation_codes: Vec<String>,
    /// Distinct handler symbols.
    pub handlers: Vec<String>,
    /// More than one handler claims this operation.
    pub handler_conflict: bool,
    /// Number of contributing claims.
    pub claim_count: usize,
    /// Source file of the first claim.
    pub source_path: String,
    /// 1-based line of the first claim.
    pub source_line: u32,
}

/// Result of processing one analyzer transcript.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// Framework family the analyzer declared.
    pub framework: String,
    /// Analyzer name and version.
    pub analyzer: String,
    /// Rule set identifier.
    pub ruleset_id: String,
    /// `complete` or `incomplete`.
    pub completion: &'static str,
    /// Sorted reasons the scan is incomplete; empty when complete.
    pub incomplete_reasons: Vec<String>,
    /// Number of validated claims.
    pub claim_count: usize,
    /// Number of claim lines that failed validation (each makes the scan incomplete).
    pub rejected_claims: usize,
    /// Number of per-file diagnostics the analyzer reported.
    pub diagnostics: usize,
    /// Number of source files the analyzer read.
    pub files_scanned: u32,
    /// Limitation code to number of claims carrying it.
    pub limitation_histogram: BTreeMap<String, usize>,
    /// Operations, ordered by route then method.
    pub operations: Vec<ScannedOperation>,
}

/// Failure to process a transcript at all (no usable header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptError {
    /// The first line is not a valid header.
    MissingHeader,
    /// The header was rejected.
    Header(StaticClaimError),
}

/// Turns analyzer output into a [`ScanResult`]. `digest_of` hashes the cited source file.
pub fn process_transcript(
    lines: &[String],
    application_component: &str,
    binding_key: &str,
    expected_framework: &str,
    digest_of: &dyn Fn(&str) -> Option<ContentHash>,
) -> Result<ScanResult, TranscriptError> {
    process_transcript_claims(
        lines,
        application_component,
        binding_key,
        expected_framework,
        digest_of,
        ProjectId::from_uuid(Uuid::nil()),
        SourceRevisionId::from_uuid(Uuid::nil()),
    )
    .map(|(result, _claims)| result)
}

/// Like [`process_transcript`], but cites `source_revision_id` in every claim and also returns the
/// validated claims in transcript order, ready to be submitted to a discovery run.
pub fn process_transcript_claims(
    lines: &[String],
    application_component: &str,
    binding_key: &str,
    expected_framework: &str,
    digest_of: &dyn Fn(&str) -> Option<ContentHash>,
    project_id: ProjectId,
    source_revision_id: SourceRevisionId,
) -> Result<(ScanResult, Vec<ValidatedEndpointClaim>), TranscriptError> {
    let mut parsed = lines.iter().filter(|line| !line.trim().is_empty());
    let header =
        match parsed.next().and_then(|line| serde_json::from_str::<AnalyzerLine>(line).ok()) {
            Some(AnalyzerLine::Header(header)) => header,
            _ => return Err(TranscriptError::MissingHeader),
        };
    let route_syntax = header.validate().map_err(TranscriptError::Header)?;
    if header.framework != expected_framework {
        return Err(TranscriptError::Header(StaticClaimError::UnknownFramework));
    }
    let context = StaticClaimContext {
        project_id,
        application_component,
        binding_key,
        route_syntax,
        source_revision_id,
    };

    let mut reasons: BTreeSet<&'static str> = BTreeSet::new();
    let mut ended = false;
    let mut analyzer_complete = true;
    let mut files_scanned = 0;
    let mut diagnostics = 0;
    let mut saw_diagnostic = false;
    let mut lines_of_claims = 0_usize;
    let mut declared_claims: Option<u32> = None;
    let mut rejected = 0;
    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut operations: BTreeMap<(String, String), ScannedOperation> = BTreeMap::new();
    let mut claim_count = 0;
    let mut kept_claims: Vec<ValidatedEndpointClaim> = Vec::new();
    for line in parsed {
        let Ok(parsed_line) = serde_json::from_str::<AnalyzerLine>(line) else {
            reasons.insert("transcript_invalid");
            continue;
        };
        match parsed_line {
            AnalyzerLine::Header(_) => {
                reasons.insert("transcript_invalid");
            }
            AnalyzerLine::Diagnostic(diagnostic) => {
                if diagnostic.validate().is_ok() {
                    diagnostics += 1;
                    saw_diagnostic = true;
                } else {
                    reasons.insert("transcript_invalid");
                }
            }
            AnalyzerLine::End(end) => {
                if ended || end.validate().is_err() {
                    reasons.insert("transcript_invalid");
                }
                ended = true;
                declared_claims = Some(end.claims);
                analyzer_complete = end.complete;
                files_scanned = end.files_scanned;
                for reason in &end.incomplete_reasons {
                    // Analyzer reasons are validated by `AnalyzerEnd::validate`; map them on.
                    if let Some(found) = ANALYZER_INCOMPLETE_REASONS
                        .iter()
                        .copied()
                        .find(|candidate| *candidate == reason.as_str())
                    {
                        reasons.insert(found);
                    }
                }
            }
            AnalyzerLine::Claim(_) if ended => {
                // Nothing may follow the `end` line.
                reasons.insert("transcript_invalid");
            }
            AnalyzerLine::Claim(claim) => {
                lines_of_claims += 1;
                if claim_count >= MAX_CLAIMS {
                    reasons.insert("claim_budget_exceeded");
                    continue;
                }
                match claim.into_validated(&context, digest_of) {
                    Ok(validated) => {
                        claim_count += 1;
                        for code in validated.limitation_codes() {
                            *histogram.entry(code.clone()).or_default() += 1;
                        }
                        let key = (
                            validated.operation().route_template.clone(),
                            validated.operation().method.as_str().to_owned(),
                        );
                        let confidence = validated.confidence_basis_points().unwrap_or(0);
                        let (path, line_no) =
                            (claim.evidence.path.clone(), claim.evidence.start_line);
                        let entry =
                            operations.entry(key.clone()).or_insert_with(|| ScannedOperation {
                                method: key.1.clone(),
                                route_template: key.0.clone(),
                                provenance: "static_inferred",
                                confidence_basis_points: confidence,
                                limitation_codes: Vec::new(),
                                handlers: Vec::new(),
                                handler_conflict: false,
                                claim_count: 0,
                                source_path: path,
                                source_line: line_no,
                            });
                        entry.claim_count += 1;
                        entry.confidence_basis_points =
                            entry.confidence_basis_points.max(confidence);
                        for code in validated.limitation_codes() {
                            if !entry.limitation_codes.contains(code) {
                                entry.limitation_codes.push(code.clone());
                            }
                        }
                        if let Some(handler) = validated.handler_symbol() {
                            if !entry.handlers.iter().any(|existing| existing == handler) {
                                entry.handlers.push(handler.to_owned());
                            }
                        }
                        kept_claims.push(validated);
                    }
                    Err(_) => {
                        rejected += 1;
                        reasons.insert("claim_rejected");
                    }
                }
            }
        }
    }
    if declared_claims
        .is_some_and(|declared| usize::try_from(declared).ok() != Some(lines_of_claims))
    {
        // The analyzer's own count disagrees with what arrived: lines were lost or invented.
        reasons.insert("transcript_invalid");
    }
    if !ended {
        reasons.insert("transcript_truncated");
    } else if analyzer_complete && saw_diagnostic {
        // A per-file diagnostic means some source was not understood; an analyzer that still
        // claims `complete` is overstating, so the scan does not believe it.
        reasons.insert("analyzer_diagnostic_unreconciled");
    } else if !analyzer_complete && reasons.is_empty() {
        reasons.insert("analyzer_failed");
    }
    debug_assert!(
        reasons
            .iter()
            .all(|r| CLI_INCOMPLETE_REASONS.contains(r) || ANALYZER_INCOMPLETE_REASONS.contains(r))
    );

    let mut operations: Vec<ScannedOperation> = operations.into_values().collect();
    for operation in &mut operations {
        operation.limitation_codes.sort();
        operation.handlers.sort();
        operation.handler_conflict = operation.handlers.len() > 1;
    }
    operations.sort_by(|a, b| (&a.route_template, &a.method).cmp(&(&b.route_template, &b.method)));
    let result = ScanResult {
        framework: header.framework,
        analyzer: format!("{} {}", header.analyzer_name, header.analyzer_version),
        ruleset_id: header.ruleset_id,
        completion: if reasons.is_empty() { "complete" } else { "incomplete" },
        incomplete_reasons: reasons.into_iter().map(str::to_owned).collect(),
        claim_count,
        rejected_claims: rejected,
        diagnostics,
        files_scanned,
        limitation_histogram: histogram,
        operations,
    };
    Ok((result, kept_claims))
}

/// Joins `relative` under `root` only when it stays inside it (no absolute path, no `..`).
fn contained_join(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute() || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return None;
    }
    Some(root.join(path))
}

/// Hashes a source file under `root`; `None` for anything unsafe or unreadable.
fn hash_source_file(root: &Path, relative: &str) -> Option<ContentHash> {
    let path = contained_join(root, relative)?;
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_HASHED_FILE_BYTES {
        return None;
    }
    // An intermediate directory symlink must not lead outside the source root.
    let canonical_root = std::fs::canonicalize(root).ok()?;
    if !std::fs::canonicalize(&path).ok()?.starts_with(&canonical_root) {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    Some(ContentHash::of_bytes(&bytes))
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::InvalidArgument(message.into())
}

/// Reads at most [`MAX_TRANSCRIPT_BYTES`] and waits for exit. Returns the stdout lines and whether
/// the analyzer timed out or failed.
async fn run_analyzer(
    analyzer: &Path,
    source: &Path,
    framework: &str,
    timeout: Duration,
) -> Result<(Vec<String>, Option<&'static str>), CliError> {
    let mut command = Command::new(analyzer);
    command.arg("--source-root").arg(source);
    // Node analyzers need the family; the Java analyzer accepts the same flag.
    command.arg("--framework").arg(framework);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    // Own process group: a forking wrapper (npm, node launcher, non-exec shell) is stopped as a
    // whole, by the PID this process started, never by pattern.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| invalid("the analyzer could not be started; check --analyzer"))?;
    let started_pid = child.id();
    let mut stdout = child.stdout.take().ok_or_else(|| invalid("analyzer produced no stdout"))?;
    // One deadline covers reading the transcript and waiting for the analyzer to exit.
    let work = async {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            let read = stdout.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            if buffer.len() + read > MAX_TRANSCRIPT_BYTES {
                return Err(std::io::Error::other("transcript too large"));
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let status = child.wait().await?;
        Ok((buffer, status))
    };
    let outcome = tokio::time::timeout(timeout, work).await;
    let (bytes, problem) = match outcome {
        Ok(Ok((bytes, status))) => {
            (bytes, if status.success() { None } else { Some("analyzer_failed") })
        }
        Ok(Err(_)) => (Vec::new(), Some("analyzer_failed")),
        Err(_) => (Vec::new(), Some("analyzer_timeout")),
    };
    if problem.is_some() {
        // The `work` future (and its borrow of `child`) is gone; stop the whole group, then reap.
        stop_group(started_pid);
        let _ = child.start_kill();
        let _ = child.wait().await;
        if problem == Some("analyzer_timeout") || bytes.is_empty() {
            return Ok((Vec::new(), problem));
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let lines = text.lines().map(str::to_owned).collect();
    Ok((lines, problem))
}

/// Signals the process group led by the analyzer we started (KILL; it is a scanner, not a service).
#[cfg(unix)]
fn stop_group(pid: Option<u32>) {
    use rustix::process::{Pid, Signal, kill_process_group};
    let Some(raw) = pid.and_then(|p| i32::try_from(p).ok()) else {
        return;
    };
    if let Some(group) = Pid::from_raw(raw) {
        let _ = kill_process_group(group, Signal::KILL);
    }
}

#[cfg(not(unix))]
fn stop_group(_pid: Option<u32>) {}

/// Runs `xtrace scan`.
pub async fn run(args: ScanArgs) -> Result<i32, CliError> {
    let project = std::fs::canonicalize(&args.project_dir)
        .map_err(|_| CliError::ProjectDirectoryMissing("project directory not found".to_owned()))?;
    let source =
        std::fs::canonicalize(&args.source).map_err(|_| invalid("source directory not found"))?;
    if !source.is_dir() {
        return Err(invalid("source must be a directory"));
    }
    if !source.starts_with(&project) {
        return Err(invalid("source must be inside the project directory"));
    }
    // jaxrs is a valid claim vocabulary entry but no analyzer produces it yet.
    if args.framework == "jaxrs" {
        return Err(invalid(
            "no jaxrs analyzer exists yet; use spring-mvc, spring-webflux, express, fastify or nest",
        ));
    }
    framework_syntax(&args.framework).map_err(|_| {
        invalid("framework must be spring-mvc, spring-webflux, express, fastify or nest")
    })?;
    let analyzer = match &args.analyzer {
        Some(path) => path.clone(),
        None => {
            let variable = if args.framework.starts_with("spring") {
                "XTRACE_JAVA_ANALYZER"
            } else {
                "XTRACE_NODE_ANALYZER"
            };
            std::env::var_os(variable)
                .map(PathBuf::from)
                .ok_or_else(|| invalid(format!("no analyzer: pass --analyzer or set {variable}")))?
        }
    };

    let (lines, problem) = run_analyzer(
        &analyzer,
        &source,
        &args.framework,
        Duration::from_secs(args.timeout_secs.max(1)),
    )
    .await?;

    let mut cache: HashMap<String, Option<ContentHash>> = HashMap::new();
    let mut digest = |path: &str| -> Option<ContentHash> {
        *cache.entry(path.to_owned()).or_insert_with(|| hash_source_file(&source, path))
    };
    // `process_transcript` takes a shared closure; precompute digests for every cited path.
    let cited: BTreeSet<String> = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<AnalyzerLine>(line).ok())
        .filter_map(|line| match line {
            AnalyzerLine::Claim(claim) => Some(claim.evidence.path),
            _ => None,
        })
        .collect();
    let digests: HashMap<String, Option<ContentHash>> =
        cited.into_iter().map(|path| (path.clone(), digest(&path))).collect();
    let lookup = |path: &str| digests.get(path).copied().flatten();

    let source_revision_id = derive_source_revision_id(&digests);
    let target = persist::open_target(&args.project_dir);
    let project_id = target.as_ref().map_or(ProjectId::from_uuid(Uuid::nil()), |t| t.project_id);
    let (mut result, claims) = match process_transcript_claims(
        &lines,
        &args.application_component,
        &args.binding_key,
        &args.framework,
        &lookup,
        project_id,
        source_revision_id,
    ) {
        Ok(found) => found,
        // A killed or failed analyzer may have written nothing; report that as an incomplete scan
        // rather than a usage error.
        Err(_) if problem.is_some() => (
            ScanResult {
                framework: args.framework.clone(),
                analyzer: "unknown".to_owned(),
                ruleset_id: "unknown".to_owned(),
                completion: "incomplete",
                incomplete_reasons: Vec::new(),
                claim_count: 0,
                rejected_claims: 0,
                diagnostics: 0,
                files_scanned: 0,
                limitation_histogram: BTreeMap::new(),
                operations: Vec::new(),
            },
            Vec::new(),
        ),
        Err(_) => {
            return Err(invalid("the analyzer did not produce a valid transcript header"));
        }
    };
    if let Some(reason) = problem {
        let mut reasons: BTreeSet<String> = result.incomplete_reasons.iter().cloned().collect();
        reasons.insert(reason.to_owned());
        result.incomplete_reasons = reasons.into_iter().collect();
        result.completion = "incomplete";
    }

    let persistence = persist::persist_scan(
        target,
        &args,
        &project,
        &source,
        &mut result,
        &claims,
        source_revision_id,
    );
    let (status, exit_code) = persistence.status_and_exit(&result);
    let document = serde_json::json!({
        "status": status,
        "persisted": persistence.revision.is_some(),
        "runId": persistence.run_id,
        "catalogRevisionId": persistence.revision.as_ref().map(|r| r.revision_id),
        "revisionOrdinal": persistence.revision.as_ref().map(|r| r.ordinal),
        "parentRevisionId": persistence.revision.as_ref().and_then(|r| r.parent_revision_id),
        "changes": persistence.changes,
        "reconciliation": persistence.reconciliation,
        "notPersistedBecause": persistence.not_persisted_because,
        "packStatus": "dev_unsigned",
        "pathHypotheses": "not_produced",
        "coverage": coverage_statement(&result.framework),
        "result": result,
    });
    let mut stdout = std::io::stdout().lock();
    if args.json {
        write_success(&mut stdout, &document).map_err(|_| invalid("could not write output"))?;
    } else {
        write_text(&mut stdout, &result, &persistence, status)
            .map_err(|_| invalid("could not write output"))?;
    }
    Ok(exit_code)
}

/// What the static analyzer for a framework does and does not see. `completion: complete` only
/// means that no gap the analyzer can detect was found; it never means the whole route table was
/// seen, so a static `complete` must never be the sole grounds for marking an operation removed.
fn coverage_statement(framework: &str) -> &'static str {
    match framework {
        "spring-mvc" | "spring-webflux" => {
            "annotation-declared mappings in class bodies only; functional RouterFunction routes, \
             interface-declared mappings and programmatic registration are not analyzed"
        }
        "express" => {
            "app/router calls with a statically known receiver; routers built by factories, \
             computed mounts and receivers guessed from their name are partial or unresolved"
        }
        "fastify" => {
            "app.METHOD, route() and relative-plugin register() prefixes; plugins from packages \
             and dynamic registration are not analyzed"
        }
        "nest" => {
            "controller decorators with setGlobalPrefix; RouterModule prefixes, versioning and \
             prefix exclusions are not modelled and mark claims unsupported_mapping"
        }
        _ => "unknown framework: no coverage statement",
    }
}

fn write_text<W: Write>(
    out: &mut W,
    result: &ScanResult,
    persistence: &persist::Persistence,
    status: &str,
) -> std::io::Result<()> {
    writeln!(
        out,
        "scan {} ({}): {} operations from {} claims in {} files, {}",
        result.framework,
        result.analyzer,
        result.operations.len(),
        result.claim_count,
        result.files_scanned,
        result.completion
    )?;
    writeln!(out, "coverage: {}", coverage_statement(&result.framework))?;
    if !result.incomplete_reasons.is_empty() {
        writeln!(out, "incomplete: {}", result.incomplete_reasons.join(", "))?;
    }
    for operation in &result.operations {
        writeln!(
            out,
            "{:7} {}  [{}% {}]  {}:{}{}",
            operation.method,
            operation.route_template,
            operation.confidence_basis_points / 100,
            operation.provenance,
            operation.source_path,
            operation.source_line,
            if operation.limitation_codes.is_empty() {
                String::new()
            } else {
                format!("  ({})", operation.limitation_codes.join(", "))
            }
        )?;
    }
    match (&persistence.revision, &persistence.not_persisted_because) {
        (Some(revision), _) => {
            writeln!(
                out,
                "persisted: catalog revision {} (ordinal {}), {}",
                revision.revision_id, revision.ordinal, status
            )?;
            if let Some(changes) = &persistence.changes {
                let line: Vec<String> =
                    changes.iter().map(|(kind, count)| format!("{count} {kind}")).collect();
                writeln!(out, "changes: {}", line.join(", "))?;
            }
            if let Some(rec) = &persistence.reconciliation {
                writeln!(
                    out,
                    "observed: {} confirmed, {} unobserved, {} undeclared, {} unresolved",
                    rec.confirmed, rec.unobserved, rec.undeclared, rec.unresolved
                )?;
            }
        }
        (None, Some(reason)) => writeln!(out, "not persisted: {reason}; exit 10")?,
        (None, None) => writeln!(out, "not persisted; exit 10")?,
    }
    Ok(())
}

mod persist {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use xtrace_application::catalog_discovery::admission::{
        LocalScanAuthority, LocalScanSelection, SourceSnapshotReader, snapshot_digest,
    };
    use xtrace_application::catalog_discovery::history::{
        CatalogHistoryPort as _, CatalogHistoryService, RevisionEntry, RevisionReconciliation,
    };
    use xtrace_application::{CatalogChangeKind, CatalogDiscoveryService};
    use xtrace_domain::catalog_discovery::{
        ClaimSourceEvidence, DiscoveryChunk, DiscoveryCompletion, DiscoveryRunFinish,
        DiscoveryRunGrant, DiscoveryRunStartRequest, DiscoveryScope, DiscoveryScopeKind,
        MAX_DISCOVERY_CHUNK_BYTES, MAX_DISCOVERY_CHUNK_CLAIMS, MAX_DISCOVERY_RUN_CHUNKS,
        ValidatedEndpointClaim, final_digest, is_discovery_limitation_code,
    };
    use xtrace_domain::{ContentHash, ProjectId, RunId, SourceRevisionId};
    use xtrace_store::SqliteStore;
    use xtrace_store::catalog_admission_store::SqliteCatalogAdmissionStore;
    use xtrace_store::catalog_discovery_store::SqliteCatalogDiscoveryStore;
    use xtrace_store::catalog_history_store::SqliteCatalogHistoryStore;

    use super::{ScanArgs, ScanResult, hash_source_file};

    /// An opened, validated project the scan can persist into.
    pub(super) struct Target {
        pub(super) store: SqliteStore,
        pub(super) project_id: ProjectId,
    }

    /// What persistence achieved. Serialized into the scan document by the caller.
    #[derive(Default)]
    pub(super) struct Persistence {
        pub(super) run_id: Option<RunId>,
        pub(super) run_status: Option<String>,
        pub(super) revision: Option<RevisionEntry>,
        pub(super) changes: Option<BTreeMap<String, usize>>,
        pub(super) reconciliation: Option<RevisionReconciliation>,
        pub(super) not_persisted_because: Option<String>,
    }

    impl Persistence {
        pub(super) fn status_and_exit(&self, result: &ScanResult) -> (&'static str, i32) {
            if self.revision.is_some() && result.completion == "complete" {
                ("persisted_complete", 0)
            } else if self.run_status.as_deref() == Some("incomplete") {
                ("incomplete_recorded", 10)
            } else {
                ("not_persisted", 10)
            }
        }
    }

    #[cfg(unix)]
    pub(super) fn open_target(project_dir: &Path) -> Result<Target, String> {
        let env_reader = crate::paths::read_env_path;
        let preflight = crate::daemon::preflight_project(project_dir, &env_reader)
            .map_err(|_| "the project is not initialized; run `xtrace init` first".to_owned())?;
        let validated = crate::daemon::open_validated_project(preflight)
            .map_err(|_| "the project store could not be opened".to_owned())?;
        Ok(Target { store: validated.store, project_id: validated.project_id })
    }

    #[cfg(not(unix))]
    pub(super) fn open_target(_project_dir: &Path) -> Result<Target, String> {
        Err("catalog persistence needs the Unix private-storage layer".to_owned())
    }

    struct FsReader {
        root: PathBuf,
    }

    impl SourceSnapshotReader for FsReader {
        fn digest(&self, relative_path: &str) -> Option<ContentHash> {
            hash_source_file(&self.root, relative_path)
        }
    }

    fn scope_for(
        args: &ScanArgs,
        project: &Path,
        source: &Path,
        result: &ScanResult,
    ) -> Result<DiscoveryScope, String> {
        let relative = source.strip_prefix(project).unwrap_or(source);
        let key = blake3::hash(relative.to_string_lossy().as_bytes());
        Ok(DiscoveryScope {
            kind: DiscoveryScopeKind::StaticRepository,
            source_root_key: Some(format!("src-{}", &key.to_hex()[..24])),
            module_selector: "default".to_owned(),
            application_component: args.application_component.clone(),
            binding_key: args.binding_key.clone(),
            framework_family: args.framework.clone(),
            producer_family: "local-static-scan".to_owned(),
            ruleset_digest: ContentHash::of_bytes(result.ruleset_id.as_bytes()),
        })
    }

    /// Splits claims into chunks within the claim-count and byte limits.
    fn chunk_claims(
        run_id: RunId,
        claims: &[&ValidatedEndpointClaim],
    ) -> (Vec<DiscoveryChunk>, usize) {
        let mut chunks: Vec<DiscoveryChunk> = Vec::new();
        let mut current: Vec<ValidatedEndpointClaim> = Vec::new();
        let mut bytes = 0_usize;
        let mut dropped = 0_usize;
        for claim in claims {
            let size = claim.canonical_bytes().len();
            if !current.is_empty()
                && (current.len() >= MAX_DISCOVERY_CHUNK_CLAIMS
                    || bytes + size > MAX_DISCOVERY_CHUNK_BYTES - 1024)
            {
                let index = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
                chunks.push(DiscoveryChunk {
                    run_id,
                    chunk_index: index,
                    claims: std::mem::take(&mut current),
                });
                bytes = 0;
            }
            if chunks.len() >= MAX_DISCOVERY_RUN_CHUNKS {
                dropped += 1;
                continue;
            }
            bytes += size;
            current.push((*claim).clone());
        }
        if !current.is_empty() && chunks.len() < MAX_DISCOVERY_RUN_CHUNKS {
            let index = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
            chunks.push(DiscoveryChunk { run_id, chunk_index: index, claims: current });
        }
        (chunks, dropped)
    }

    pub(super) fn persist_scan(
        target: Result<Target, String>,
        args: &ScanArgs,
        project: &Path,
        source: &Path,
        result: &mut ScanResult,
        claims: &[ValidatedEndpointClaim],
        source_revision_id: SourceRevisionId,
    ) -> Persistence {
        let mut out = Persistence::default();
        let target = match target {
            Ok(target) => target,
            Err(reason) => {
                out.not_persisted_because = Some(reason);
                return out;
            }
        };
        if claims.is_empty() {
            out.not_persisted_because = Some("the scan produced no claims to record".to_owned());
            return out;
        }
        match run_persist(
            &target,
            args,
            project,
            source,
            result,
            claims,
            source_revision_id,
            &mut out,
        ) {
            Ok(()) => {}
            Err(reason) => out.not_persisted_because = Some(reason),
        }
        out
    }

    #[allow(clippy::too_many_arguments, reason = "one linear persistence sequence")]
    fn run_persist(
        target: &Target,
        args: &ScanArgs,
        project: &Path,
        source: &Path,
        result: &mut ScanResult,
        claims: &[ValidatedEndpointClaim],
        source_revision_id: SourceRevisionId,
        out: &mut Persistence,
    ) -> Result<(), String> {
        // Cited files and the digests the claims recorded form the pinned snapshot.
        let mut files: BTreeMap<String, ContentHash> = BTreeMap::new();
        for claim in claims {
            for evidence in claim.source_evidence() {
                if let ClaimSourceEvidence::StaticSnapshot {
                    relative_path,
                    recorded_source_digest,
                    ..
                } = evidence
                {
                    files.insert(relative_path.clone(), *recorded_source_digest);
                }
            }
        }
        let scope = scope_for(args, project, source, result)
            .map_err(|_| "the scan scope is invalid".to_owned())?;
        scope.digest().map_err(|_| {
            "--application-component and --binding-key may use letters, digits and ._:- only"
                .to_owned()
        })?;
        let analyzer_digest = ContentHash::of_bytes(
            format!("xtrace.local-analyzer.v1\0{}\0{}", result.analyzer, result.ruleset_id)
                .as_bytes(),
        );
        let selection = LocalScanSelection {
            project_id: target.project_id,
            scope: scope.clone(),
            analyzer_digest,
            source_revision_id,
            pinned_source_digest: snapshot_digest(&files),
        };
        let authority = LocalScanAuthority::establish(
            &SqliteCatalogAdmissionStore::new(target.store.clone()),
            &selection,
            Arc::new(FsReader { root: source.to_path_buf() }),
        )
        .map_err(|error| format!("owner selection could not be recorded: {}", error.message()))?;
        let service = CatalogDiscoveryService::for_local_scan(
            Arc::new(SqliteCatalogDiscoveryStore::new(target.store.clone())),
            &authority,
        );
        let context = authority.context();
        let request = DiscoveryRunStartRequest {
            schema_version: 1,
            run_hint: format!("scan-{}", uuid::Uuid::now_v7().simple()),
            requested_scope: scope.clone(),
            owner_selection_ref: None,
        };
        let run_id = match service.start_run(context, &request) {
            Ok(DiscoveryRunGrant::Admitted { run_id, .. }) => run_id,
            Ok(DiscoveryRunGrant::Refused { reason }) => {
                return Err(format!("the catalog run was refused: {reason:?}"));
            }
            Err(error) => return Err(format!("the catalog run could not start: {error}")),
        };
        out.run_id = Some(run_id);

        // One claim per producer hint: a repeated hint is the same mapping, not a second claim.
        let mut seen = std::collections::BTreeSet::new();
        let unique: Vec<&ValidatedEndpointClaim> =
            claims.iter().filter(|claim| seen.insert(claim.claim_hint().to_owned())).collect();
        let (chunks, dropped) = chunk_claims(run_id, &unique);
        let mut rejected = u32::try_from(result.rejected_claims).unwrap_or(u32::MAX);
        if dropped > 0 {
            rejected = rejected.saturating_add(u32::try_from(dropped).unwrap_or(u32::MAX));
            if !result.incomplete_reasons.iter().any(|r| r == "claim_budget_exceeded") {
                result.incomplete_reasons.push("claim_budget_exceeded".to_owned());
                result.incomplete_reasons.sort();
            }
            result.completion = "incomplete";
        }
        for chunk in &chunks {
            service
                .submit_chunk(context, chunk)
                .map_err(|error| format!("a claim chunk was refused: {error}"))?;
        }
        let completion = if result.completion == "complete" {
            DiscoveryCompletion::Complete
        } else {
            DiscoveryCompletion::Incomplete
        };
        let mut codes: Vec<String> = result
            .incomplete_reasons
            .iter()
            .filter(|reason| is_discovery_limitation_code(reason))
            .cloned()
            .collect();
        codes.sort();
        codes.dedup();
        if completion == DiscoveryCompletion::Complete {
            codes.clear();
        }
        let accepted: u32 =
            u32::try_from(chunks.iter().map(|c| c.claims.len()).sum::<usize>()).unwrap_or(u32::MAX);
        let digest =
            final_digest(run_id, &scope, Some(source_revision_id), &chunks, rejected, completion)
                .map_err(|_| "the run digest could not be computed".to_owned())?;
        let finish = DiscoveryRunFinish {
            run_id,
            expected_chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            accepted_claim_count: accepted,
            rejected_claim_count: rejected,
            final_digest: digest,
            completion,
            limitation_codes: codes,
        };
        service
            .finish_run(context, &finish)
            .map_err(|error| format!("the catalog run could not finish: {error}"))?;

        let history = SqliteCatalogHistoryStore::new(target.store.clone());
        let run = history
            .run(target.project_id, run_id)
            .map_err(|error| format!("the run could not be read back: {}", error.message()))?;
        out.run_status = run.as_ref().map(|run| run.status.clone());
        let Some(revision_id) = run.and_then(|run| run.revision_id) else {
            return Ok(());
        };
        let reader = CatalogHistoryService::new(history);
        let (entry, operations) = reader
            .operations(target.project_id, Some(revision_id))
            .map_err(|error| format!("the revision could not be read back: {error}"))?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for operation in &operations {
            *counts.entry(operation.change_kind.as_str().to_owned()).or_default() += 1;
        }
        for kind in [
            CatalogChangeKind::Added,
            CatalogChangeKind::Changed,
            CatalogChangeKind::Unchanged,
            CatalogChangeKind::Unknown,
        ] {
            counts.entry(kind.as_str().to_owned()).or_default();
        }
        out.changes = Some(counts);
        out.reconciliation =
            reader.reconcile_with_observations(target.project_id, Some(revision_id)).ok();
        out.revision = Some(entry);
        Ok(())
    }
}

/// Content-derived source revision id: identical cited bytes give an identical id, so a rescan of
/// unchanged source yields identical claim digests and the diff reports `unchanged`. A cited file
/// that changes (or disappears) changes the id, so `changed` means a cited byte changed.
fn derive_source_revision_id(digests: &HashMap<String, Option<ContentHash>>) -> SourceRevisionId {
    let ordered: BTreeMap<&str, Option<&ContentHash>> =
        digests.iter().map(|(path, hash)| (path.as_str(), hash.as_ref())).collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.scan.source-revision.v1\0");
    for (path, hash) in ordered {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        match hash {
            Some(hash) => {
                hasher.update(&[1]);
                hasher.update(hash.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    SourceRevisionId::from_uuid(Uuid::from_bytes(bytes))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "unit tests assert on fixed transcripts"
)]
mod tests {
    use super::*;

    #[test]
    fn source_revision_id_is_content_derived_and_uuid_v7_shaped() {
        use xtrace_domain::ids::Id as _;
        let mut digests: HashMap<String, Option<ContentHash>> = HashMap::new();
        digests.insert("a.js".to_owned(), Some(ContentHash::of_bytes(b"one")));
        digests.insert("b.js".to_owned(), None);
        let first = derive_source_revision_id(&digests);
        assert_eq!(first, derive_source_revision_id(&digests.clone()));
        let uuid = first.as_uuid();
        assert_eq!(uuid.get_version_num(), 7);
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
        digests.insert("a.js".to_owned(), Some(ContentHash::of_bytes(b"two")));
        assert_ne!(first, derive_source_revision_id(&digests));
    }

    fn digest(path: &str) -> Option<ContentHash> {
        (path != "missing.js").then(|| ContentHash::of_bytes(path.as_bytes()))
    }

    fn header(framework: &str) -> String {
        format!(
            r#"{{"type":"header","contractVersion":1,"analyzerName":"fake","analyzerVersion":"0.0.1","rulesetId":"r/1","framework":"{framework}"}}"#
        )
    }

    fn claim(method: &str, parts: &str, path: &str, line: u32, extra: &str) -> String {
        format!(
            r#"{{"type":"claim","method":"{method}","routeParts":{parts},"routeBasis":"literal",{extra}"evidence":{{"path":"{path}","startLine":{line},"startColumn":1,"endLine":{line},"endColumn":9}}}}"#
        )
    }

    const END_OK: &str =
        r#"{"type":"end","claims":0,"filesScanned":2,"complete":true,"incompleteReasons":[]}"#;

    fn end_ok(claims: u32) -> String {
        format!(
            r#"{{"type":"end","claims":{claims},"filesScanned":2,"complete":true,"incompleteReasons":[]}}"#
        )
    }

    fn scan(lines: &[String]) -> ScanResult {
        process_transcript(lines, "app", "default", "express", &digest).expect("processes")
    }

    #[test]
    fn complete_transcript_yields_operations_with_static_provenance() {
        let result = scan(&[
            header("express"),
            claim("GET", r#"["/api","/users/:id"]"#, "a.js", 3, r#""handler":"show","#),
            claim("POST", r#"["/api","/users"]"#, "a.js", 4, ""),
            end_ok(2),
        ]);
        assert_eq!(result.completion, "complete");
        assert_eq!(result.claim_count, 2);
        let routes: Vec<_> = result
            .operations
            .iter()
            .map(|o| (o.method.as_str(), o.route_template.as_str()))
            .collect();
        assert_eq!(routes, [("POST", "/api/users"), ("GET", "/api/users/{id}")]);
        assert!(result.operations.iter().all(|o| o.provenance == "static_inferred"));
        assert_eq!(result.operations[1].confidence_basis_points, 9000);
        assert_eq!(result.operations[1].handlers, ["show"]);
    }

    #[test]
    fn param_renames_collapse_into_one_operation_and_conflicting_handlers_are_flagged() {
        let result = scan(&[
            header("express"),
            claim("GET", r#"["/u/:id"]"#, "a.js", 1, r#""handler":"one","#),
            claim("GET", r#"["/u/:userId"]"#, "b.js", 2, r#""handler":"two","#),
            end_ok(2),
        ]);
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0].claim_count, 2);
        assert!(result.operations[0].handler_conflict);
    }

    #[test]
    fn complete_claim_with_a_diagnostic_is_not_believed() {
        let lines = [
            header("express"),
            claim("GET", r#"["/a"]"#, "a.js", 1, ""),
            r#"{"type":"diagnostic","code":"unsupported_syntax","path":"a.js"}"#.to_owned(),
            r#"{"type":"end","claims":1,"filesScanned":1,"complete":true,"incompleteReasons":[]}"#
                .to_owned(),
        ];
        let result = scan(&lines);
        assert_eq!(result.completion, "incomplete");
        assert_eq!(result.incomplete_reasons, ["analyzer_diagnostic_unreconciled"]);
        assert_eq!(result.diagnostics, 1);
    }

    #[test]
    fn unsupported_syntax_is_an_analyzer_incomplete_reason() {
        let lines = [
            header("express"),
            r#"{"type":"diagnostic","code":"unsupported_syntax","path":"a.js"}"#.to_owned(),
            r#"{"type":"end","claims":0,"filesScanned":1,"complete":false,"incompleteReasons":["unsupported_syntax"]}"#
                .to_owned(),
        ];
        let result = scan(&lines);
        assert_eq!(result.incomplete_reasons, ["unsupported_syntax"]);
    }

    #[test]
    fn end_count_mismatch_and_lines_after_end_are_invalid() {
        let mismatch =
            scan(&[header("express"), claim("GET", r#"["/a"]"#, "a.js", 1, ""), end_ok(5)]);
        assert_eq!(mismatch.incomplete_reasons, ["transcript_invalid"]);
        let after = scan(&[
            header("express"),
            claim("GET", r#"["/a"]"#, "a.js", 1, ""),
            end_ok(1),
            claim("GET", r#"["/b"]"#, "a.js", 2, ""),
        ]);
        assert_eq!(after.incomplete_reasons, ["transcript_invalid"]);
        assert_eq!(after.operations.len(), 1);
    }

    #[test]
    fn missing_end_line_means_truncated_and_incomplete() {
        let result = scan(&[header("express"), claim("GET", r#"["/a"]"#, "a.js", 1, "")]);
        assert_eq!(result.completion, "incomplete");
        assert_eq!(result.incomplete_reasons, ["transcript_truncated"]);
        assert_eq!(result.claim_count, 1);
    }

    #[test]
    fn analyzer_incompleteness_and_rejected_claims_are_visible() {
        let lines = [
            header("express"),
            claim("GET", r#"["/ok"]"#, "a.js", 1, ""),
            claim("GET", r#"["/nofile"]"#, "missing.js", 1, ""),
            claim("FETCH", r#"["/x"]"#, "a.js", 1, ""),
            r#"{"type":"diagnostic","code":"parse_error","path":"b.js"}"#.to_owned(),
            r#"{"type":"end","claims":3,"filesScanned":3,"complete":false,"incompleteReasons":["parse_error"]}"#
                .to_owned(),
        ];
        let result = scan(&lines);
        assert_eq!(result.completion, "incomplete");
        assert_eq!(result.incomplete_reasons, ["claim_rejected", "parse_error"]);
        assert_eq!(result.rejected_claims, 2);
        assert_eq!(result.claim_count, 1);
        assert_eq!(result.diagnostics, 1);
    }

    #[test]
    fn limitation_codes_are_counted_and_unknown_ones_rejected() {
        let result = scan(&[
            header("express"),
            claim(
                "GET",
                r#"["/{X}"]"#,
                "a.js",
                1,
                r#""limitations":["route_constant_unresolved"],"#,
            ),
            claim("GET", r#"["/y"]"#, "a.js", 2, r#""limitations":["made_up"],"#),
            end_ok(2),
        ]);
        assert_eq!(result.limitation_histogram.get("route_constant_unresolved"), Some(&1));
        assert_eq!(result.rejected_claims, 1);
        assert_eq!(result.operations[0].limitation_codes, ["route_constant_unresolved"]);
    }

    #[test]
    fn garbage_lines_make_the_scan_incomplete_and_a_bad_header_is_fatal() {
        let result = scan(&[header("express"), "not json".to_owned(), END_OK.to_owned()]);
        assert_eq!(result.incomplete_reasons, ["transcript_invalid"]);
        assert_eq!(
            process_transcript(&["{}".to_owned()], "a", "b", "express", &digest).unwrap_err(),
            TranscriptError::MissingHeader
        );
        assert_eq!(
            process_transcript(&[header("fastify")], "a", "b", "express", &digest).unwrap_err(),
            TranscriptError::Header(StaticClaimError::UnknownFramework)
        );
    }

    #[test]
    fn text_output_states_per_framework_coverage() {
        let result =
            scan(&[header("express"), claim("GET", r#"["/a"]"#, "a.js", 1, ""), end_ok(1)]);
        let mut out = Vec::new();
        write_text(&mut out, &result).expect("writes");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("coverage: app/router calls"), "{text}");
        for framework in ["spring-mvc", "spring-webflux", "express", "fastify", "nest"] {
            assert!(
                !coverage_statement(framework).starts_with("unknown"),
                "{framework} has a statement"
            );
        }
    }

    /// Real analyzer output committed as golden files; the analyzer's own test asserts byte
    /// equality with the same files, so a field rename on either side fails a suite.
    #[test]
    fn node_analyzer_golden_transcripts_pass_the_validator() {
        let express = include_str!(
            "../../../adapters/node/packages/analyzer/golden/express-basic.transcript.jsonl"
        );
        let nest = include_str!(
            "../../../adapters/node/packages/analyzer/golden/nest-versioned.transcript.jsonl"
        );
        let lines = |text: &str| text.lines().map(str::to_owned).collect::<Vec<_>>();
        let result = process_transcript(&lines(express), "app", "default", "express", &digest)
            .expect("express golden transcript validates");
        assert_eq!(result.completion, "complete");
        assert_eq!(result.claim_count, 15);
        assert_eq!(result.rejected_claims, 0);
        let result = process_transcript(&lines(nest), "app", "default", "nest", &digest)
            .expect("nest golden transcript validates");
        assert_eq!(result.claim_count, 1);
        assert_eq!(result.operations.len(), 1);
        assert!(result.operations[0].limitation_codes.contains(&"unsupported_mapping".to_owned()));
    }

    #[test]
    fn contained_join_refuses_escapes() {
        let root = Path::new("/r");
        assert!(contained_join(root, "a/b.js").is_some());
        assert!(contained_join(root, "../x").is_none());
        assert!(contained_join(root, "/etc/passwd").is_none());
        assert!(contained_join(root, "a/../b").is_none());
    }
}
