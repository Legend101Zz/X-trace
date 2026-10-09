//! `xtrace scan` (lane K): static endpoint discovery.
//!
//! The scan runs a static analyzer as a separate subprocess (never a shell, never the analyzed
//! code), reads its JSON-lines transcript, normalizes and validates every claim with the domain
//! contract, hashes the cited source files itself, and reports what a catalog revision would
//! contain: operations, provenance, confidence, limitation codes and completeness.
//!
//! Honest scope of this build: claims are validated but not yet persisted as a catalog revision,
//! because the owner-selection admission that lets a local scan submit through
//! `CatalogDiscoveryService` (AD-1) is not implemented. The command therefore prints the full
//! result and exits with the partial status (10); it never claims a stored revision. Static path
//! hypotheses (call graphs) are not produced at all.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use uuid::Uuid;
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
        project_id: ProjectId::from_uuid(Uuid::nil()),
        application_component,
        binding_key,
        route_syntax,
        source_revision_id: SourceRevisionId::from_uuid(Uuid::nil()),
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
    Ok(ScanResult {
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
    })
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

    let mut result = match process_transcript(
        &lines,
        &args.application_component,
        &args.binding_key,
        &args.framework,
        &lookup,
    ) {
        Ok(result) => result,
        // A killed or failed analyzer may have written nothing; report that as an incomplete scan
        // rather than a usage error.
        Err(_) if problem.is_some() => ScanResult {
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

    let document = serde_json::json!({
        "status": "analyzed_not_persisted",
        "persisted": false,
        "catalogRevisionId": serde_json::Value::Null,
        "packStatus": "dev_unsigned",
        "notPersistedBecause": "owner-selection admission for local scans (AD-1) is not implemented in this build",
        "pathHypotheses": "not_produced",
        "coverage": coverage_statement(&result.framework),
        "result": result,
    });
    let mut stdout = std::io::stdout().lock();
    if args.json {
        write_success(&mut stdout, &document).map_err(|_| invalid("could not write output"))?;
    } else {
        write_text(&mut stdout, &result).map_err(|_| invalid("could not write output"))?;
    }
    Ok(10)
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

fn write_text<W: Write>(out: &mut W, result: &ScanResult) -> std::io::Result<()> {
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
    writeln!(
        out,
        "not persisted: catalog admission (AD-1) is not implemented in this build; exit 10"
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "unit tests assert on fixed transcripts"
)]
mod tests {
    use super::*;

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
        let result = scan(&[header("express"), claim("GET", r#"["/a"]"#, "a.js", 1, ""), end_ok(1)]);
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

    #[test]
    fn contained_join_refuses_escapes() {
        let root = Path::new("/r");
        assert!(contained_join(root, "a/b.js").is_some());
        assert!(contained_join(root, "../x").is_none());
        assert!(contained_join(root, "/etc/passwd").is_none());
        assert!(contained_join(root, "a/../b").is_none());
    }
}
