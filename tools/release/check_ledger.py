#!/usr/bin/env python3
"""Fail-closed validator for v0.01 requirement and evidence receipts.

The checker verifies structure, hashes, candidate/build identity, and detached
signatures against an operator-supplied trust configuration inside the
explicit evidence root. It does not decide whether an attestor is a real
participant or whether substantive claims are true; the release owner must
review those facts independently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import stat
import re
import subprocess
import sys
import tempfile
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
BUILD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PINNED_CONTRACTS_PATH = pathlib.Path(__file__).resolve().parents[2] / "evidence/v0.01/requirements.json"
PINNED_CONTRACTS_SHA256 = "ee3ab8c2bb1850e14397019aa2f2d1bb6f654d26be08bfbbdf06e19620f6de8a"
REQUIRED_KIND = {
    "CAMPAIGN-": "campaign",
    "HUMAN-USABILITY": "human_usability",
    "HUMAN-OWNER": "human_owner",
    "PLATFORM-": "platform",
    "SUPPLY-CHAIN": "supply_chain",
    "REVIEWS-EXACT": "reviews",
    "DISTRIBUTED-RECHECK": "distributed_recheck",
}
REQUIRED_IDS = frozenset("""INSTALL-PACK INSTALL-FRESH JAVA-LAUNCH JAVA-ATTACH NODE-LAUNCH
CATALOG-STATIC CATALOG-RUNTIME CATALOG-HISTORY CATALOG-LINKS JAVA-MVC JAVA-WEBFLUX
JAVA-SERVLET JAVA-INTERACTIONS NODE-HTTP NODE-EXPRESS NODE-FASTIFY NODE-NEST
NODE-SOURCE NODE-INTERACTIONS PROCESS-LINKAGE REPLAY-SOURCE REPLAY-LINE REPLAY-FRAMES
REPLAY-OUTCOME REPLAY-NAV REPLAY-CANVAS REPLAY-TUI REPLAY-HONESTY EXPORT-OPENAPI
EXPORT-POSTMAN EXPORT-CURL EXPORT-BUNDLE EXERCISE-PLAN EXERCISE-EXEC
EXERCISE-PROVENANCE RECOVERY-UPGRADE RETENTION-DOCTOR SECURITY-LOCAL PRIVACY-CANARIES
UX-ACCESSIBILITY PERFORMANCE PLATFORM-MAC PLATFORM-LINUX SUPPLY-CHAIN MATRIX
CAMPAIGN-PETCLINIC CAMPAIGN-JHIPSTER CAMPAIGN-FINERACT CAMPAIGN-DIRECTUS
CAMPAIGN-MEDUSA CAMPAIGN-VENDURE HUMAN-USABILITY HUMAN-OWNER REVIEWS-EXACT
DISTRIBUTED-RECHECK""".split())
PETCLINIC_EXCEPTION = "Use current main SHA with explicit tag exception"


class ValidationError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_pinned_contracts() -> dict[str, dict[str, Any]]:
    source = _load_json(PINNED_CONTRACTS_PATH.read_bytes(), "approved requirement manifest")
    rows = source.get("requirements")
    if not isinstance(rows, list):
        raise ValidationError("approved requirement manifest has no requirement rows")
    contracts: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in contracts:
            raise ValidationError("approved requirement manifest has malformed or duplicate IDs")
        contract = {field: row.get(field) for field in ("id", "requirement", "approvedSlice", "mandatory")}
        contracts[row["id"]] = contract
    canonical = canonical_json(sorted(contracts.values(), key=lambda item: item["id"]))
    if sha256(canonical) != PINNED_CONTRACTS_SHA256 or set(contracts) != REQUIRED_IDS:
        raise ValidationError("approved requirement semantics differ from the pinned v0.01 contracts")
    if any(not isinstance(item["requirement"], str) or not isinstance(item["approvedSlice"], str) or item["mandatory"] is not True for item in contracts.values()):
        raise ValidationError("approved requirement manifest has invalid mandatory contract fields")
    return contracts


def _safe_relpath(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError("evidence path must be a non-empty relative POSIX path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValidationError("evidence path escapes the explicit evidence root")
    return path


def read_evidence(root: pathlib.Path, value: Any, expected_hash: Any = None, *, allow_unhashed: bool = False) -> bytes:
    rel = _safe_relpath(value)
    if expected_hash is None and not allow_unhashed:
        raise ValidationError("evidence reference is missing its SHA-256")
    if expected_hash is not None and (not isinstance(expected_hash, str) or not HEX64_RE.fullmatch(expected_hash)):
        raise ValidationError("evidence reference has an invalid SHA-256")
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags_file = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    opened: list[int] = []
    try:
        parent_fd = os.open(root, flags_dir)
        opened.append(parent_fd)
        for part in rel.parts[:-1]:
            parent_fd = os.open(part, flags_dir, dir_fd=parent_fd)
            opened.append(parent_fd)
        file_fd = os.open(rel.parts[-1], flags_file, dir_fd=parent_fd)
        opened.append(file_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("evidence reference does not name a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    except (OSError, NotADirectoryError) as exc:
        raise ValidationError("referenced evidence is missing, unreadable, or traverses a symlink") from exc
    finally:
        for fd in reversed(opened):
            os.close(fd)
    if expected_hash is not None and sha256(data) != expected_hash:
        raise ValidationError("referenced evidence hash mismatch")
    return data


def _load_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValidationError(f"{label} contains a duplicate JSON key")
                value[key] = item
            return value

        result = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValidationError(f"{label} contains non-finite JSON number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid JSON") from exc
    if not isinstance(result, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return result


def _verify_signature(root: pathlib.Path, trust: dict[str, dict[str, Any]], entry: Any, payload: bytes) -> tuple[str, str]:
    if not isinstance(entry, dict):
        raise ValidationError("signature entry must be an object")
    key_id, role = entry.get("keyId"), entry.get("role")
    if not isinstance(key_id, str) or not isinstance(role, str) or key_id not in trust:
        raise ValidationError("signature key is not in the supplied trust configuration")
    key = trust[key_id]
    if role not in key["roles"]:
        raise ValidationError("signature role is not authorized by the trust configuration")
    signature = read_evidence(root, entry.get("path"), entry.get("sha256"))
    public_key = read_evidence(root, key["path"], key["sha256"])
    with tempfile.TemporaryDirectory(prefix="xtrace-attestation-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        payload_path, signature_path, key_path = temp / "payload", temp / "signature", temp / "public-key"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        key_path.write_bytes(public_key)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-sigfile", str(signature_path), "-rawin", "-in", str(payload_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode:
        raise ValidationError("detached signature verification failed")
    return key_id, role


def _trust_config(root: pathlib.Path, relative_path: str) -> tuple[dict[str, dict[str, Any]], str]:
    data = read_evidence(root, relative_path, allow_unhashed=True)
    config = _load_json(data, "trust configuration")
    if config.get("schemaVersion") != 1 or not isinstance(config.get("keys"), list):
        raise ValidationError("trust configuration schema is invalid")
    keys: dict[str, dict[str, Any]] = {}
    public_key_fingerprints: dict[str, str] = {}
    for item in config["keys"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("roles"), list):
            raise ValidationError("trust key entry is malformed")
        if item["id"] in keys or not item["roles"] or any(not isinstance(role, str) for role in item["roles"]):
            raise ValidationError("trust key IDs and roles must be unique and non-empty")
        pub = read_evidence(root, item.get("publicKey"), item.get("publicKeySha256"))
        if not pub:
            raise ValidationError("trusted public key is empty")
        with tempfile.TemporaryDirectory(prefix="xtrace-trusted-key-") as temp_dir:
            key_path = pathlib.Path(temp_dir) / "public-key.pem"
            key_path.write_bytes(pub)
            try:
                normalized = subprocess.run(
                    ["openssl", "pkey", "-pubin", "-in", str(key_path), "-pubout", "-outform", "DER"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
            except OSError as exc:
                raise ValidationError("OpenSSL is required to validate trusted public keys") from exc
        if normalized.returncode or not normalized.stdout:
            raise ValidationError("trusted public key is not a valid OpenSSL public key")
        key_fingerprint = sha256(normalized.stdout)
        if key_fingerprint in public_key_fingerprints:
            raise ValidationError("trust configuration aliases one public key under multiple signer IDs")
        public_key_fingerprints[key_fingerprint] = item["id"]
        keys[item["id"]] = {"roles": item["roles"], "path": item["publicKey"], "sha256": item["publicKeySha256"]}
    return keys, sha256(data)


def _ref(root: pathlib.Path, item: Any, label: str) -> None:
    if not isinstance(item, dict):
        raise ValidationError(f"{label} reference must be an object")
    read_evidence(root, item.get("path"), item.get("sha256"))


def validate_release_build(root: pathlib.Path, candidate: str, value: Any) -> tuple[dict[str, Any], dict[str, set[str | None]]]:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not BUILD_RE.fullmatch(value["id"]):
        raise ValidationError("ledger must identify one accepted logical release build")
    if value.get("state") != "accepted":
        raise ValidationError("logical release build is not accepted")
    if value.get("sourceSha") != candidate:
        raise ValidationError("accepted release build is stale for this candidate")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValidationError("accepted release build has no artifact set")
    normalized: list[dict[str, str]] = []
    artifact_hashes: dict[str, set[str | None]] = {}
    paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("sha256"), str):
            raise ValidationError("accepted release artifact is malformed")
        _ref(root, artifact, "accepted release artifact")
        path = artifact["path"]
        if path in paths:
            raise ValidationError("accepted release artifact paths must be unique")
        paths.add(path)
        record = {"path": path, "sha256": artifact["sha256"]}
        if "platform" in artifact:
            if not isinstance(artifact["platform"], str) or not artifact["platform"]:
                raise ValidationError("accepted release artifact platform is malformed")
            record["platform"] = artifact["platform"]
        normalized.append(record)
        artifact_hashes.setdefault(artifact["sha256"], set()).add(artifact.get("platform"))
    normalized.sort(key=lambda item: (item.get("platform", ""), item["path"], item["sha256"]))
    actual_set_sha = sha256(canonical_json(normalized))
    if not isinstance(value.get("artifactSetSha256"), str) or value["artifactSetSha256"] != actual_set_sha:
        raise ValidationError("accepted release artifact-set digest does not match its referenced artifacts")
    return {"id": value["id"], "sourceSha": candidate, "artifactSetSha256": actual_set_sha}, artifact_hashes


def _required_kind(requirement_id: str) -> str | None:
    for prefix, kind in REQUIRED_KIND.items():
        if requirement_id == prefix or requirement_id.startswith(prefix):
            return kind
    return None


def _validate_special(root: pathlib.Path, requirement_id: str, attestation: dict[str, Any], release_artifacts: dict[str, set[str | None]] | None = None) -> None:
    attested_artifacts = attestation.get("artifacts", [])
    if not isinstance(attested_artifacts, list):
        raise ValidationError("attested artifact list is malformed")
    for artifact in attested_artifacts:
        _ref(root, artifact, "attested artifact")
    if requirement_id.startswith("CAMPAIGN-"):
        upstream = attestation.get("upstream")
        scenarios = attestation.get("scenarios")
        if not isinstance(upstream, dict) or not isinstance(upstream.get("canonicalUrl"), str) or not upstream["canonicalUrl"].startswith("https://"):
            raise ValidationError("campaign upstream identity is incomplete")
        if not isinstance(upstream.get("sha"), str) or not SHA_RE.fullmatch(upstream["sha"]):
            raise ValidationError("campaign must pin a full upstream commit SHA")
        if requirement_id == "CAMPAIGN-PETCLINIC":
            exception = attestation.get("tagException")
            if (not isinstance(exception, dict) or exception.get("ownerDecision") != PETCLINIC_EXCEPTION
                    or exception.get("obsoleteTagUsed") is not False or exception.get("tagWasMissing") is not True
                    or exception.get("testedRefKind") != "branch-main-sha"):
                raise ValidationError("Petclinic receipt must record the approved maintained-main tag exception")
        elif not isinstance(upstream.get("stableTag"), str) or not upstream["stableTag"]:
            raise ValidationError("campaign must name its current stable upstream tag")
        if not isinstance(scenarios, list) or len(scenarios) < 5:
            raise ValidationError("campaign requires at least five scenario receipts")
        for scenario in scenarios:
            if not isinstance(scenario, dict) or not isinstance(scenario.get("name"), str) or not scenario["name"].strip():
                raise ValidationError("campaign scenario receipt is malformed")
            for name in ("baseline", "instrumented", "browser", "privacy", "overhead"):
                _ref(root, scenario.get(name), f"campaign {name}")
            fingerprint = scenario.get("semanticEffectFingerprint")
            if not isinstance(fingerprint, str) or not HEX64_RE.fullmatch(fingerprint) or scenario.get("instrumentedSemanticEffectFingerprint") != fingerprint:
                raise ValidationError("baseline and instrumented semantic effect fingerprints differ")
    elif requirement_id == "HUMAN-USABILITY":
        participants = attestation.get("participants")
        if not isinstance(participants, list) or len(participants) < 2:
            raise ValidationError("usability receipt requires participant records")
        if any(not isinstance(item, dict) for item in participants):
            raise ValidationError("usability participant records are malformed")
        identities = [item.get("participantId") for item in participants]
        if any(not isinstance(value, str) or not value.strip() for value in identities) or len(set(identities)) != len(identities):
            raise ValidationError("usability participant IDs must be present and unique")
        for item in participants:
            elapsed = item.get("elapsedSeconds")
            if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0 or elapsed > 600:
                raise ValidationError("usability participant exceeded the ten-minute task bound")
            if not isinstance(item.get("correct"), bool):
                raise ValidationError("each usability observation requires an ID and outcome")
            for name in ("journey", "scoring"):
                _ref(root, item.get(name), f"participant {name}")
        rate = sum(item["correct"] for item in participants) / len(participants)
        if rate < 0.8:
            raise ValidationError("usability participant success rate is below 80 percent")
    elif requirement_id == "HUMAN-OWNER":
        required = {"fresh_install", "linear_canvas_tui", "attach_failure", "partial_capture", "exercise", "exports"}
        journeys = attestation.get("reviewedJourneys")
        if not isinstance(journeys, list) or any(not isinstance(value, str) for value in journeys) or not required.issubset(set(journeys)):
            raise ValidationError("owner review does not cover every required journey")
        if release_artifacts is not None and (attestation.get("releaseBuildId") is None or attestation.get("artifactSetSha256") is None):
            raise ValidationError("owner review must bind the accepted logical release build and artifact set")
    elif requirement_id.startswith("PLATFORM-"):
        platform = attestation.get("platform")
        expected = {"PLATFORM-MAC": ("macOS", "arm64", "macos-arm64"), "PLATFORM-LINUX": ("Linux", "x86_64", "linux-x86_64")}[requirement_id]
        if not isinstance(platform, dict) or (platform.get("os"), platform.get("architecture")) != expected[:2]:
            raise ValidationError("platform receipt does not match its required OS/architecture")
        package_sha = platform.get("packageSha256")
        if not isinstance(package_sha, str) or not HEX64_RE.fullmatch(package_sha):
            raise ValidationError("platform receipt package SHA-256 is malformed")
        platform_artifacts = {a.get("sha256") for a in attested_artifacts}
        if (platform.get("freshProfileInstall") is not True or package_sha not in platform_artifacts
                or (release_artifacts is not None and expected[2] not in release_artifacts.get(package_sha, set()))):
            raise ValidationError("platform receipt must bind fresh-profile acceptance to a package artifact")
    elif requirement_id == "SUPPLY-CHAIN":
        required = {"sbom", "licenses", "notices", "advisories", "checksums", "provenance"}
        artifacts = attestation.get("supplyChainArtifacts")
        if not isinstance(artifacts, dict) or not required.issubset(artifacts):
            raise ValidationError("supply-chain receipt is incomplete")
        for name in required:
            _ref(root, artifacts[name], f"supply-chain {name}")
    elif requirement_id == "REVIEWS-EXACT":
        reviewers = attestation.get("reviewers", [])
        if not isinstance(reviewers, list) or any(not isinstance(item, dict) or not isinstance(item.get("role"), str) for item in reviewers):
            raise ValidationError("exact release reviewer records are malformed")
        roles = {item["role"] for item in reviewers}
        if not {"architecture", "security_privacy", "build_integration"}.issubset(roles):
            raise ValidationError("exact release reviews require architecture, security/privacy, and build/integration reviewers")
    elif requirement_id == "DISTRIBUTED-RECHECK":
        if attestation.get("freshProfile") is not True or attestation.get("javaJourney") is not True or attestation.get("nodeJourney") is not True:
            raise ValidationError("distributed recheck requires fresh-profile Java and Node journeys")


def validate_receipt(
    root: pathlib.Path,
    ref: Any,
    requirement_id: str,
    candidate: str,
    trust: dict[str, dict[str, Any]],
    release_build: dict[str, Any] | None = None,
    release_artifacts: dict[str, set[str | None]] | None = None,
) -> None:
    raw = read_evidence(root, ref.get("path") if isinstance(ref, dict) else None, ref.get("sha256") if isinstance(ref, dict) else None)
    receipt = _load_json(raw, f"{requirement_id} receipt")
    if receipt.get("schemaVersion") != 1 or receipt.get("requirementId") != requirement_id:
        raise ValidationError(f"{requirement_id} receipt identity/schema mismatch")
    if receipt.get("result") != "passed":
        raise ValidationError(f"{requirement_id} receipt is not a passing result")
    if receipt.get("candidateSha") != candidate:
        raise ValidationError(f"{requirement_id} receipt is stale for this candidate")
    build = receipt.get("build")
    if not isinstance(build, dict) or build.get("sourceSha") != candidate or not isinstance(build.get("id"), str) or not BUILD_RE.fullmatch(build["id"]):
        raise ValidationError(f"{requirement_id} receipt is not bound to an exact candidate build")
    if release_build is not None and (build.get("id") != release_build["id"] or build.get("artifactSetSha256") != release_build["artifactSetSha256"]):
        raise ValidationError(f"{requirement_id} receipt is bound to a different logical release build or artifact set")
    artifacts = receipt.get("artifacts")
    evidence = receipt.get("evidence")
    checks = receipt.get("checks")
    if not isinstance(artifacts, list) or not artifacts or not isinstance(evidence, list) or not evidence:
        raise ValidationError(f"{requirement_id} receipt must reference build artifacts and evidence")
    for item in artifacts:
        _ref(root, item, f"{requirement_id} artifact")
        if release_artifacts is not None and item["sha256"] not in release_artifacts:
            raise ValidationError(f"{requirement_id} references an artifact outside the accepted release artifact set")
    if requirement_id.startswith("PLATFORM-") and release_artifacts is not None:
        attestation = receipt.get("attestation")
        if not isinstance(attestation, dict) or not isinstance(attestation.get("platform"), dict):
            raise ValidationError("platform receipt has no typed package identity")
        package_sha = attestation["platform"].get("packageSha256")
        if package_sha not in {item.get("sha256") for item in artifacts if isinstance(item, dict)}:
            raise ValidationError("platform package must be included among the receipt's accepted artifacts")
    for item in evidence:
        _ref(root, item, f"{requirement_id} evidence")
    if not isinstance(checks, list) or not checks:
        raise ValidationError(f"{requirement_id} receipt has no reached assertions")
    for check in checks:
        if not isinstance(check, dict) or check.get("status") != "passed" or check.get("reached") is not True:
            raise ValidationError(f"{requirement_id} contains a failed, skipped, or unreached assertion")
    kind = receipt.get("kind")
    expected_kind = _required_kind(requirement_id)
    if expected_kind and kind != expected_kind:
        raise ValidationError(f"{requirement_id} receipt kind must be {expected_kind}")
    attestation = receipt.get("attestation")
    if not isinstance(attestation, dict):
        raise ValidationError(f"{requirement_id} has no typed attestation")
    _validate_special(root, requirement_id, attestation, release_artifacts)
    if requirement_id == "HUMAN-OWNER" and release_build is not None:
        if attestation.get("releaseBuildId") != release_build["id"] or attestation.get("artifactSetSha256") != release_build["artifactSetSha256"]:
            raise ValidationError("owner review is not bound to the accepted logical release build and artifact set")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ValidationError(f"{requirement_id} has no detached trusted signature")
    signed_receipt = {key: value for key, value in receipt.items() if key != "signatures"}
    signed = canonical_json(signed_receipt)
    verified: list[tuple[str, str]] = []
    for signature in signatures:
        verified.append(_verify_signature(root, trust, signature, signed))
    if len({key for key, _ in verified}) != len(verified):
        raise ValidationError(f"{requirement_id} repeats a signing key")
    roles = {role for _, role in verified}
    if requirement_id.startswith("CAMPAIGN-") and "campaign-runner" not in roles:
        raise ValidationError("campaign receipt lacks a trusted campaign-runner signature")
    if requirement_id == "HUMAN-OWNER" and "release-owner" not in roles:
        raise ValidationError("owner review lacks a trusted release-owner signature")
    if requirement_id == "HUMAN-USABILITY":
        if "usability-scorer" not in roles:
            raise ValidationError("usability results lack a trusted scorer signature")
    if requirement_id == "REVIEWS-EXACT" and not {"architecture-reviewer", "security-reviewer", "build-reviewer"}.issubset(roles):
        raise ValidationError("exact reviews lack separately trusted architecture/security/build signers")
    if requirement_id.startswith("PLATFORM-") and "platform-operator" not in roles:
        raise ValidationError("platform receipt lacks a trusted platform-operator signature")
    if requirement_id == "SUPPLY-CHAIN" and "supply-chain-auditor" not in roles:
        raise ValidationError("supply-chain receipt lacks a trusted auditor signature")
    if requirement_id == "DISTRIBUTED-RECHECK" and "distributed-rechecker" not in roles:
        raise ValidationError("distributed recheck lacks a trusted rechecker signature")


def check(ledger_path: pathlib.Path, evidence_root: pathlib.Path, candidate: str, trust_path: str) -> dict[str, Any]:
    candidate = candidate.lower()
    if not SHA_RE.fullmatch(candidate):
        raise ValidationError("candidate must be a full 40-character commit SHA")
    if evidence_root.is_symlink():
        raise ValidationError("evidence root must not be a symlink")
    evidence_root = evidence_root.resolve(strict=True)
    if not evidence_root.is_dir():
        raise ValidationError("evidence root must be a real directory")
    ledger = _load_json(ledger_path.read_bytes(), "requirement ledger")
    if ledger.get("schemaVersion") != 1 or ledger.get("candidateSha") != candidate:
        raise ValidationError("ledger schema or candidate SHA does not match")
    trust, trust_digest = _trust_config(evidence_root, trust_path)
    contracts = load_pinned_contracts()
    release_build, release_artifacts = validate_release_build(evidence_root, candidate, ledger.get("releaseBuild"))
    requirements = ledger.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValidationError("ledger has no requirements")
    ids: set[str] = set()
    for item in requirements:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in ids:
            raise ValidationError("requirement rows must have unique IDs")
        ids.add(item["id"])
        if item.get("mandatory") is not True:
            raise ValidationError(f"mandatory requirement {item['id']} was downgraded")
        contract = {field: item.get(field) for field in ("id", "requirement", "approvedSlice", "mandatory")}
        if contract != contracts.get(item["id"]):
            raise ValidationError(f"approved requirement text or slice changed for {item['id']}")
    if ids != REQUIRED_IDS:
        missing = sorted(REQUIRED_IDS - ids)
        extra = sorted(ids - REQUIRED_IDS)
        raise ValidationError(f"requirement set differs from the pinned v0.01 set (missing={len(missing)}, extra={len(extra)})")
    ids.clear()
    accepted = 0
    for item in requirements:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in ids:
            raise ValidationError("requirement rows must have unique IDs")
        ids.add(item["id"])
        if item.get("mandatory") is not True:
            raise ValidationError(f"mandatory requirement {item['id']} was downgraded")
        receipts = item.get("receipts")
        if item.get("state") != "accepted" or not isinstance(receipts, list) or not receipts:
            raise ValidationError(f"mandatory requirement {item['id']} is pending, missing, skipped, or incomplete")
        for ref in receipts:
            validate_receipt(evidence_root, ref, item["id"], candidate, trust, release_build, release_artifacts)
        accepted += 1
    return {
        "schemaVersion": 1,
        "candidateSha": candidate,
        "releaseBuildId": release_build["id"],
        "artifactSetSha256": release_build["artifactSetSha256"],
        "mandatoryRequirementsAccepted": accepted,
        "mandatoryRequirementsTotal": sum(item.get("mandatory") is True for item in requirements),
        "approvedRequirementsSha256": PINNED_CONTRACTS_SHA256,
        "decision": "receipts_structurally_valid_for_release_owner_review",
        "trustConfigSha256": trust_digest,
        "substantiveTruthReviewed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, help="requirement ledger JSON")
    parser.add_argument("--evidence-root", required=True, help="the only root for referenced evidence and trust files")
    parser.add_argument("--trust-config", required=True, help="relative path under evidence root to trusted key/role configuration")
    parser.add_argument("--candidate-sha", required=True, help="exact candidate commit SHA")
    args = parser.parse_args()
    try:
        result = check(pathlib.Path(args.ledger), pathlib.Path(args.evidence_root), args.candidate_sha, args.trust_config)
    except (OSError, ValidationError, subprocess.SubprocessError) as exc:
        print(json.dumps({"decision": "not_ready", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
