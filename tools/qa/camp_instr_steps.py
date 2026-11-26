#!/usr/bin/env python3
"""Turn instrumented-run outputs into campaign summary steps (pass | fail | not-implemented | reported).

  camp_instr_steps.py instrumented --file SUMMARY --project P --receipt instrumented-N/receipt.json [--stop-exit-9-is-ni]
  camp_instr_steps.py flows        --file SUMMARY --project P --flows flows-N/flows.json
  camp_instr_steps.py browser      --file SUMMARY --project P --journeys browser/journeys.json
  camp_instr_steps.py tui          --file SUMMARY --project P --tui tui/tui.json
  camp_instr_steps.py overhead     --file SUMMARY --project P --overhead overhead.json

A missing or unreadable input is a failed step, never a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402


def _load(path: str):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return None


FLOW_STEPS = ("record-stop-flow", "restart-reopen", "partial-recording-reopen", "active-line-frames", "frame-values",
              "focused-canary-injection", "focused-redaction-control", "focused-value-control", "standard-no-values")


def flow_steps(f: dict | None) -> list[tuple[str, str, str]]:
    """Steps produced by campaigns/lib/xflows.py (`run.py flows`). A missing document, a missing step or an unknown status
    is a failed step, never a pass and never a quiet skip; a status of not-implemented is accepted only when the flow itself
    saw the product answer exit 9."""
    steps = (f or {}).get("steps") if isinstance(f, dict) else None
    out = []
    for name in FLOW_STEPS:
        v = steps.get(name) if isinstance(steps, dict) else None
        if not isinstance(v, dict) or v.get("status") not in ("pass", "fail", "not-implemented"):
            out.append((name, "fail", "no result from the flows run (document missing, flow did not complete)" if v is None
                        else "the flows run reported an unknown status"))
        else:
            out.append((name, v["status"], str(v.get("note", ""))[:300]))
    accommodation = steps.get("flow-accommodations") if isinstance(steps, dict) else None
    if isinstance(accommodation, dict):
        out.append(("flow-accommodations", "reported", str(accommodation.get("note", ""))))
    scope = steps.get("privacy-scope") if isinstance(steps, dict) else None
    if isinstance(scope, dict):
        out.append(("privacy-scope", "reported", str(scope.get("note", ""))))
    return out


def instrumented_steps(r: dict | None) -> list[tuple[str, str, str]]:
    if r is None:
        return [("instrumented-run", "fail", "no instrumented receipt (the run did not complete)")]
    sc = r.get("scenarios", [])
    out: list[tuple[str, str, str]] = []
    ok_checks = [s["id"] for s in sc if s.get("scenarioChecksPassed")]
    out.append(("instrumented-run", "pass" if sc and len(ok_checks) == len(sc) else "fail",
                f"{len(ok_checks)}/{len(sc)} scenarios passed their own checks under xtrace run"))
    eq = [s["id"] for s in sc if s.get("fingerprintEqualsBaseline") is True]
    none = [s for s in sc if s.get("fingerprintEqualsBaseline") is None]
    if none:
        out.append(("instrumented-fingerprints-equal-baseline", "fail", "no baseline fingerprints to compare"))
    else:
        diff = [s["id"] for s in sc if s.get("fingerprintEqualsBaseline") is False]
        out.append(("instrumented-fingerprints-equal-baseline", "pass" if sc and not diff else "fail",
                    f"{len(eq)}/{len(sc)} equal" + (f"; differ: {','.join(diff)}" if diff else "")))
    api = r.get("api", {})
    if not api.get("ok"):
        out.append(("recordings-per-scenario", "fail", f"read API unavailable: {api.get('reason', '')[:120]}"))
        out.append(("source-identity", "fail", "no recordings read back"))
        out.append(("api-json-artifact", "fail", "no API JSON captured"))
    else:
        v = [s for s in sc if (s.get("recordingVerdict") or {}).get("passed")]
        pc = r.get("problemClasses", {})
        out.append(("recordings-per-scenario", "pass" if sc and len(v) == len(sc) else "fail",
                    f"{len(v)}/{len(sc)} scenarios meet route, HTTP outcome and controller/repository frame expectations "
                    f"({api.get('recordings', 0)} recordings); problems: {json.dumps(pc, sort_keys=True)}"))
        n_src = r.get("recordingsWithSource", 0)
        bad_src = [k for k in ("no-source-file-line", "source-binding-unacceptable", "source-binding-missing") if pc.get(k)]
        out.append(("source-identity", "pass" if n_src > 0 and not bad_src else "fail",
                    (f"{n_src} recordings carry a matched .java file and method-range start line with an accepted source binding "
                     f"(not an executed line)" if n_src > 0 else "no recording frame carried a matched .java file and start line")
                    + (f"; problems: {','.join(bad_src)}" if bad_src else "")))
        n_rec = api.get("recordings", 0)
        out.append(("api-json-artifact", "pass" if n_rec > 0 else "fail",
                    f"{n_rec} recordings saved as API JSON" if n_rec > 0 else "the read API returned 0 recordings, nothing to save"))
    # record-stop-flow, restart-reopen, partial-recording-reopen, active-line-frames and frame-values come from `flows` below
    out.append(("launcher-exit-after-sigterm", "pass" if r.get("notes", {}).get("launcherExitCode") in (0, 143, -15) else "fail",
                f"xtrace run exited {r.get('notes', {}).get('launcherExitCode')} after SIGTERM to the launcher pid"))
    accommodations = r.get("notes", {}).get("accommodations")
    if accommodations:
        out.append(("unpaced-load-not-exercised", "reported",
                    f"pace_seconds={accommodations.get('pace_seconds')}; drain_seconds={accommodations.get('drain_seconds')}; "
                    + str(accommodations.get("reason", ""))))
    return out


BROWSER_WIDTHS = (320, 736, 1024, 1280, 1440)
BROWSER_PHASES = ("list", "recordings", "linear", "canvas", "returnToSteps")


def _browser_screenshot(path: pathlib.Path, width: int, digest: object) -> bool:
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    try:
        image = path.read_bytes()
    except OSError:
        return False
    return (len(image) > 45 and image.startswith(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR")
            and width <= int.from_bytes(image[16:20], "big") <= width + 1
            and int.from_bytes(image[20:24], "big") > 0
            and image.endswith(b"\0\0\0\0IEND\xaeB`\x82")
            and hashlib.sha256(image).hexdigest() == digest)


def browser_steps(j: dict | None, widths: tuple[int, ...] = BROWSER_WIDTHS, *,
                  frame_dir: pathlib.Path | None = None, source_sha: str = "",
                  package_sha256: str = "", require_current: bool = False) -> list[tuple[str, str, str]]:
    def results(linear: str, canvas: str, note: str):
        return [("browser-journeys-linear", linear, note), ("browser-journeys-canvas", canvas, note)]

    if not isinstance(j, dict):
        return results("fail", "fail", "browser report missing or unreadable")
    rows = j.get("widths")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or type(row.get("width")) is not int
                                        or not 0 < row["width"] <= 2**53 - 1 for row in rows):
        return results("fail", "fail", "invalid viewport rows")
    observed = [row["width"] for row in rows]
    width_note = f"observed widths {','.join(map(str, observed)) or 'none'}"
    if j.get("schemaVersion") == 1 and j.get("kind") == "browser_journeys":
        note = f"legacy evidence without selection proof; {width_note}"
        if require_current:
            return results("fail", "fail", note)
        if not rows or len(set(observed)) != len(observed) or j.get("overflowAt") != []:
            return results("fail", "fail", note)
        legacy = []
        for mode in ("linear", "canvas"):
            declared = j.get(mode)
            earned = declared == "pass" or (mode == "canvas" and declared == "not-implemented")
            for row in rows:
                steps = row.get("steps")
                if (not isinstance(steps, dict) or "error" in steps
                        or row.get("horizontalOverflow") is not False
                        or type(row.get("pageErrors")) is not int or row["pageErrors"] != 0):
                    earned = False
                    break
                listing = steps.get("list")
                result = steps.get(mode)
                if (not isinstance(listing, dict) or listing.get("status") != "pass"
                        or not isinstance(result, dict) or result.get("status") != declared):
                    earned = False
                    break
            legacy.append("reported" if earned and declared == "pass" else "not-implemented" if earned else "fail")
        return results(*legacy, note)
    if j.get("schemaVersion") != 2 or j.get("kind") != "browser_journeys":
        return results("fail", "fail", "unsupported browser report schema")
    if len(set(observed)) != len(observed) or set(observed) != set(widths):
        return results("fail", "fail", f"incomplete, duplicate or unexpected viewports; {width_note}")
    if (not source_sha or j.get("sourceSha") != source_sha
            or not package_sha256 or j.get("packageSha256") != package_sha256):
        return results("fail", "fail", "browser package provenance missing or mismatched")

    raw_statuses = {"linear": [], "canvas": []}
    failures = {"linear": [], "canvas": []}
    overflow_at = []
    notes = []
    for row in rows:
        w = row["width"]
        issues = []
        steps = row.get("steps")
        if not isinstance(steps, dict):
            steps = {}
        for mode, statuses in raw_statuses.items():
            entry = steps.get(mode)
            statuses.append(entry.get("status") if isinstance(entry, dict) else None)

        shared_failure = type(row.get("pageErrors")) is not int or row["pageErrors"] != 0 or "cleanup" in steps
        if shared_failure:
            issues.append("page errors or cleanup failure")
        linear_failed = shared_failure
        canvas_failed = shared_failure
        map_unavailable = steps.get("canvas") == {"status": "not-implemented"}
        if map_unavailable:
            issues.append("Map unavailable")

        row_overflow = False
        for phase in BROWSER_PHASES:
            if map_unavailable and phase == "canvas":
                continue
            if map_unavailable and phase == "returnToSteps" and phase not in steps:
                continue
            step = steps.get(phase)
            overflow = isinstance(step, dict) and step.get("horizontalOverflow") is True
            row_overflow |= overflow
            if overflow:
                issues.append(f"{phase} overflow")
                earned = False
            elif not isinstance(step, dict) or step.get("status") != "pass" or step.get("horizontalOverflow") is not False:
                issues.append(f"{phase} not passed")
                earned = False
            else:
                screenshot = f"{phase}-{w}.png"
                earned = (frame_dir is not None and step.get("screenshot") == screenshot
                          and _browser_screenshot(frame_dir / screenshot, w, step.get("screenshotSha256")))
                if not earned:
                    issues.append(f"{phase} screenshot missing or invalid")
            if not earned:
                canvas_failed = True
                if phase in ("list", "recordings", "linear"):
                    linear_failed = True
        if row_overflow:
            overflow_at.append(w)
            linear_failed = True
        if not map_unavailable and row.get("selectionContinuous") is not True:
            issues.append("selection continuity unavailable")
            canvas_failed = True
        failures["linear"].append(linear_failed)
        failures["canvas"].append(canvas_failed)
        if issues:
            notes.append(f"{w}: {', '.join(issues)}")

    if j.get("browserCloseFailed", False) is not False:
        return results("fail", "fail", f"{width_note}; browser cleanup failed")
    declared_overflow = j.get("overflowAt")
    if (not isinstance(declared_overflow, list) or any(type(w) is not int for w in declared_overflow)
            or declared_overflow != overflow_at):
        return results("fail", "fail", f"{width_note}; inconsistent overflow aggregate")
    rollups = {}
    for mode, statuses in raw_statuses.items():
        aggregate = ("pass" if all(v == "pass" for v in statuses) else
                     "not-implemented" if all(v == "not-implemented" for v in statuses) else "fail")
        if j.get(mode) != aggregate:
            notes.append(f"inconsistent {mode} aggregate")
            rollups[mode] = "fail"
        elif any(failures[mode]) or (mode == "linear" and aggregate != "pass"):
            rollups[mode] = "fail"
        else:
            rollups[mode] = aggregate
    note = "; ".join([width_note, *notes])
    return results(rollups["linear"], rollups["canvas"], note)


def tui_steps(t: dict | None) -> list[tuple[str, str, str]]:
    if t is None:
        return [("tui-pty-transcript", "fail", "no tui.json")]
    v = t.get("verdict")
    out = [("tui-pty-transcript", v if v in ("pass", "not-implemented") else "fail", str(t.get("reason", ""))[:160])]
    observed = t.get("observations", {})
    if observed.get("accommodation"):
        out.append(("tui-navigation-accommodation", "reported",
                    f"open_after={observed.get('open_after')}; listObserved={observed.get('listObserved')}; "
                    + str(observed["accommodation"])))
    return out


def overhead_steps(o: dict | None) -> list[tuple[str, str, str]]:
    if o is None:
        return [("overhead-measurement", "fail", "no overhead.json"), ("overhead-repeats-ge-5", "fail", "no overhead.json")]
    a = o.get("aggregate", {})
    reps = o.get("repeats", 0)
    eligible = (type(reps) is int and reps >= 5 and o.get("interleaved") is True
                and o.get("eligibleForClaim") is True and not o.get("errors")
                and len(o.get("runs", [])) == 2 * reps)
    previous_end = 0
    for index, run in enumerate(o.get("runs", [])):
        start, end = run.get("startedNs"), run.get("finishedNs")
        ordered = type(start) is int and type(end) is int and previous_end <= start < end
        eligible = (eligible and ordered
                    and run.get("mode") == ("baseline" if index % 2 == 0 else "instrumented")
                    and run.get("repeat") == index // 2 and run.get("exitCode") == 0
                    and len(run.get("canonicalReceiptSha256", "")) == 64)
        if ordered:
            previous_end = end
    if not eligible or not a.get("baseline", {}).get("n") or not a.get("instrumented", {}).get("n"):
        return [("overhead-measurement", "fail", "no qualified overhead number: five successful interleaved workload pairs required"),
                ("overhead-repeats-ge-5", "fail", f"{reps} pairs reported; ordered run evidence is missing, insufficient or failed")]
    return [("overhead-measurement", "reported",
             f"p50 {a['baseline']['p50Ms']}->{a['instrumented']['p50Ms']}ms (x{a['p50Ratio']}), "
             f"p95 {a['baseline']['p95Ms']}->{a['instrumented']['p95Ms']}ms (x{a['p95Ratio']}); "
             "warm-up, canaries and launcher included; paced serial load, capture drops may affect measurements; no budget"),
            ("overhead-repeats-ge-5", "pass", f"{reps} successful interleaved baseline/instrumented pairs with observed run intervals")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["instrumented", "flows", "browser", "tui", "overhead"])
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", required=True)
    for n in ("receipt", "journeys", "tui", "overhead", "flows"):
        ap.add_argument(f"--{n}", default="")
    ap.add_argument("--widths", default=",".join(map(str, BROWSER_WIDTHS)))
    ap.add_argument("--source-sha", default="")
    ap.add_argument("--package-sha256", default="")
    a = ap.parse_args()
    if a.kind == "browser":
        declared = a.widths.split(",")
        if any(not re.fullmatch(r"[1-9][0-9]{0,15}", w) for w in declared):
            ap.error("invalid browser widths")
        widths = tuple(map(int, declared))
        if len(set(widths)) != len(widths) or any(w > 2**53 - 1 for w in widths):
            ap.error("invalid browser widths")
        if ((a.source_sha and not re.fullmatch(r"[0-9a-f]{40}", a.source_sha))
                or (a.package_sha256 and not re.fullmatch(r"[0-9a-f]{64}", a.package_sha256))):
            ap.error("invalid browser package provenance")
        journey = pathlib.Path(a.journeys)
        steps = browser_steps(_load(a.journeys), widths, frame_dir=journey.parent,
                              source_sha=a.source_sha, package_sha256=a.package_sha256, require_current=True)
    else:
        src = {"instrumented": (a.receipt, instrumented_steps), "flows": (a.flows, flow_steps),
               "tui": (a.tui, tui_steps), "overhead": (a.overhead, overhead_steps)}[a.kind]
        steps = src[1](_load(src[0]))
    for step, status, note in steps:
        cs.record(pathlib.Path(a.file), a.project, step, status, note)
        print(f"campaign step {step}: {status} ({note})")
    if a.kind == "browser" and any(status != "pass" for _, status, _ in steps):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
