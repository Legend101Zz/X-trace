#!/usr/bin/env python3
"""Turn instrumented-run outputs into campaign summary steps (pass | fail | not-implemented | reported).

  camp_instr_steps.py instrumented --file SUMMARY --project P --receipt instrumented-N/receipt.json [--stop-exit-9-is-ni]
  camp_instr_steps.py browser      --file SUMMARY --project P --journeys browser/journeys.json
  camp_instr_steps.py tui          --file SUMMARY --project P --tui tui/tui.json
  camp_instr_steps.py overhead     --file SUMMARY --project P --overhead overhead.json

A missing or unreadable input is a failed step, never a pass.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402


def _load(path: str):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return None


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
        out.append(("source-identity", "pass" if n_src > 0 and not pc.get("no-source-file-line") else "fail",
                    f"{n_src} recordings carry a matched .java file and line" if n_src > 0 else "no recording frame carried a matched .java file and line"))
        n_rec = api.get("recordings", 0)
        out.append(("api-json-artifact", "pass" if n_rec > 0 else "fail",
                    f"{n_rec} recordings saved as API JSON" if n_rec > 0 else "the read API returned 0 recordings, nothing to save"))
    stop = r.get("notes", {}).get("stopCommand", {})
    # `xtrace run` owns its daemon for the life of the JVM, so `xtrace stop` (which ends a `xtrace record` daemon) has nothing
    # to stop after it. Until the harness launches the app with `xtrace record`, then `xtrace stop`, the record+stop flow was
    # never exercised: that is not-implemented (it gates), never a pass and never a quiet `reported`.
    out.append(("record-stop-flow", "not-implemented",
                f"harness runs `xtrace run` only; record, launch and `xtrace stop` is not exercised "
                f"(`xtrace stop` after run exited {stop.get('exitCode')})"))
    out.append(("launcher-exit-after-sigterm", "pass" if r.get("notes", {}).get("launcherExitCode") in (0, 143, -15) else "fail",
                f"xtrace run exited {r.get('notes', {}).get('launcherExitCode')} after SIGTERM to the launcher pid"))
    return out


def browser_steps(j: dict | None) -> list[tuple[str, str, str]]:
    if j is None:
        return [("browser-journeys-linear", "fail", "no journeys.json (browser run did not finish)"),
                ("browser-journeys-canvas", "fail", "no journeys.json")]
    widths = ",".join(str(w["width"]) for w in j.get("widths", []))
    lin = j.get("linear")
    note = f"widths {widths}; overflow at [{','.join(map(str, j.get('overflowAt', [])))}]"
    out = [("browser-journeys-linear", "pass" if lin == "pass" and not j.get("overflowAt") else "fail", note)]
    can = j.get("canvas")
    out.append(("browser-journeys-canvas", {"pass": "pass", "not-implemented": "not-implemented"}.get(can, "fail"), note))
    return out


def tui_steps(t: dict | None) -> list[tuple[str, str, str]]:
    if t is None:
        return [("tui-pty-transcript", "fail", "no tui.json")]
    v = t.get("verdict")
    return [("tui-pty-transcript", v if v in ("pass", "not-implemented") else "fail", str(t.get("reason", ""))[:160])]


def overhead_steps(o: dict | None) -> list[tuple[str, str, str]]:
    if o is None:
        return [("overhead-measurement", "fail", "no overhead.json")]
    a = o["aggregate"]
    return [("overhead-measurement", "reported",
             f"p50 {a['baseline']['p50Ms']}->{a['instrumented']['p50Ms']}ms (x{a['p50Ratio']}), "
             f"p95 {a['baseline']['p95Ms']}->{a['instrumented']['p95Ms']}ms (x{a['p95Ratio']}); not gated")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["instrumented", "browser", "tui", "overhead"])
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", required=True)
    for n in ("receipt", "journeys", "tui", "overhead"):
        ap.add_argument(f"--{n}", default="")
    a = ap.parse_args()
    src = {"instrumented": (a.receipt, instrumented_steps), "browser": (a.journeys, browser_steps),
           "tui": (a.tui, tui_steps), "overhead": (a.overhead, overhead_steps)}[a.kind]
    for step, status, note in src[1](_load(src[0])):
        cs.record(pathlib.Path(a.file), a.project, step, status, note)
        print(f"campaign step {step}: {status} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
