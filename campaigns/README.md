# External campaigns (v0.01 preparation)

Tracked definitions and harnesses for the real-project campaigns. PREPARATION ONLY: they
build upstream projects at a pinned SHA in ephemeral Docker containers and record an
UNINSTRUMENTED baseline. They are not acceptance evidence and never count as a campaign receipt.

- `lib/xcamp.py` - stdlib-only runner (Docker lifecycle, HTTP recording, normalization, fingerprints, compare).
- `java/<project>/campaign.json` - pin, license, runtime, DB image digest, ports, reset procedure, scenarios.
- `java/<project>/harness/run.py` - `build | baseline | compare`.
- `java/INSTRUMENTED-RUN.md` - how the later packaged-xtrace run is done and what the receipt needs.

Private (untracked) layout under `$XTRACE_CAMPAIGN_ROOT`: `java/<project>/src` (pinned upstream
checkout; tracked files must stay clean), `java/<project>/work` (build logs), `java/<project>/baseline-<n>`
(`receipt.json`, `application.log`).

Rules enforced by the code: every Docker object is prefixed `xtrace-camp-` and the runner refuses to
touch anything else; databases are disposable (tmpfs) and recreated every run; synthetic data only;
no upstream source changes (config-only adaptations are listed in each `campaign.json`).

semanticEffectFingerprint = sha256 of canonical JSON of {scenario id, kind, per-request label/status/
selected headers/normalized-body sha256, check outcomes, database effect rows}. Volatile values
(timestamps, jsessionid, host:port, JWTs, UUIDs, generated ids in concurrency scenarios) are normalized.
