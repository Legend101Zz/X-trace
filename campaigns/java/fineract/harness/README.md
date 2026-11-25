# Fineract installed development campaign

Refs #117, #8 and #5. Use a clean checkout of the exact product source in a
hosted Linux x86_64 job. A matching HEAD alone is insufficient: staged,
modified, deleted or untracked product files refuse source qualification.
Build the exact unsigned development archive separately, and retain its digest.
No workflow or network dispatch is provided by this harness.

The private parent must already be owner-only with safe ancestors; the run and
public output directories must not exist. The outer driver streams must close
before final privacy projection:

```sh
umask 077
mkdir -m 700 "$PRIVATE_PARENT/driver"
rc=0
python3 -B campaigns/java/fineract/harness/installed.py \
  --private-root "$PRIVATE_PARENT/run" \
  --archive "$PACKAGE_ARCHIVE" --package-sha256 "$PACKAGE_SHA256" \
  --source-sha "$PRODUCT_SHA" --java "$JAVA_HOME/bin/java" \
  > "$PRIVATE_PARENT/driver/stdout" 2> "$PRIVATE_PARENT/driver/stderr" || rc=$?
python3 -B - "$rc" "$PRIVATE_PARENT/driver/status.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[2]).write_text(json.dumps({
    "schema": "xtrace-fineract-driver/1", "exitCode": int(sys.argv[1])}) + "\n")
PY
python3 -B campaigns/java/fineract/harness/privacy.py \
  --private-root "$PRIVATE_PARENT/run" --public-out "$PRIVATE_PARENT/public"
```

The driver does not resume, retry or replace a failed attempt. It verifies the
archive's bytes and source/platform identity before running package binaries,
installs to a fresh prefix, verifies upstream source and license files, builds
the pinned application, then runs the original baseline and instrumented
workloads. Both phases use the same host boot, exact Java executable and release
file, built JAR, database image and archive. Each resets PostgreSQL and creates
both databases through the existing `xcamp.Stack` procedure. Instrumentation
also compares every installed payload file against the verified archive and
invokes the installed verifier. Product checkout cleanliness is checked again
before subprocess commands, host pin binding and final source projection.

The eight original scenario functions, assertions, SQL effects, normalization
and execution order remain unchanged. `xinstr` keeps serial, concurrent and
cleanup phases in that order, with observed recording boundaries. Missing
boundaries leave evidence unattributed while the workload still progresses.
Workload success, same-host semantic equality, historical comparison and
recording evidence remain separate. A later failure never repairs an earlier
phase exit or privacy failure. Separate denied canary requests exercise the
Authorization, Cookie, query and JSON-body surfaces. Two additional authenticated
requests follow the final workload boundary: an office-list GET carries Cookie
and query canaries, and a client-validation POST carries the password canary in
a body without client names. They must return 200 and 400 respectively and each
have exactly one complete, status-matching Servlet/Jersey/resource recording in
the post-workload window. The POST must not create a client. Denied probes stay
separate and must still pass their own exact attribution and denial checks; a
response alone cannot clear them. Duplicate or unverified recording attribution
remains red. These probes do not modify any original workload request, check,
fingerprint or the eight-scenario order. The healthy instrumented child receives
the environment canary.

The invalid Authorization canary cannot also serve as the valid seeded demo
credential: its coverage is `denied-only`. Environment delivery establishes the
healthy child received the variable, without proving a value entered a recording.
The body/cookie/query probes exercise authenticated processing at standard
capture depth; they do not establish focused argument/local/return capture.
`privacy.scopeComplete` remains false with fixed named gaps for valid-authorization
recording, environment recording and focused capture. A bounded sink/probe scan
can pass while those broader qualification gaps remain visible and unaccepted.

## Private sinks and bounded output

The root admission marker binds the run directory and private parent to their
actual device/inode identities. Each completed phase writes a private inventory
and scan snapshot. Finalization rescans actual storage, API pages, all three
ordered boundary snapshots, the entire capture directory including its actual
`receipt.json`, the entire baseline output including its receipt, the source
repository `.xtrace` pointer directory, application/viewer/launcher output,
retained child stderr, CLI pages and status, the saved-API ZIP, phase and package
verification metadata, installer receipt, home output, prior privacy reports,
and the entire closed outer driver directory including admission and exit status.
Unexpected outputs under the run root, sinks, project output, instrumented output
and installer prefix/bin are scanned by default. Discovery validates private
ancestors before enumeration. Existing outputs are scanned even when their
declared phase was unreached; a failed phase's partial output cannot disappear
from privacy evidence. A missing required output remains a gap. Inventories
bound files and bytes, reject links/special entries or unsafe ownership/modes,
and compare names, identities, sizes, timestamps and SHA-256 before/after scans.
The existing canary scanner checks bytes, names, common encodings and supported
compressed containers to depth two. Missing, empty, unreached, changing or
unscannable sinks are named gaps. Successful child calls need not produce
retained failure stderr; missing/unavailable/oversized failure capture remains a
gap. Optional home/extra-output/privacy-report classes can be `not-produced`
only when genuinely empty; produced but empty files remain gaps. Large Gradle
home output can exceed the unchanged inventory bounds, which remains a named
failure requiring a future narrower, independently justified inventory.

Excluded private inputs are explicit: `canaries.json` and in-memory original
probe requests intentionally contain test values; package/archive and extracted
or installed version payload trees are package inputs checked by the existing
archive/payload verifier; the pinned upstream source, Git metadata and its build
inputs/outputs are application inputs to this runtime campaign. The source's
`.xtrace` directory and installer's generated receipt are scanned separately.
This is not a claim that arbitrary runtime writes into otherwise excluded source
or version payload files have been inventoried. All excluded bytes stay private;
no exclusion satisfies the missing broader release privacy qualification.

Finalization validates required canary generation, exact expected delivery status,
all denied/authenticated probe verdicts and single-record attribution, API/CLI
collection completeness, every attempted phase inventory and previous scan
failures. A missing API continuation field is not clean collection. Only fixed
scenario/class names, enums, booleans and bounded counts enter `public/summary.json`.
The exact final output bytes are canary-scanned before writing; a failed or
unavailable final scan yields only an empty object. Publication means this
bounded projection was scanned; campaign, privacy and release verdicts are
separate. Nothing is uploaded by either command. All other files remain private.

## Evidence boundary

This code has not been run through the real installed Fineract product. Source
expectations follow `campaign.json`; they do not prove the application executed
them. The receipt names missing Servlet/Jersey invocation and resource identity,
source, command/client-service, exception/mapper, JDBC and concurrent-group
observations separately. Required SQL verb/table policy is unchanged: an
observed JDBC `execute` or `executeBatch` method is never substituted for an SQL
verb. No shared schema or adapter changes occur. Individual concurrent
request-to-recording isolation remains unobserved even when route group counts
match; there is no synthetic isolation credit.

The pinned Fineract 1.15.0 source, historical baseline JAR identity and Linux
arm64 baseline remain the development reference. This is not a claim that 1.15.0
is the current upstream release. The new host is Linux x86_64. Exact JDK, JAR and
database identities are observed again; Jersey server/common, Tomcat, Spring
Boot and pgjdbc versions and bytes are checked inside the actual built boot JAR.
Historical and same-host fingerprints remain separate, and a historical mismatch
stays red. The previous failing campaign row and failed upstream-build evidence
are not superseded by this harness or the historical baseline passes.

Browser, TUI, restart, real export, overhead, focused capture privacy, release
privacy and signed-ledger qualification remain required. The private ZIP is
saved API JSON, not an export bundle. No release row is accepted by this work.
Regression tests run on GitHub; local verification compiles Python source only.
