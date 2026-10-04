# v0.01 release gate tools

`run_gates.py` runs the fixed Rust, Java, Node, web, restricted-PATH and pinned
phase-diff gates. It accepts a checkout, a full immutable base commit SHA, a
safe run label, and a cache root explicitly:

Before creating cache directories, logs, leases, or receipts, the runner admits
the configured cache root and every existing named cache location. It follows
no symlinks, requires owner-controlled non-group/other-writable directories,
and rejects filesystems or ACL states it cannot prove suitable for private
local storage. On macOS it requires APFS with global permissions enabled; on
Linux it accepts only the explicitly checked local filesystem set and rejects
POSIX ACLs. Initial admission completes before the runner's first cache write;
later admission failures stop subsequent writes without repairing or relocating
the selected cache.
The per-run restricted Cargo target must be new and empty before its build.
Choose an owner-controlled cache location on a supported filesystem whose
immediate parent already exists; the runner does not move cache data or change
host ACLs.

```text
python3 tools/release/run_gates.py \
  --repo /path/to/X-trace \
  --base 0123456789abcdef0123456789abcdef01234567 \
  --label P01-candidate-a \
  --cache-root /path/to/task-cache
```

The runner records the starting and ending `HEAD`, pinned base, working-tree
and phase-diff digests, selected tool versions, argv, command exit codes and
durations. It stops at the first nonzero gate and never emits a passing summary
for a failed or unreached gate. Full command output stays in the configurable
cache under `release-gates/<label>/logs/`; `receipt.json` contains hashes and
relative log names, with no checkout/cache paths or inherited environment dump.
The web workspace dependencies and pinned Playwright Chromium are installed
before the real Java/Spring CLI journey and remaining Rust tests. The restricted
build uses a new per-label Cargo target directory and checks that `protoc` is
absent from its restricted `PATH` before building. Separate atomic Cargo and
Gradle leases serialize release-gate runs that share the cache root; an owned
lease is an error and is never broken automatically. An explicitly nested run
may reuse a lease only by supplying its exact 32-hex lease token. The tool only runs checks.
It does not accept a phase, merge, push, tag, or publish.

Each gate runs in a fresh POSIX session. The runner tracks descendant PIDs with
their process start identity, including descendants that create a new session
or process group. Timeout or interrupt sends TERM, then KILL if needed, and
confirms every owned process is gone before releasing either builder lease. A
process tree that cannot be confirmed drained leaves both leases in place with
`requiresManualRecovery`, `processGroupId`, the tracked PID/start-identity list
in `ownedProcesses`, and a reason in each `owner.json`.
Do not remove those lease directories by age or retry automatically: inspect the
recorded process and descendants, confirm none can write to either builder
cache, then have the operator remove both lease directories manually. The
runner never breaks a retained lease itself. Source
HEAD, worktree, and pinned phase-diff identity are checked immediately before
and after every gate as well as at the full-run boundary.

After every completed command, the runner compares the process table with its
pre-launch snapshot. A new, untracked live process is treated as an unconfirmed
descendant when it still holds that command's private raw-log file open (the
usual inherited stdout case). The inspection is batched on macOS, capped at 512
candidate processes and two seconds; exhausting either limit or being unable
to inspect descriptors retains the leases with a reason. If the host cannot
inspect open descriptors, a new process is ambiguous and also retains the
leases. Such candidates are recorded separately as `unconfirmedProcesses`; the
runner never signals them. This catches a detached child that outlives its
parent without treating unrelated concurrent processes as owned. A child that
deliberately closes or redirects stdout can evade this marker, so process-table
polling is not a universal containment boundary; the runner remains intended
for a frozen checkout with an operator overseeing retained leases.

Version probes use that same process-tree control and private per-tool raw logs;
a timeout or uncertain descendant is a failed run, never an `unavailable`
version. The local Buf and Playwright executables are probed after their
respective workspace installs, so the receipt records the actual pinned
workspace tools.

`check_ledger.py` reads the ledger path supplied by the caller and resolves
every referenced receipt, artifact, log, key and signature only beneath the
explicit evidence root. Receipt paths must be relative, symlink-free, and
SHA-256 matched. Every mandatory ledger row must already be `accepted`, with
passing reached checks tied to the exact candidate SHA and a build ID. Failed,
skipped, unreached, missing, stale, or hash-mismatched evidence fails closed.

Detached signatures are verified with OpenSSL against a caller-supplied
trust configuration stored beneath that evidence root. The trust configuration
contains key IDs, role names, relative public-key paths and public-key hashes.
The operator/release owner must independently authenticate and approve that
trust configuration; the checker does not create signing authority. The tool
pins the canonical `id`, `requirement`, `approvedSlice`, and `mandatory` fields
for every approved row with a tracked contract digest, so deleting a row,
changing its wording/slice, or changing it to optional cannot make the ledger
pass. Trusted signer IDs must resolve to distinct normalized public-key
material, preventing one key from filling multiple reviewer roles. This checks
key distinctness only: the owner must authenticate the mapping and verify that
reviewers were independent actors; signatures do not prove human identity or
independent review. Signed
campaign, platform, supply-chain, review, owner and human-study receipt types
have additional required fields. For usability, each observed participant
record carries an individual outcome and time plus hashed journey/scoring
evidence; the aggregate scorer signs the complete receipt. Individual
participant signatures are optional. Owner journeys and campaign scenarios
reference hashed evidence. Each detached signature covers the complete receipt
except its `signatures` array, binding candidate, build, result, checks, artifact
hashes, and attestation together. The checker validates
these bytes and structures but cannot establish from JSON that a signer is the
claimed person, that a test was honestly run, or that a product-quality claim is
true. Those judgments remain explicit release-owner review work. A successful
checker result means only that the supplied receipts are structurally valid,
hash-consistent, candidate-bound, and signed by keys in the supplied trust
configuration; its output always says `substantiveTruthReviewed: false`. It is
not permission to publish.

Receipt references use this shape:

```json
{"path":"receipts/P01-JAVA-LAUNCH.json","sha256":"<64 lowercase hex characters>"}
```

The ledger has one accepted `releaseBuild` with a logical build ID, candidate
source SHA, and an `artifacts` set of hashed files (platform packages use the
declared `macos-arm64` and `linux-x86_64` platform labels). Its canonical
`artifactSetSha256` binds that set. Every receipt must
name the same build ID, source SHA, and artifact-set digest; all receipt
artifacts must be members of that accepted set. The owner-review receipt also
signs the logical build and artifact-set identity. This prevents joining
independently rebuilt receipts or unreviewed package hashes into one candidate.

Each receipt has `schemaVersion`, `requirementId`, `kind`, `result`,
`candidateSha`, `build: {id, sourceSha, artifactSetSha256}`, non-empty
`artifacts`, `evidence`, and `checks` arrays. Each check must say
`status: "passed"` and `reached: true`.
For the supply-chain receipt, `attestation.artifacts` remains the ordinary list
of release artifacts; its separate `attestation.supplyChainArtifacts` object
maps `sbom`, `licenses`, `notices`, `advisories`, `checksums`, and `provenance`
to hashed evidence references.
The canonical receipt excluding `signatures` is the signed payload. Signature
entries identify a trusted `keyId`, authorized `role`, relative signature
`path`, and SHA-256. The Petclinic exception records the user's explicit choice
to test a pinned maintained `main` SHA because no current stable tag exists; it
also records that obsolete `1.5.x` was not used.

Run the stdlib-only tooling tests with an explicit existing scratch directory
that has already passed the private-cache admission policy. The runner supplies
its admitted `cache/tmp` as `XTRACE_TEST_SCRATCH_ROOT` to child test commands;
direct test invocations must set that variable themselves. The tests do not
fall back to writing beneath the user's home directory.

```text
XTRACE_TEST_SCRATCH_ROOT=/absolute/path/to/admitted/test-scratch PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.release.test_release_tools
```

## Leased runner for builds and tests

`tools/release/leased_run.py` runs one Cargo, Gradle or npm command under both
real builder leases in the private cache root, with the same task-scoped
environment and process-tree supervision as the 23-gate floor:

```
python3.14 -B -m tools.release.leased_run --repo <worktree> --label <new unique label> \
    --cache-root <private root> --timeout <seconds> [--wait <seconds>] \
    [--jdk-home <path>] [--expect-unittest <N>] -- <argv...>
```

- The label must be new. Both leases are acquired with a fresh random token that
  is never printed. A held lease is never borrowed or broken: the runner polls
  every 15 s for at most `--wait` seconds, then exits with code 75.
- Uncommitted edits are allowed; HEAD and working-tree digests are recorded in
  `release-gates/<label>/receipt.json` (no tokens, paths or environment).
- Exit codes: 0 passed, 1 command or expectation failed, 2 invalid input,
  admission failure or a label already used (also when it was taken while
  waiting; the other run's files are never overwritten), 3 uncertain process
  tree (leases retained for manual recovery, also if finalization then fails) or
  lease release failure, 4 the receipt could not be written, 75 a live owner held
  a lease for the whole `--wait`, 76 a lease is retained for manual recovery
  (reported at once; waiting cannot help).
- Only these commands run: cargo, gradlew, npm, npx, node, git, java, and python3/python3.14 as
  `-B -m unittest` or `-B -m tools.release.*`; anything else (shells, open, launchctl, osascript,
  docker, systemd-run, at) is refused with exit code 77 before any lease is taken. This is hygiene,
  not a launcher barrier: npx/node/java/git/python can run anything. The residual is recorded in each
  receipt (`provenanceResidual`) and in ADR 0007.
- HOME is a private directory inside the run's scratch (`~/.npmrc`, `~/.netrc`, `~/.ssh` are not
  reachable); `--pass-env HOME` passes the host HOME explicitly and is recorded as
  `hostHomePassed`. Export `RUSTUP_HOME` when rustup toolchains live outside the host HOME.
  `--pass-env` refuses code-loading and redirecting names (LD_*, DYLD_*, NODE_OPTIONS, PYTHONPATH,
  JAVA_TOOL_OPTIONS, BASH_ENV, RUSTC_WRAPPER, RUSTFLAGS, CARGO_*, GIT_*, *_PROXY, ...).
- The command sees an allowlisted parent environment (PATH, HOME, locale and
  toolchain locators) plus the task variables; add non-secret names with
  `--pass-env NAME`. Per-run scratch is removed only after a passing run and a
  successful lease release. The raw log is capped at 64 MiB while the command
  runs; on overflow only the run's own process tree is stopped (exit 1, reason
  `log-exceeded-bound`).
- `--expect-unittest N` passes only on exit 0, `Ran N tests`, a plain `OK` and
  no skip or expected-failure marker.
- One JSON summary line is printed: label, decision, exit code, duration, log
  SHA-256 and lease cleanup.

## Process provenance classification

An uninspectable process (other-user or kernel; its descriptors cannot be read
unprivileged) that is positively not a descendant of the run no longer blocks
quiescence. macOS compares resource coalition ids (`proc_pidinfo`); Linux makes
the runner a child subreaper for the command and requires a process that was never
in the descendant set, whose parent chain does not reach the runner. Unreadable,
equal, inconsistent or unavailable facts leave the process uncertain (fail
closed). Evidence (pid, start time, same/other user class, coalition ids) is
recorded in the receipt under `provenance` (`leased_run`) or per gate/probe
(`run_gates`, disable with `--no-provenance`). It proves non-descent in the fork
tree only; see `docs/decisions/0007-process-provenance-classification-for-builder-quiescence.md`
for the residual delegated-work routes.

## Manual recovery of retained leases

`tools/release/recover_leases.py` implements the bounded manual-recovery protocol for the two builder
leases a failed run retains. It uses only `private_roots`, `run_gates` and `provenance`, sends no
signal, uses no privilege and applies no UID or name exemption. Default is a dry run that writes a
sanitized `release-gates/<label>/recovery-plan-<utc>.json`; `--execute --confirm-label <label>`
re-does every check, archives both owner records and the failed receipt privately under
`release-gates/<label>/manual-recovery-<utc>/`, unlinks each `owner.json`, removes each lease directory,
fsyncs, verifies both are absent and writes `manual-recovery.json` (its sha256 is printed). The failed
receipt is never modified.

```
python3.14 -B -m tools.release.recover_leases --cache-root <root> --label <label> \
    --receipt <root>/release-gates/<label>/receipt.json [--run-coalition-id <id>]  # additive only; must be corroborated
```

Recovery is allowed only if both owner records carry the label and `requiresManualRecovery`, their
directories, inodes and record hashes are stable, every recorded identity (owner records and receipt
evidence) is exited (PID gone, start differs or zombie) or positively not a descendant
(`non-descendant-predates-run`, `non-descendant-ancestor-predates-run`, `non-descendant-coalition`), the
owner process is gone, two complete global scans at least 2 s apart (every live process born since the run
began) leave nothing unproven, and nothing holds the cache directories open. Identities are observed three
times at least 2 s apart. An empty `lsof` result is supporting evidence only. Exit codes: 0 allowed or
recovered, 1 refused, 2 invalid input or admission, 3 recovery started but incomplete.

Since the final fix round new runs persist their coalition ids and subreaper fact in the owner record
(`provenance`) and the receipt, and recovery treats those as authoritative. `--run-coalition-id` is
additive evidence and is refused unless it is in the persisted record, equals the recovery tool's own session
coalition, or is carried by a still-live recorded identity (0, negative and more than 8 ids are rejected).
Identities the run recorded as owned are cleared only by a verified exit. "Predates the run" uses the
kernel start time (proc_pidinfo or /proc), must agree with `ps` within 2 s, and needs a 300 s margin;
DST-ambiguous times fail closed. The owner record is re-read and unlinked through the lease directory
descriptor, archived owner records have the token replaced by its sha256, and `manual-recovery.json`
is written with an honest `status` even if a step after removal fails. Recovery proves non-descent in the
fork tree only; it cannot prove that a pre-existing daemon or delegated work cannot write the caches.
The floor job passes `--prewarm-gradle` (see below).

## Warming the pinned Gradle distribution

A cold `./gradlew --version` downloads the pinned Gradle distribution and cannot finish inside the fixed 20 s
`gradle-wrapper` version-probe budget (exit 124; the budget is never raised). `run_gates --prewarm-gradle`
runs the same wrapper through the supervised runner, under the floor's leases and environment, with its
own timeout (at most 900 s) and 3 attempts, into the private `GRADLE_USER_HOME` before the version probes;
CI uses it, and a local cold-cache floor should too:

```
python3.14 -B -m tools.release.run_gates --repo <worktree> --base <phase-base> --label <new label> \
    --cache-root <private root> --prewarm-gradle
```

To warm without running the floor, use the leased runner (same cache and leases):
`python3.14 -B -m tools.release.leased_run --repo <worktree> --label <new label> --cache-root <private root>
--timeout 900 -- ./adapters/java/gradlew --no-daemon --version`.
