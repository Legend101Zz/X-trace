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
- Exit codes: 0 passed, 1 command or expectation failed, 2 invalid input or
  admission failure, 3 uncertain process tree (leases retained for manual
  recovery) or lease release failure, 75 leases busy past `--wait`.
- `--expect-unittest N` passes only on exit 0, `Ran N tests`, a plain `OK` and
  no skip or expected-failure marker.
- One JSON summary line is printed: label, decision, exit code, duration, log
  SHA-256 and lease cleanup.
