# v0.01 release gate tools

`run_gates.py` runs the fixed Rust, Java, Node, web, restricted-PATH and pinned
phase-diff gates. It accepts a checkout, a full immutable base commit SHA, a
safe run label, and a cache root explicitly:

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

For a command that exits almost immediately, the runner also compares the
process table with its pre-launch snapshot. A new, untracked live process is
treated as an unconfirmed descendant when it still holds that command's
private raw-log file open (the usual inherited stdout case). If the host cannot
inspect open descriptors, a new process is ambiguous and also retains the
leases. Such candidates are recorded separately as `unconfirmedProcesses`; the
runner never signals them. This catches a detached child that outlives its fast
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

Run the stdlib-only tooling tests with:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.release.test_release_tools
```
