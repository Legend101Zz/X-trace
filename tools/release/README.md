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
pins the complete mandatory requirement-ID set from the approved v0.01 plan,
so deleting a row or changing it to optional cannot make the ledger pass. Signed
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

Each receipt has `schemaVersion`, `requirementId`, `kind`, `result`,
`candidateSha`, `build: {id, sourceSha}`, non-empty `artifacts`, `evidence`,
and `checks` arrays. Each check must say `status: "passed"` and `reached: true`.
The canonical receipt excluding `signatures` is the signed payload. Signature
entries identify a trusted `keyId`, authorized `role`, relative signature
`path`, and SHA-256. The Petclinic exception records the user's explicit choice
to test a pinned maintained `main` SHA because no current stable tag exists; it
also records that obsolete `1.5.x` was not used.

Run the stdlib-only tooling tests with:

```text
python3 -m unittest tools.release.test_release_tools
```
