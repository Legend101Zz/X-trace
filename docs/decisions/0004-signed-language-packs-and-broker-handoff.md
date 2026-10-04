# ADR 0004: Signed language packs and broker handoff (Java and Node)

- Status: Proposed
- Date: 2026-10-04
- Context: `docs/plans/x-trace/03c-runtime-adapters.md` §1 specifies a signed
  `xtrace-pack.json`, and `03b-protocol-and-api.md` §2.1/§2.4 specify private
  bootstrap and an `AdapterHello` manifest digest, but no plan or ADR defines the
  concrete pack format, the Node producer manifest, the trust authority, the
  cross-process bootstrap broker, or the daemon's join between an admitted pack
  and a live session. The verifier on `slice/v001-pack-verifier` (e48d6d2)
  implements a format and refuses Node pending "an approved producer-manifest
  contract" (`pack_inventory.rs:473-480`, `pack_inventory.rs:1001`). This ADR
  documents what exists, extends it to Node, and proposes the broker contract.
  A bootstrap secret, an HMAC, a digest, or a Hello assertion is never publisher
  trust.

## Decision

### 1. The existing format (as implemented on `slice/v001-pack-verifier`)

References are to that branch.

**Outer manifest.** File `xtrace-pack.json` at the pack root. Canonical JSON:
UTF-8, no whitespace, object keys sorted by UTF-16 code unit, duplicate keys
rejected, only unsigned integers up to 2^53-1 (no floats, negatives, or
exponents), strings up to 16 KiB, depth <= 32, nodes <= 8,192, file <= 64 KiB
(`signed_pack.rs:12-17, 233-250`). Non-canonical bytes are rejected, not
normalized. The key set is closed and exact:

```text
schemaVersion        1
pack                 {name: "java"|"node", version: "0.0.1", buildHash: "b3:<64 lowercase hex>"}
release              {min: "0.0.1", max: "0.0.1"}                 (signed_pack.rs:279,288)
protocol             {min: "M.m", max: "M.m"}
runtime              {language, versionRange: ">=A <B", testedMajors: [u32 ... 1..16]}
platforms            [{os: "macos"|"linux", arch: "aarch64"|"x86_64"}]  sorted, unique, <= 8
entrypoints          {launch, attach, staticDiscovery}
frameworkModules     [ {id, framework, packageMarkers, versionRange, testedVersions,
                        status, discoveryCapabilities, captureCapabilities,
                        requiredRuntimeFeatures, matcherIds, conflicts, after,
                        posture, fixtureIds} ] <= 64
capabilities         {name: "unavailable"|"preview"|"supported"}   closed name list
knownLimitations     [closed list of 21 codes], sorted, <= 64
artifacts            [{path, hash: "b3:<hex>"}]                   sorted, case-fold unique, <= 96
signature            {algorithm: "Ed25519", keyId, value: base64url(no padding, 64 bytes)}
```

Entrypoint shape: Java `launch` and `attach` are artifact paths; Node `launch` is
`{commonJs, esModule}` (two artifact paths), Node `attach` is `null`
(`signed_pack.rs:560-600`). `staticDiscovery` is `null` or an artifact path. Every
referenced path must be in `artifacts`. Windows and other platforms are not
representable (`signed_pack.rs:509-540`).

**Signature algorithm and message.** Ed25519 via `ring`. The signature is
**embedded** in the manifest (not a detached file). The signed message is
`"XTRACE-PACK-v1\0" || canonical_json(manifest with only signature.value
removed)` (`signed_pack.rs:1261`), so `signature.algorithm` and
`signature.keyId` are covered.

**Digests.** Artifact digest: BLAKE3-256 of the exact file bytes, `b3:`+hex.
`pack.buildHash` = BLAKE3-256 of
`"XTRACE-PACK-BUILD-v1\0" || be32(count) || for each artifact in path order:
be32(len(path)) || path || digest32` (`signed_pack.rs:1298`). The **outer manifest
digest** is BLAKE3-256 of the canonical manifest bytes including the signature
(`signed_pack.rs:1280`); the private snapshot directory is named
`b3-<outer digest hex>`.

**Trust.** `TRUSTED_RELEASE_KEYS: &[TrustedReleaseKey{key_id, public_key[32],
minimum_release, maximum_release, revoked}]` compiled into the core binary, empty
in this checkpoint (`signed_pack.rs:1360`); `verify_with_installed_trust` looks up
`signature.keyId`, enforces release range and revocation, then verifies the
signature (`signed_pack.rs:1371`). An unknown key id returns `TrustUnavailable`; no
key is ever read from the pack, environment, or CLI.

**Inventory and admission pipeline.**
`inspect_pack` -> `InspectedPack` (untrusted; descriptor-relative no-follow reads,
closed file/directory inventory, per-file <= 256 MiB, total <= 512 MiB, <= 4,096
tree entries, 30 s deadline; `pack_inventory.rs:21-29`) ->
`authenticate_artifacts_and_snapshot` (installed-trust signature first, then copy
exact opened descriptors into an owner-enforced private snapshot,
`pack_inventory.rs:157`) -> `AuthenticatedArtifactSnapshot` (no compatibility
claim) -> `verify_for_runtime(RuntimeMajor)` (`pack_inventory.rs:417`) ->
`VerifiedSignedPack` (private-field, non-constructible elsewhere). Admission checks
pack and release version `0.0.1`, pack name == runtime language, platform tuple,
`xtrace_protocol` version within `protocol.min..=max` (daemon constants are
`1.0`, `envelope.rs:20-22`), `runtime.versionRange` and `testedMajors` containing
the core-selected major (`Java17|Java21|Node22|Node24`), and binds the **inner
manifest digest**.

**Java inner layout (verified in `verify_inner_manifests`,
`pack_inventory.rs:997-1065`).** Required files `pack.manifest`,
`attach/xtrace-attach.jar`, `agent/manifest.sha256`, `agent/xtrace-java-agent.jar`,
and `agent/runtime/*.jar`; directories exactly `agent`, `agent/runtime`, `attach`.
`pack.manifest` and `agent/manifest.sha256` are SHA-256 row files
(`<64 hex>  <relative path>\n`, sorted, <= 96 rows); `pack.manifest` must list every
file except itself and `xtrace-pack.json`; `agent/manifest.sha256` must list exactly
the `agent/**/*.jar` set. The core-selected inner digest is the BLAKE3 digest, from
the signed outer inventory, of the artifact `agent/manifest.sha256`
(`pack_inventory.rs:473-480`).

Separation of concerns that this ADR keeps: **publisher authority** is the
installed trust table and the Ed25519 signature; **byte integrity** is the signed
inventory; **runtime/platform fit** is `verify_for_runtime`; **process identity**
is the broker binding (section 4); **session join** is the daemon expected-pack
record (section 5). None substitutes for another.

### 2. Node pack extension

**Layout** (pure JavaScript, closed inventory, bundled so the 96-artifact limit
holds; target <= 40 files):

```text
xtrace-pack.json                      outer manifest (name "node")
pack.manifest                         SHA-256 rows of every file except itself and the outer manifest
node/producer-manifest.json           inner (producer) manifest, canonical JSON, <= 64 KiB
register/register.cjs                 CJS preload      (outer entrypoints.launch.commonJs)
register/register.mjs                 ESM import entry (outer entrypoints.launch.esModule)
dist/loader.cjs                       registerHooks loader (ADR 0003)
dist/transport-worker.cjs             TLS transport worker
dist/instrumentation-*.cjs            http, express, fastify, nest modules
dist/vendor.cjs                       bundled acorn, magic-string, remapping, protobuf runtime
dist/node-http-manifest.json          existing capability facts, now covered by the inventory
licenses/THIRD_PARTY.txt              SPDX list for every bundled dependency
```

Directories are exactly `register`, `dist`, `node`, `licenses`. `attach` is `null`
(Node attach is unsupported in v0.01). Outer `platforms` is
`[{linux,x86_64},{macos,aarch64}]` (the two promised platforms); `runtime` is
`{language: "node", versionRange: ">=22 <25", testedMajors: [22, 24]}`.

**Inner (producer) manifest**, schema `xtrace-node-producer/1`:

```text
schemaVersion      1
producer           {name: "xtrace-node", version: "0.0.1"}
runtime            {language: "node", versionRange: ">=22 <25", testedMajors: [22, 24],
                    hooksMinimum: "22.15.0"}
entrypoints        {commonJs: "register/register.cjs", esModule: "register/register.mjs",
                    worker: "dist/transport-worker.cjs"}      must equal the outer launch paths
files              [{path, b3: "b3:<hex>", sha256: "<hex>"}]   closed; every file except
                                                                node/producer-manifest.json,
                                                                pack.manifest, xtrace-pack.json
modules            [{id, path, moduleSystem: "cjs"|"esm"|"both", kind: "preload"|"loader"|
                     "worker"|"instrumentation"|"vendor"}]
dependencies       [{name, version, integrity: "sha512-<base64>", license: "<SPDX>"}]
capabilities       subset of the outer capabilities (never a superset)
limits             {maxSourceBytes: 1048576, maxFileBytes: ..., maxEventBytes: ...}
```

**Inner-manifest digest binding.** The inner manifest cannot contain the outer
build hash (circular). It is bound downward and upward: the outer inventory lists
`node/producer-manifest.json` with its BLAKE3 digest, so the signature and
`buildHash` cover the inner manifest; the core-selected inner digest for Node is
that artifact's inventory digest, exactly as for Java
(`known_inner_manifest_digest`, `pack_inventory.rs:473`, gains
`"node" => "node/producer-manifest.json"`). `verify_inner_manifests`
(`pack_inventory.rs:1001`, currently `if pack_name != "java" { return Ok(()) }`) must
run for Node and reject: any file absent from, or extra to, `files`; a `b3` or
`sha256` mismatch; inner `entrypoints` differing from outer launch paths; inner
`capabilities` not a subset of outer; outer `matcherIds` not a subset of inner
`modules[].id`; a `runtime` range wider than the outer range.
`AdapterHello.manifest_digest` MUST equal `b3:<inner digest hex>` and
`adapter_build_hash` MUST equal `pack.buildHash`; today the daemon merely echoes the
adapter's claimed digest (`crates/xtrace-daemon/src/runtime.rs:160-224`), which this
ADR replaces with a comparison against the expected-pack record (section 5).

**Schema change proposed before first signing** (schema 1 has never been signed;
no migration needed): add required `runtime.bestEffortMajors` (array, possibly
empty, disjoint from `testedMajors`, each within `versionRange`) and
widen Java `versionRange` to `>=17 <26`. `VerifiedSignedPack` records a
`support_level` of `tested` or `best_effort`; a best-effort major is admitted only
for attach and is labelled "unverified" everywhere. This is how ADR 0005 allows
JDK 25 without making it a release claim. If root declines, JDK 25 remains
unadmitted and `doctor` reports `XTR-RUNTIME-UNTESTED`.

### 3. Trust authority and key custody

Three trust roots exist and are never mixed:

1. **Release trust table**: compiled into the core binary, shipped with the
   installed CLI, release builds only. This is the only authority for
   `Supported`/`Preview` pack claims and for every ledger row that cites pack
   provenance.
2. **Dev/test trust**: a Cargo feature `dev-trust-table`, off by default, never in
   `default` or release feature sets. Test keys are generated at test time or
   embedded under `#[cfg(test)]`; no runtime route (flag, file, environment) can
   add a key. CI asserts `cargo tree -e features` and the release workflow fail if
   the feature is enabled for a release artifact. Sessions created through it carry
   `pack_trust: dev`, a permanent UI warning, and cannot back any v0.01 receipt.
3. **Explicit unsigned development pack**: `--allow-unsigned-dev-pack <dir>` only,
   per 03c §1; permanent warning, `pack_trust: unsigned_dev`, refused when the
   binary was built with the release marker, and a recording made under it is never
   later relabelled as signed.

The release-evidence ledger (`tools/release/check_ledger.py`) uses OpenSSL
detached signatures against an owner-authenticated trust config. That is a
separate domain from pack signing and must not share keys with it.

**Requires a real signing identity (cannot be satisfied by test keys):** the
Ed25519 release key and its custody/rotation/revocation policy (public key bytes
into `TRUSTED_RELEASE_KEYS`); macOS Developer ID codesigning and notarization of
the package; the signed Linux package; ledger signer keys. **Works with test keys:**
every verifier unit test, tamper and rejection matrices, broker tests, daemon join
tests, and CI journeys on the dev-trust build. Until a release key exists, the
production path returns `TrustUnavailable` and INSTALL-*, PLATFORM-* and
SUPPLY-CHAIN rows stay pending (the ledger has no waiver state).

### 4. Private one-shot broker/peer handoff

Replaces the owner-readable bootstrap file for signed-pack launches and attach.

**Namespace.** The core creates a per-launch directory with a short path (macOS
`sun_path` is 104 bytes, Linux 108): `<owner-private runtime root>/b/<12 hex>`, mode
0700, owned by the effective UID, created under an admitted private root
(`private_roots`/`AdmittedPrivateRoot` capability), every parent component opened
no-follow and proven owner-only. The socket is `<dir>/s`. A path longer than 100
bytes is a hard error.

**Parameters delivered to the target.** Only the socket path (not secret): Java
`-javaagent:<jar>=broker=<path>`; Node `XTRACE_BROKER=<path>`, removed from
`process.env` after reading, alongside the existing preload-environment restore
(`start-capture.ts` `restoreLauncherEnvironment`). No secret travels through argv
or env.

**Protocol (one global deadline, default 5 s from listen to ACK).**

1. Core binds `AF_UNIX/SOCK_STREAM`, `listen(1)`, records
   `expected = {pid, pid_start_identity, uid, launch_id | attach_id, session_id}`.
   Launch: `pid` is the spawned child; attach: the PID and `startTime` validated
   by the attach helper (`crates/xtrace-cli/src/attach.rs:435-437, 972` on
   `slice/v001-java-cli-attach`).
2. Core `accept`s exactly one connection, then immediately stops listening.
3. Peer check: macOS `LOCAL_PEERCRED` (uid) and `LOCAL_PEERPID`; Linux
   `SO_PEERCRED` (pid, uid). Reject unless `uid == euid` and `pid == expected.pid`.
   Start-time binding: macOS `proc_pidinfo(PROC_PIDTBSDINFO)` start time; Linux
   `/proc/<pid>/stat` field 22 plus boot id. It is read before and after the transfer;
   a change aborts.
4. Request frame: `magic "XTBK1"`, `be16 length`, client nonce (16 bytes). Response:
   one bounded frame (<= 4 KiB) with the session secret, certificate pin,
   `runtime_session_id`, project id, protocol range, and daemon endpoint (the same
   material as 03b §2.1), tagged with the nonce.
5. Consumer ACK frame carries `SHA-256(payload)`; core verifies it, then unlinks
   the socket, removes the directory, and zeroizes the payload buffer. Any failure,
   timeout, second connection, or oversize frame also removes the socket and
   directory. Residue that cannot be removed is recorded (`broker_cleanup_uncertain`)
   and fails the launch.

**Target-side checks before reading any byte.** Java (`java.nio` unix-domain socket,
JDK 16+; the pack's JDK 17/21 floor) and Node (`net.connect({path})`): `lstat` the
directory and socket without following symlinks; require owner uid equal to the
process euid, directory mode 0700, socket not group/other accessible, parent chain
not world-writable, and, where the platform exposes it, that the filesystem is not a
network or ownership-disabled mount (the SSD, whose ownership is disabled and mode
is 0775, is not admitted). Failure is a refusal with a bounded `XTR-*` diagnostic on
stderr; **the application continues without capture** (existing fail-open behavior
is not weakened).

**Direct-reader refusal.** The new consumers contain no code path that accepts a
bootstrap file path in release mode. A file bootstrap is accepted only under
`pack_trust: dev`/`unsigned_dev`.

**Other-UID negative.** A fake broker bound by a different UID in a directory that
UID owns must be rejected by the target (owner mismatch). This requires a second
local user: Linux CI uses `sudo -u`; macOS arm64 runs it on the GitHub macOS runner
(ADR 0006). It cannot be produced on the owner's workstation without privileged user
creation and is therefore a CI obligation.

### 5. Daemon expected-pack session join

When the core admits a `VerifiedSignedPack` and starts a launch/attach, it records
an `ExpectedPack` in the daemon, never derived from the connecting process:

```text
{ outer_digest, build_hash, key_id, inner_digest, language, runtime_major,
  support_level, pack_trust, launch_id|attach_id, expected_pid, pid_start_identity,
  session_id, deadline }
```

The daemon accepts `AdapterHello` only when all hold: TLS pin and the existing
session-secret transcript proof (this proves possession of the broker-delivered
secret, which is **not** publisher trust); `manifest_digest == b3:inner_digest`;
`adapter_build_hash == build_hash`; `signing_identity == key_id`; `language` and
runtime major match; `pid` equals `expected_pid` and the reported start identity
matches (as asserted; the authoritative binding is step 3 of the broker); the
`ExpectedPack` is unexpired and not already joined. A Hello with no `ExpectedPack`
is rejected, except under `unsigned_dev`, which is recorded as such. The session
stores the pack facts (manifest digest, key id, trust level) with the runtime
session and every recording, per 02a "Capability manifest".

### 6. Rejection matrix (stable codes, none leaks paths or secrets)

| Stage | Reject when | Code |
|---|---|---|
| Parse | oversize, noncanonical, duplicate key, bad UTF-8, float/negative/overflow | `XTR-PACK-MANIFEST-INVALID` |
| Schema | unknown/missing key, wrong version/name/release/platform/limits | `XTR-PACK-MANIFEST-UNSUPPORTED` |
| Inventory | extra/missing/changed file, symlink, hard link, special file, case-fold clash, path rule violation, limit | `XTR-PACK-INVENTORY-MISMATCH` |
| Build hash | frame digest differs | `XTR-PACK-BUILD-HASH` |
| Trust | unknown key id, revoked key, release outside key range | `XTR-PACK-TRUST-UNAVAILABLE` |
| Signature | wrong key, tampered field incl. `keyId`/`algorithm`, bad base64url | `XTR-PACK-SIGNATURE` |
| Inner | missing inner manifest, digest/entrypoint/capability/module mismatch | `XTR-PACK-INNER-MISMATCH` |
| Compat | runtime major not tested/best-effort, platform, protocol range | `XTR-PACK-INCOMPATIBLE` |
| Snapshot | private root not admitted, cleanup uncertain | `XTR-PACK-SNAPSHOT` |
| Broker | wrong uid/pid/start time, second connection, oversize, bad nonce/ACK, symlink, deadline | `XTR-BROKER-REFUSED` |
| Join | digest/key/build/pid mismatch, no expected pack, expired, replay | `XTR-SESSION-PACK-MISMATCH` |
| Mode | dev/unsigned pack in a release build | `XTR-PACK-DEV-DISALLOWED` |

## Alternatives considered

- **Keep the owner-readable bootstrap file.** Same-UID processes can read it and
  directory ownership is not provable inside a standalone Java helper or Node
  preload; a path or environment Boolean is not authority. Retained only for dev
  modes.
- **Sign with HMAC / rely on Hello `manifest_digest` and `signing_identity`.**
  Self-asserted by the process being authenticated; rejected as publisher trust.
- **Detached signature (`xtrace-pack.json.sig`).** Would let the signed bytes and
  key id diverge; the embedded form already binds `keyId` and `algorithm`. Kept
  embedded; changing it forfeits the reviewed verifier.
- **Sigstore/cosign or X.509.** Needs network or a PKI/transparency dependency at
  install; incompatible with offline/local-first. Possible later for package
  distribution, not for pack admission.
- **TCP loopback broker.** Peer PID is not portably available and any local process
  can connect; Unix-domain sockets give kernel-reported peer credentials.
- **`fork`/`exec` fd inheritance of a pipe.** Works for launch but not attach, and
  the JVM/Node preload would still need to trust an inherited descriptor number.
- **Separate native per-platform Node pack.** Not needed; the pack is pure JS.

## Consequences

- Shared-contract changes: `signed_pack.rs` schema key `runtime.bestEffortMajors`,
  `RuntimeMajor` and `VerifiedSignedPack.support_level`, Node inner verification,
  daemon `ExpectedPack` and Hello comparison, a new `xtrace-runtime` broker module,
  Java `BootstrapReader` and Node `bootstrap.ts` broker consumers.
- Release builds cannot load any real pack until a release key exists; this is
  deliberate fail-closed and shows up as pending INSTALL/PLATFORM/SUPPLY-CHAIN rows.
- The pack constants `0.0.1` (`signed_pack.rs:279,288`,
  `pack_inventory.rs:29`) must change with the next release; they are intentionally
  not ranges today.
- Node's 40-file budget forces bundling; the bundle itself is part of the signed
  inventory and the supply-chain evidence (licenses, integrity of each dependency).

## Test and evidence obligations

Verifier: golden vector (manifest bytes, signed message, build hash, outer digest,
signature) for Java and Node produced with a test key; one test per rejection row;
mutation tests (flip each byte class: keyId, algorithm, an artifact digest, an
entrypoint, inner digest); inventory tests for symlink, hard link, FIFO, case-fold,
oversize, depth; swap tests (valid Java inner digest in a Node pack); revoked and
out-of-range key; snapshot cleanup fault injection. Node inner manifest: closed
inventory, subset rules, entrypoint equality. Broker: unit tests on both OS for peer
uid/pid/start-time (PID-reuse simulation), deadline, second connection, oversize,
wrong nonce, symlinked directory, 0770 directory, ACK failure cleanup, residue
detection; Java and Node consumers each with the other-UID fake broker (Linux x86_64
and macOS arm64 in CI); direct-reader refusal; fail-open proof that the application
still serves traffic and exits with its own code when the broker is refused.
Daemon join: matrix over each Hello field mismatch; replayed Hello; Hello without
expected pack; `unsigned_dev` labelling persisted and rendered. Packaged: installed
CLI refuses a pack signed by a non-table key; fresh-profile journey on both
platforms with the release key (blocked on authority); canary scan includes broker
payload (secret never in argv, env after read, logs, or crash output).

## Open questions

1. Who holds the Ed25519 release key and what are the rotation/revocation rules
   (single key for v0.01, or two for rotation rehearsal)?
2. Accept the proposed `runtime.bestEffortMajors` schema addition, or leave JDK 25
   unadmitted?
3. Is a 5 s global broker deadline acceptable for slow JVM startups, or should
   attach and launch differ?
4. Should Node pack bundling use esbuild (new build dependency) or ship unbundled
   files and raise `MAX_ARTIFACTS`?
5. Where does the broker runtime root live on Linux when `XDG_RUNTIME_DIR` is
   absent (CI containers)?
6. Do we require Linux/macOS peer start-time binding on the daemon's TLS side as
   well, or is the broker binding sufficient?
