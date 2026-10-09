# Packaging, supply chain and signing

Everything here produces UNSIGNED release-candidate artifacts. Signing, notarization and the release trust table are
owner-held (see "What needs the owner"). Dev builds in the Docker devbox are feedback only, never acceptance evidence.

## Build

    python3 packaging/build.py --out dist [--platform macos-arm64|linux-x86_64|linux-aarch64-dev]

Builds from a clean git checkout (refuses a dirty tree), then writes `dist/<platform>/`:

| file | content |
|---|---|
| `xtrace-0.0.1-<platform>.tar.gz` | deterministic payload: `bin/xtrace`, `share/xtrace/{web,packs/java,packs/node,schema,sbom.cdx.json,licenses.json,THIRD_PARTY_LICENSES,payload.sha256,PACKAGE-MANIFEST.json,VERSION}`, `install.sh`, `uninstall.sh` |
| `SHA256SUMS` | sha256 of every file in the directory except itself |
| `sbom.cdx.json` | CycloneDX 1.5: Cargo.lock + Gradle lockfiles/verification metadata + npm lockfiles |
| `licenses.json`, `THIRD_PARTY_LICENSES` | license inventory; flags `unknown`, `copyleft`, `review` |
| `build-info.json` | commit, lockfile hashes, toolchain versions (builder-provided, not attested) |

Determinism: sorted tar entries, uid/gid 0 root, mtime = `SOURCE_DATE_EPOCH` (the commit time), modes 0755/0644,
gzip mtime 0 and no file name, `--locked` Rust with path remapping and stripped symbols, Gradle archives forced
reproducible through `packaging/gradle/reproducible.init.gradle` (no product build edits), strict Gradle dependency
verification. `python3 packaging/repro_check.py --out DIR` rebuilds twice from fresh exports in different paths and
compares every output.

There is one product binary (`xtrace`; the daemon is a library inside it). Web assets are what the binary embeds
(`crates/xtrace-daemon/assets/ui`, verified against a fresh `vite build` with `npm run check:embedded`). Migrations
are compiled into the store crate, so no separate migration files ship.

## Static analyzers and `xtrace scan`

The release payload does not bundle the static analyzers. `xtrace scan` runs an analyzer as a separate subprocess and
finds it only from the `--analyzer PATH` flag or, when the flag is absent, the environment variable
`XTRACE_NODE_ANALYZER` (express, fastify, nest) or `XTRACE_JAVA_ANALYZER` (spring-mvc, spring-webflux). There is no
default lookup: with neither set the command exits with a usage error naming the variable. The Node analyzer is built
from `adapters/node` (`npm ci && npm run build`; entry `packages/analyzer/dist/main.js`, run with `node`, so point
`--analyzer` at a small executable wrapper). The Java analyzer is `adapters/java/static-analyzer`. It is part of the
Java Gradle build (`adapters/java/settings.gradle.kts`) and has unit tests (`SpringMvcAnalyzerTest`), but it is
not bundled in the release payload, and no test yet runs `xtrace scan` against the built Java analyzer. CI proves the Node path end to end with `crates/xtrace-cli/tests/scan_real_node_analyzer.rs`,
which scans the `express-basic` fixture with the built analyzer and reads the catalog back.

## Install, upgrade, uninstall

    tar -xzf xtrace-0.0.1-<platform>.tar.gz && cd xtrace-0.0.1-<platform>
    ./install.sh [--prefix DIR]            # default ~/.local/xtrace; prints PATH guidance, never edits profiles
    ./install.sh verify [--prefix DIR]     # re-check the installed payload against payload.sha256
    ./install.sh verify-dist DIR           # re-check DIR/SHA256SUMS before extracting
    ./uninstall.sh [--prefix DIR]

User data (the data home: `XTRACE_DATA_HOME`, else `~/Library/Application Support/xtrace` on macOS or
`${XDG_DATA_HOME:-~/.local/share}/xtrace` on Linux) is never created, modified or deleted by these scripts. An upgrade
copies the data home to `<prefix>/backups/<utc>-pre-<version>/` before the new version becomes `current`, keeps one
previous version for rollback, refuses downgrades without `--allow-downgrade`, and refuses a prefix inside the data
home. Uninstall removes program files only and prints where data and backups are. The product itself runs store
migrations at first use; the installer cannot migrate (and does not stop a running daemon: stop it first).
`packaging/test/install_test.sh dist/<platform>` exercises fresh install, upgrade, tamper/downgrade refusal and uninstall, and
the lifecycle on the installed binary (`init`, `record`, `stop`, and `restart` after the upgrade).

## Signing interfaces (fail clearly without real authority)

- `packaging/sign-macos.sh --archive A --out-dir D --identity "Developer ID Application: ..." --notary-profile P`
  requires macOS, a valid Developer ID identity in the keychain and a notarytool profile; otherwise exits 3 and does
  nothing. It signs `bin/xtrace` with the hardened runtime, notarizes, runs `spctl`, and repacks via `repack.py`
  (marks `packTrust=signed-macos-developer-id`). A bare Mach-O/zip cannot be stapled.
- `packaging/sign-detached.sh --key K --sums SHA256SUMS` writes an Ed25519 signature (`openssl pkeyutl -sign -rawin`,
  the primitive `tools/release/check_ledger.py` verifies). Needs OpenSSL 3 and a 0600 owner key. Test keys
  (`--non-release --generate-test-key`) are refused in release mode and their output is `*.nonrelease.sig`.

Pack signing (ADR 0004 Ed25519 embedded in `xtrace-pack.json`) is a different key domain and is not done here.

## Package content verification

`packaging/verify_package.py PACKAGE [--version 0.0.1] [--repo REPO] [--run-binary]` (stdlib only) verifies an
extracted package directory or the `.tar.gz`: manifest shape, version 0.0.1 in the manifest and `share/xtrace/VERSION`,
required components (the single `bin/xtrace` binary is checked only for presence; whether it contains a working
daemon or TUI is what the `--run-binary` checks below probe; web assets; Java pack; Node pack; protobuf schemas and OpenAPI; SBOM; licenses; installers),
per-file size and sha256 against the manifest, no unlisted files, `payload.sha256` rows, and a pack trust of
`unsigned` or `dev` only (a release claim is rejected, the report always says `release_evidence: false`). With
`--run-binary` it runs `bin/xtrace --version` and requires `xtrace <version>` plus `schema-version:` and `xtp-protocol:` lines, and
`xtrace tui --help` (`tui_subcommand_registered`: the subcommand exists) plus `xtrace tui` with stdin closed
(`tui_implemented`: the TUI is wired, so it must not exit 9 or report the old skeleton); with `--repo` it requires the reported schema version to equal the migration catalog's latest.
`packaging/test/test_verify_package.py` pins each check on synthetic layouts (not a product build). CI wiring is a
request to the CI lane (additive steps in `package.yml`).

## Daemon lifecycle (`xtrace record | stop | restart`)

* `record` starts `xtrace daemon` detached (own process group, output to private files under the project's
  `.daemon/` directory), waits for its readiness document, and writes `.daemon/daemon.json` (0600): pid, process start
  time, executable, session id, port, pin, bootstrap path. The bootstrap is single use, so a `record` arms exactly one
  launch; no secret is copied into the state file or the command output. Before starting, recordings that a previous
  daemon left open are sealed as partial.
* `stop` signals only that recorded pid, and only after it proves the pid is still that daemon (same process start
  time, same executable, an `xtrace daemon` command line). A mismatch is refused (exit 4, `XTR-LIFECYCLE-IDENTITY-MISMATCH`)
  and nothing is signalled. A daemon holding the project lock that `record` did not start is not signalled either. It
  waits for the lock to be released (it never escalates to SIGKILL), then seals recordings the daemon left open as
  partial. Not running is exit 3 (`XTR-LIFECYCLE-NOT-RUNNING`).
* `restart` is `stop` (not running is fine) then `record`; no data is deleted, but recordings left open are sealed as partial (store rows change).
* `record`, `stop` and `restart` are serialized per project by `.daemon/lifecycle.lock` (bounded 60 s wait, then `XTR-LIFECYCLE-BUSY`). Recordings are sealed best-effort one by one: a recording that cannot be sealed is listed with completion `failed` and `stop`/`restart` exit 10 (partial); `stop` with nothing running but rows sealed prints the document and exits 3.
* A start that fails after the daemon was spawned (bad readiness line, state write failure, timeout) terminates the child it spawned, so no unmanaged daemon is left holding the project lock.
* Identity checks need a procps or BSD `ps` supporting `-o lstart=` and `-o command=` (BusyBox `ps` does not); they run with `LC_ALL=C`. If `ps` is unusable, `record`/`stop` fail with `XTR-LIFECYCLE-IDENTITY-UNAVAILABLE` and change nothing.
* Limits: events a daemon had staged in memory but not yet written as a segment are lost on SIGTERM/SIGKILL (a
  daemon-side flush on shutdown is requested separately). `record` and `restart` take the same capture flags as
  `run`; what `capture_depth_enforced` promises is described in `docs/security-local.md` (capture depth). When a
  verified daemon is already running, `record` reports it and does not apply newly given capture flags.

## CI

`.github/workflows/package.yml` (push to `slice/v001-**`, `ultra/*-integration` and `ultra/rc-*`, manual):
`ubuntu-24.04` (linux-x86_64) and `macos-15` (macos-arm64): tool unit checks, reproducibility double build, build,
checksum + install journey, the install scratch test, the package content verifier (`packaging/verify_package.py`),
upload of unsigned artifacts. If the verifier is absent on a branch the step warns and records "NOT RUN" (a skip, not a
pass). `permissions: contents: read`, no secrets, actions pinned by commit SHA. `ci.yml` (push to `main`, `slice/**`,
`ultra/*-integration`, `ultra/rc-*`, and pull requests) runs the Linux 23-gate floors and the hosted macOS arm64 job;
`lane.yml` runs per-branch suites on `ultra/**`; `campaigns.yml` runs on `ultra/campaign/**` pushes and manual dispatch.

## What needs the owner

Developer ID identity + notary profile; the Ed25519 release/ledger keys and trust tables; legal review of flagged
licenses; provenance attestations (need `id-token`/`attestations` permissions, deliberately not granted here). The
project license is MIT (root `LICENSE`, workspace `license = "MIT"`).

## Install test scratch

`packaging/test/install_test.sh` creates its work directory under `$XTRACE_TEST_PRIVATE_SCRATCH` (a private 0700 directory the caller
created) when set, else `$TMPDIR`. `package.yml` points `TMPDIR` at a 0700 directory below `$RUNNER_TEMP`; `ci.yml` and `lane.yml` set
`XTRACE_TEST_PRIVATE_SCRATCH`. Product storage refuses data directories below group- or world-writable ancestors such as Linux
`/tmp`, so the script refuses such a scratch root up front. It aborts if `mktemp` fails, refuses a work directory equal to the starting
directory (logical or physical) or `$HOME`, refuses one that is not empty when claimed, and on exit stops a leftover daemon (by the
project's recorded identity) and removes only that directory. `packaging/test/install_scratch_test.sh` asserts these behaviours
(failing mktemp, missing/open scratch root, cwd and symlinked cwd, foreign non-empty dir, scratch root used and emptied); it needs no
build. Linux/dash proof comes from running it in CI.
