# Developer setup

This document describes how to set up a working copy of the X-trace workspace
and run the Slice 1A gates from a fresh checkout.

## Toolchain

- Rust stable (1.85 or newer; the workspace pins `rust-version = "1.85"`).
- `cargo`, `rustfmt`, and `clippy` from the active toolchain.
- A C compiler for `rusqlite`'s bundled SQLite build (clang on macOS, gcc
  on Linux, MSVC on Windows). No system SQLite is required.
- No system `protoc`. The build pulls Google's prebuilt `protoc` from
  `protoc-bin-vendored` at compile time.
- Node.js 22 or newer and npm, for the synthetic XTP conformance client.
- A Java 17 or 21 JDK, for the Java synthetic client and experimental Spring
  premain fixture. CI runs the fixture journey on both versions. The checked-in
  Gradle wrapper supplies Gradle 9.8.0 and verifies its distribution checksum.

## Caches

Caches are configurable. Point these variables at a suitable local cache root
to keep build artifacts outside the checkout:

```text
CARGO_HOME=/path/to/cache/cargo
CARGO_TARGET_DIR=/path/to/cache/cargo-target
GRADLE_USER_HOME=/path/to/cache/gradle
XDG_CACHE_HOME=/path/to/cache/xdg
PNPM_HOME=/path/to/cache/pnpm
NPM_CONFIG_CACHE=/path/to/cache/npm
```

The variables are optional; each tool falls back to its built-in locations
when they are unset. Set `GRADLE_USER_HOME` when large Gradle downloads and
caches should live outside the system disk.

The Node workspace also keeps its npm cache configurable through
`NPM_CONFIG_CACHE`. Generated protobuf bindings and compiled TypeScript are
not npm cache data: the bindings are checked in under
`adapters/node/packages/protocol/src/gen`, while `node_modules` and `dist`
remain ignored build outputs.

## Workspace commands

Run from the repository root:

| Command                                            | Purpose                                              |
|----------------------------------------------------|------------------------------------------------------|
| `cargo fmt --all --check`                          | Stable-rustfmt formatting gate                       |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Strict clippy gate                                   |
| `cargo test --workspace --all-features`            | Full unit and integration test suite                 |
| `cargo build -p xtrace-protocol --all-features`    | Build the protobuf crate end-to-end                  |
| Restricted-PATH build (see below)                  | Verify vendored protoc without a system `protoc`     |
| CLI smoke (see below)                              | End-to-end init / status / open walkthrough         |

The `justfile` exposes `just ci`, `just lint`, `just test`, `just node-check`,
and `just java-check`. The `test` and `ci` recipes prepare both language
workspaces before running the Rust workspace tests.

### Node XTP conformance client

The Node 22 workspace is a protocol-only foundation, not a runtime capture
adapter. Its synthetic client and daemon acceptance test are Unix-only. It
generates TypeScript bindings from the canonical Rust daemon schemas, then runs
a private synthetic client against `xtrace daemon`:

```bash
npm ci --prefix adapters/node
npm run generate:check --prefix adapters/node
npm test --prefix adapters/node
cargo test -p xtrace-cli --test node_synthetic_adapter
```

The integration test uses only the daemon's one-shot bootstrap path, validates
the certificate pin before sending XTP application data, proves the TLS
exporter-bound HMAC transcript, and verifies `Staged` acknowledgements plus a
fully verified XTF segment under the selected project's SQLite root. The
fixture is synthetic. This slice does not claim adapter support, framework
instrumentation, signatures, reconnect, daemon commands, `Committed` ACKs,
terminal recording state, or replay/UI support.

The pinned direct dependency licenses are compatible with the root MIT or
Apache-2.0 licensing: Buf's generator/runtime and CLI are Apache-2.0,
`@bufbuild/protobuf` declares Apache-2.0 AND BSD-3-Clause, TypeScript is Apache-2.0,
and `hash-wasm`, `uuid`, and `@types/node` are MIT. Exact versions are recorded
in `adapters/node/package.json` and `package-lock.json`.

### Java XTP conformance client

The Java 17 workspace is also protocol-only. It generates Java protobuf
classes at build time from `schema/proto`; generated sources and build output
are intentionally not checked in. Dependency locking, SHA-256 verification
metadata, and the Gradle distribution checksum are committed. Protoc artifact
verification covers Linux x86_64/AArch64, macOS x86_64/AArch64, and Windows
x86_64 builds; the private bootstrap reader and live acceptance executable are
Unix-only.

```bash
export GRADLE_USER_HOME=/path/to/cache/gradle
adapters/java/gradlew -p adapters/java --dependency-verification strict \
  clean test installDist agentDist fixtureBootJar
cargo test -p xtrace-cli --test java_synthetic_adapter
cargo test -p xtrace-runtime
cargo test -p xtrace-cli --test java_premain_spring
cargo test -p xtrace-cli --test java_run_spring
```

The private client accepts only `--bootstrap <path>`. It validates the
owner-only one-shot file, pins the exact TLS leaf certificate before sending
XTP data, uses an isolated Conscrypt provider for the TLS exporter, and proves
four `Staged` acknowledgements plus the selected-root SQLite/XTF artifact. It
prints one credential-free JSON receipt with `capture_supported: false`.

### Experimental Spring premain tracer bullet

The `agent-bootstrap`, `agent-runtime`, and `spring-fixture` Gradle projects are
a deliberately fixture-scoped launch proof. The JDK-only agent entrypoint
receives only the private bootstrap-file path in `-javaagent` options. It loads
Byte Buddy 1.18.14, protobuf, Conscrypt, and the XTP writer through a private
child-first runtime directory; those packages are not placed on the fixture's
application classpath. This experimental distribution does not yet relocate
Byte Buddy or protobuf. Conscrypt remains unrelocated for its native/JNI
resources. Package scans and the live fixture assert that none of these runtime
packages are visible from the application classloader.

Instrumentation is intentionally exact: Spring Framework 7.0.9's
`RequestMappingHandlerAdapter.handleInternal`, the fixture controller/service/
repository methods, and H2 2.4.240's zero-argument `executeUpdate()`. Advice
uses a fixed, source-derived `POST /orders` identity after the exact handler
matcher succeeds; it does not inspect a request route or perform dynamic
endpoint discovery. Advice passes only fixed identifiers and primitive status
to a bounded nonblocking queue; one writer thread owns XTP. The real-daemon
test sends a canary-bearing
`POST /orders`, verifies HTTP 201 and one H2 business row, then validates the
ordered selected-root XTF events and privacy surfaces. A second request throws
a canary-bearing fixture exception and proves the exception text is absent from
the 500 response, complete process streams, and persisted telemetry. The test
also proves invalid-bootstrap, daemon-unavailable, and forced-disconnect paths
leave application behavior intact while telemetry fails honestly.

This sub-slice is not a general Java agent release or a support claim. There is
no `agentmain`/attach, endpoint discovery, static scan, async propagation,
request values, SQL text/binds, source lines, UI, `xtrace run`, `Committed` ACK,
or terminal-complete recording. The existing live bootstrap path remains
Unix-only. The exact direct pins remain in the Gradle build files and strict
SHA-256 dependency verification/locking applies to every module.

### Experimental `xtrace run`

On Unix, `xtrace run` supervises a direct Java launcher and injects the built
agent with the private one-shot bootstrap path:

```bash
export CARGO_TARGET_DIR="/path/to/cache/cargo-target"
export XTRACE_DATA_HOME="/tmp/xtrace-run/userdata"
cargo build -p xtrace-cli --bin xtrace
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-run/repo
cargo run -q -p xtrace-cli --bin xtrace -- run \
  --project-dir /tmp/xtrace-run/repo \
  --java-agent adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar \
  -- java -jar adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar
```

The run command accepts only a direct executable named `java`; it preserves
the supplied argument vector and does not parse shell syntax or invoke a
wrapper. The agent JAR must have its `runtime/` sibling directory containing
regular JAR files. Setup failures happen before the child is launched. The
command waits for the Java process, forwards SIGINT/SIGTERM to its process
group, escalates after ten seconds, drains the daemon, cleans the private
runtime directory, and returns the Java process status. A sanitized
`capture_incomplete` diagnostic is written if the daemon exits early, fails to
drain, cleanup fails, or the one-shot bootstrap was never consumed.

Before project side effects, `xtrace-runtime` checks the native executable
format and probes the resolved launcher with `-version`; the probe has no
agent, bootstrap, or application arguments, and its output is never displayed.
Both the probe and launched JVM deliberately clear `JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS`, and `_JAVA_OPTIONS`, so ambient JVM option channels cannot
inject a second agent or expose bootstrap material. `@argfile` arguments are
rejected because they can hide additional JVM options. The agent distribution
must include `manifest.sha256` covering the bootstrap and every runtime JAR;
membership, SHA-256 digests, owner, hard-link count, symlink status, and write
permissions are checked before project side effects. This is integrity checking,
not a signature or trust claim.
This does not prevent a same-UID actor replacing files after validation;
same-user TOCTOU is outside this experimental boundary. The CLI owns only
selected-project daemon composition and result mapping.

After application exit, daemon drain is bounded to five seconds. If capture work
does not return by then, the CLI reports capture as incomplete and deliberately
retains the project lock and runtime artifacts through process termination. It
does not claim cleanup later in the same process: the unfinished daemon task is
not cancelled, and the lock is retained so another capture cannot overlap it.
The binary then returns the Java process status and exits; OS process teardown
releases the lock, and the next locked daemon start removes only recognized
stale artifacts. A long-lived embedding likewise retains the lock rather than
allowing overlapping capture work.

This is a supervised launch of the exact Spring Boot 4.1.1 fixture and its
existing `POST /orders` instrumentation. It is not Gradle/Maven task launch,
wrapper launch, generic Java/Spring/Servlet compatibility, attach, endpoint
discovery, browser replay, or a complete capture/replay release journey.

After stopping the run, inspect the persisted request with fresh CLI
processes:

```bash
cargo run -q -p xtrace-cli --bin xtrace -- recording list \
  --project-dir /tmp/xtrace-run/repo --limit 50
cargo run -q -p xtrace-cli --bin xtrace -- recording show \
  --project-dir /tmp/xtrace-run/repo <recording-id> --limit 200
```

List pages are metadata-only and bounded to 200 rows. Show windows are bounded
to 1,000 events, 256 KiB of compact event JSON, and 16 MiB of verified
compressed-plus-logical XTF input per request. If another segment would exceed
the input budget, the response stops at the preceding event and returns a
cursor; one codec-bounded first segment may be processed to ensure progress.
Use the returned versioned `next_cursor` with `--cursor` to continue. The
cursor is bound to the selected project and recording. Raw interaction paths
are omitted because path segments may contain identifiers or tokens. Oversized
display fields become `[truncated]`; oversized identity/relationship fields
become `[unavailable]`, with field names and original byte lengths reported
without source text. These are persisted facts, not debugger-complete replay:
values, source bodies, and completion semantics remain unavailable.
Read-only SQLite access keeps normal WAL visibility and may create SQLite
coordination sidecars, but does not apply migrations or update project or
pointer metadata.

### Restricted-PATH build

The build script must not rely on a system `protoc`. CI exercises the
constraint by setting `PATH` to a minimal set that excludes any directory
containing `protoc`:

```bash
PATH="/usr/bin:/bin:/usr/local/bin:/Users/comreton/.cargo/bin:/Users/comreton/.rustup/toolchains/stable-*/bin" \
    cargo build -p xtrace-protocol --all-features
```

A successful build under that `PATH` proves the build script resolves
`protoc` exclusively through `protoc-bin-vendored`.

### CLI smoke

The CLI smoke verifies the storage layout end to end:

```bash
export XTRACE_DATA_HOME=/tmp/xtrace-cli-smoke/userdata
mkdir -p /tmp/xtrace-cli-smoke/repo

# Status on an uninitialized repository must not mutate state.
cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir /tmp/xtrace-cli-smoke/repo

# Init creates the database and writes the pointer.
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-cli-smoke/repo --display-name "Smoke"

# Idempotent replay returns the original receipt.
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-cli-smoke/repo --display-name "Smoke"

# A conflicting reuse surfaces XTR-COMMAND-409.
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-cli-smoke/repo --display-name "Different" || true

# Status on the initialized repository reports the project.
cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir /tmp/xtrace-cli-smoke/repo

rm -rf /tmp/xtrace-cli-smoke
```

The CLI writes JSON to stdout on success and a single JSON error document to
stderr on failure, with a stable exit-code mapping documented in
`crates/xtrace-cli/src/error.rs`.

## Dependency and license policy

`deny.toml` enforces the project dependency policy. License pinning is required
to:

- MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception
- BSD-2-Clause, BSD-3-Clause, ISC
- Unicode-DFS-2016, Unicode-3.0
- CC0-1.0, Zlib, OpenSSL, MPL-2.0

`cargo deny check` is the recommended local invocation. The CI lane runs it
before the build so a license drift fails before the slow compilation step.

## Coding standards

The workspace `[workspace.lints]` table covers the surface; per-crate lints
inherit from it. Library code never panics; tests may panic on invariant
violations and unwrap fallible fixture data under explicit allow attributes.
Public items carry rustdoc; non-obvious invariants carry a one-line comment
explaining the design intent.
