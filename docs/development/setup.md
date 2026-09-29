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

The variables are optional; cargo falls back to its built-in locations when
they are unset.

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

The `justfile` exposes `just ci`, `just lint`, and `just test`. The `test` and
`ci` recipes install, codegen-check, and build/test the Node workspace before
running the Rust workspace tests.

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
