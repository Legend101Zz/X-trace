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

## Caches

`AGENTS.md` documents the recommended cache layout for this worktree.
The defaults keep build artifacts on the external SSD so a fresh checkout
does not fill the system disk:

```text
CARGO_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/cargo
CARGO_TARGET_DIR=/Volumes/Mrigesh SSD/.cache/xtrace/cargo-target
GRADLE_USER_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/gradle
XDG_CACHE_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/xdg
PNPM_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/pnpm
```

The variables are optional; cargo falls back to its built-in locations when
they are unset.

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

The `justfile` exposes the same set through `just ci`, `just lint`, and
`just test` for convenience.

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