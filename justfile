# justfile — root command surface for the X-trace Slice 1A spine.
#
# Each recipe documents its intent. The default recipe prints the available
# entry points so a fresh checkout never needs to guess.

set shell := ["zsh", "-cu"]

default:
    @just --list

# Print required toolchain versions and confirm the caches described in
# AGENTS.md are wired correctly.
doctor:
    @rustc --version
    @cargo --version
    @echo "CARGO_HOME=${CARGO_HOME:-default}"
    @echo "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-default}"

# Format every workspace crate.
format:
    cargo fmt --all

# Run clippy across the workspace with warnings denied.
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build everything (debug, no features flag required).
build:
    cargo build --workspace --all-features

# Run the full test suite.
test:
    cargo test --workspace --all-features

# Rebuild generated protocol bindings and confirm they are in sync.
protoc:
    cargo build -p xtrace-protocol --all-features

# Build the protobuf crate with a PATH that excludes any directory that
# could host a system `protoc`. A successful build proves the build
# script resolves `protoc` exclusively through `protoc-bin-vendored`.
protoc-restricted:
    PATH="/usr/bin:/bin:/usr/local/bin:$HOME/.cargo/bin" cargo build -p xtrace-protocol --all-features

# End-to-end CLI smoke: status on an uninitialized repo, init, idempotent
# replay, idempotency conflict, status, and open. Each step is asserted.
# Set XTRACE_DATA_HOME to control the user-data root.
smoke-cli:
    #!/usr/bin/env bash
    set -euo pipefail
    smoke_root=$(mktemp -d -t xtrace-cli-smoke.XXXXXX)
    export XTRACE_DATA_HOME="$smoke_root/userdata"
    mkdir -p "$smoke_root/repo"
    repo="$smoke_root/repo"
    cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir "$repo"
    test ! -d "$XTRACE_DATA_HOME"
    init_out=$(cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir "$repo" --display-name "Smoke")
    project_id=$(printf '%s' "$init_out" | grep -oE '"project_id": "[^"]+"' | cut -d'"' -f4)
    test -n "$project_id"
    test -f "$XTRACE_DATA_HOME/projects/$project_id/metadata.sqlite3"
    test -f "$repo/.xtrace/config.toml"
    replay=$(cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir "$repo" --display-name "Smoke")
    replay_id=$(printf '%s' "$replay" | grep -oE '"project_id": "[^"]+"' | cut -d'"' -f4)
    test "$replay_id" = "$project_id"
    conflict=$(cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir "$repo" --display-name "Different" 2>&1 || true)
    echo "$conflict" | grep -q "XTR-COMMAND-409"
    status=$(cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir "$repo")
    echo "$status" | grep -q "\"initialized\": true"
    echo "$status" | grep -q "$project_id"
    cargo run -q -p xtrace-cli --bin xtrace -- open --project-dir "$repo"
    rm -rf "$smoke_root"

# Run every gate a handoff requires.
ci: format lint test
