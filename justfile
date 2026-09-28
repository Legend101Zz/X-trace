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

# Apply the SQLite initial migration against a temporary store and report
# schema metadata. Used as a smoke check outside the Rust test harness.
smoke-cli:
    cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-smoke
    cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir /tmp/xtrace-smoke --format json
    rm -rf /tmp/xtrace-smoke

# Run every gate a handoff requires.
ci: format lint test
