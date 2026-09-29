# X-trace

X-trace is a local-first capture-and-replay tool for HTTP services. Slice 1A
ships the minimal Rust foundation: a workspace of five crates, one forward-only
SQLite migration, the XTP-Agent protobuf bindings, and a small CLI that can
initialize a project, open it, and report a truthful spine status.

The Node 22 workspace under `adapters/node` is a protocol/conformance
foundation only. Its private synthetic client can authenticate to the local
daemon and prove a staged XTP recording reached selected-root XTF storage; it
does not instrument Node applications or declare Node capture support. See
`docs/development/setup.md` for the exact acceptance commands and boundary.

## Crate layout

| Crate               | Purpose                                                                |
|---------------------|------------------------------------------------------------------------|
| `xtrace-domain`     | IO-free entities, identifiers, errors, value vocabulary                |
| `xtrace-application`| Commands, queries, ports, and the `Application` facade                 |
| `xtrace-protocol`   | Generated XTP protobuf bindings and domain-DTO translation              |
| `xtrace-store`      | Bundled SQLite store, migrations, and `ProjectRepository` adapter      |
| `xtrace-cli`        | Clap subcommands, output formatting, user-data path resolution          |

Dependency direction follows `docs/plans/x-trace/02-architecture.md`:

```text
xtrace-cli       -> xtrace-application, xtrace-store, xtrace-domain
xtrace-store     -> xtrace-application, xtrace-domain
xtrace-protocol  -> xtrace-domain
xtrace-application -> xtrace-domain
```

The domain crate never imports generated types; every wire payload that crosses
into domain DTOs flows through `xtrace-protocol::translate`.

## Storage layout

Project state lives under the resolved user-data home directory, not inside
the repository:

```text
<resolved_data_home>/projects/<project-id>/metadata.sqlite3
```

The resolved home is `XTRACE_DATA_HOME` when set to an absolute path, used
directly as the application root. When the override is absent, the platform
default documented in `crates/xtrace-cli/src/paths.rs` is used, and that
default already lives under `xtrace/...` because the resolver appends the
application folder itself. So an explicit `XTRACE_DATA_HOME` must not add
another `xtrace` segment, and the platform defaults shown below already
include the trailing `xtrace`:

- macOS: `$HOME/Library/Application Support/xtrace`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/xtrace`
- Windows: `%APPDATA%\xtrace`

The repository owns a single atomic pointer at `.xtrace/config.toml`:

```toml
schema_version = 1
project_id = "0192..."
data_home = "/Users/.../Library/Application Support/xtrace"
```

`xtrace init` writes the pointer after the database is fully initialized.
`xtrace status` reads the pointer and emits an empty report when it is
absent, without opening or creating any database file. `xtrace open` reads
the pointer and resolves the database path under the user-data home.

## Idempotent commands

Every command accepts a client-generated idempotency key. The CLI
auto-generates one (for example `xtrace-init-/path/to/repo`) so an
unattended retry behaves as a replay. The application facade persists every
receipt in the `command_receipts` table keyed by
`(project_id, command_kind, idempotency_key)`:

- Same key + same canonical input → return the original receipt verbatim.
- Same key + different canonical input → `XTR-COMMAND-409` (`Conflict`).

## Protobuf

The build resolves `protoc` from `protoc-bin-vendored` and passes the
absolute path to `prost_build::Config::protoc_executable`. It never inspects
`PATH`, never sets `PROTOC`, and never installs a system `protoc`. CI runs a
restricted-PATH build to verify the vendored path.

## Quick start

```bash
# Prepare and validate the Node XTP workspace (Node 22+, npm)
npm ci --prefix adapters/node
npm run generate:check --prefix adapters/node
npm test --prefix adapters/node

# Run the Rust suite, including the Node-to-daemon persistence test
cargo build --workspace --all-features
cargo test --workspace --all-features

# Initialize, status, and open the spine against a temporary repo
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-smoke
cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir /tmp/xtrace-smoke
cargo run -q -p xtrace-cli --bin xtrace -- open --project-dir /tmp/xtrace-smoke
```

`just test` and `just ci` perform the Node preparation and checks before Rust
tests, so their daemon integration test does not depend on prebuilt `dist`
files from another job or checkout.

The status report on an uninitialized repository is a single JSON document
that names no projects and reports `initialized: false` without touching
the filesystem.

## License

Dual-licensed under MIT or Apache-2.0 at the user's option.
