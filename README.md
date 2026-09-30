# X-trace

X-trace is a local-first capture-and-replay tool for HTTP services. The Rust
workspace provides project storage, authenticated XTP ingestion, and a CLI for
project setup, the foreground daemon, and an experimental direct-Java launch.

The Node 22 workspace under `adapters/node` is a protocol/conformance
foundation only. Its private synthetic client can authenticate to the local
daemon and prove a staged XTP recording reached selected-root XTF storage; it
does not instrument Node applications or declare Node capture support. See
`docs/development/setup.md` for the exact acceptance commands and boundary.

The Java workspace under `adapters/java` preserves that synthetic conformance
client and adds an experimental launch-only tracer bullet. A JDK-only
`premain`/bridge JAR loads a private runtime and captures one pinned Spring Boot
4.1.1 fixture's `POST /orders` path through Spring MVC, three exact application
methods, and H2 `executeUpdate()`. This is fixture evidence, not general Java,
Spring, Spring Boot, Servlet, attach, or production capture support. The
`POST /orders` identity is fixed by the exact fixture handler matcher; it is
source-derived test metadata, not request-derived dynamic endpoint discovery.
`xtrace run` is Unix-only and scoped to this exact fixture tracer bullet. It
does not launch Gradle/Maven tasks, wrappers, application servers, or arbitrary
process trees, and it does not add attach, discovery, browser replay, or broad
Java compatibility.

## Crate layout

| Crate               | Purpose                                                                |
|---------------------|------------------------------------------------------------------------|
| `xtrace-domain`     | IO-free entities, identifiers, errors, value vocabulary                |
| `xtrace-application`| Commands, queries, ports, and the `Application` facade                 |
| `xtrace-protocol`   | Generated XTP protobuf bindings and domain-DTO translation              |
| `xtrace-store`      | Bundled SQLite store, migrations, and `ProjectRepository` adapter      |
| `xtrace-daemon`     | Authenticated loopback XTP ingress and supervised connection draining |
| `xtrace-runtime`    | Runtime launch validation, agent injection, and process supervision    |
| `xtrace-cli`        | Clap subcommands, project composition, output and path resolution       |

Dependency direction follows `docs/plans/x-trace/02-architecture.md`:

```text
xtrace-cli       -> xtrace-application, xtrace-store, xtrace-daemon, xtrace-domain, xtrace-protocol, xtrace-runtime
xtrace-runtime   -> OS process launch and supervision policy
xtrace-daemon    -> xtrace-application, xtrace-domain, xtrace-protocol
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

# Verify dependencies, generate Java bindings, test, install the synthetic
# client, and assemble the experimental premain agent and Spring fixture
GRADLE_USER_HOME=/path/to/cache/gradle \
  adapters/java/gradlew -p adapters/java --dependency-verification strict \
  clean test installDist agentDist fixtureBootJar

# Run the Rust suite, including both language-to-daemon persistence tests
cargo build --workspace --all-features
cargo test --workspace --all-features

# Initialize, status, and open the spine against a temporary repo
cargo run -q -p xtrace-cli --bin xtrace -- init --project-dir /tmp/xtrace-smoke
cargo run -q -p xtrace-cli --bin xtrace -- status --project-dir /tmp/xtrace-smoke
cargo run -q -p xtrace-cli --bin xtrace -- open --project-dir /tmp/xtrace-smoke
```

Persisted recordings can be inspected through the bounded, read-only query
surface:

```bash
cargo run -q -p xtrace-cli --bin xtrace -- recording list \
  --project-dir /tmp/xtrace-smoke --limit 50
cargo run -q -p xtrace-cli --bin xtrace -- recording show \
  --project-dir /tmp/xtrace-smoke <recording-id> --limit 200
```

`list` is metadata-only, ordered by opening time and recording ID, and accepts
the returned `next_after` recording ID for another page (default 50, maximum
200). `show` verifies the touched XTF segments and returns an ordered event
window (default 200, maximum 1,000 events, 256 KiB of compact event JSON, and
16 MiB of verified compressed-plus-logical XTF input per call). If another
segment would exceed the input budget, the response stops at the preceding
event and returns a cursor; one codec-bounded first segment may be processed
to ensure progress. Pass the versioned `next_cursor` back with `--cursor`; the
cursor is bound to the selected project and recording. Sequence and monotonic
values are decimal strings for JavaScript-safe precision. Raw interaction paths
are omitted because persisted path segments may contain identifiers or tokens.
Oversized display fields become `[truncated]`; oversized identity/relationship
fields become `[unavailable]`. `field_truncations` records field names,
original byte lengths, and replacement kinds without retaining source text.
These projections contain persisted event metadata only: they do not expose
captured values, source bodies, or completion semantics, and a `recording`
status is not a completion claim.
Opening read-only uses normal SQLite WAL coordination; SQLite may create its
empty WAL/shared-memory coordination files when none exist, but query paths do
not migrate or update logical store data, repository pointers, or project
`last_opened` metadata.

`just test` and `just ci` prepare both language workspaces before Rust tests,
so their daemon integration tests do not depend on ignored build output from
another job or checkout.

The status report on an uninitialized repository is a single JSON document
that names no projects and reports `initialized: false` without touching
the filesystem.

## License

Dual-licensed under MIT or Apache-2.0 at the user's option.
