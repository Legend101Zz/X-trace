# Gate 3 Appendix D: Clients, Configuration, Exports, and Verification

**Status:** approved with Gate 3 on 2026-09-28  
**Purpose:** define CLI/TUI/web behavior, shared replay state, configuration, endpoint exercise, deterministic exports, Postman delivery, and the end-to-end verification matrix.

## 1. One interaction model, three surfaces

The clients share command/query names, DTOs, filters, status vocabulary, error codes, and replay navigation semantics. They do not share view components.

| Intent | CLI | TUI | Web |
|---|---|---|---|
| discover | `xtrace scan` | Run menu | endpoint catalog action |
| launch capture | `xtrace run -- …` | Launch dialog | launch instructions/action |
| JVM attach | `xtrace attach` | process picker | process picker opened through daemon |
| inspect endpoint | `xtrace endpoint show` | endpoint/detail panes | endpoint region |
| replay | `xtrace recording show` summary | linear source/call panes | Canvas or Linear |
| focused capture | `xtrace capture arm` | arm action | arm next request |
| exercise | `xtrace exercise plan/run` | plan review | plan review |
| export | `xtrace export` | export dialog | export menu |

## 2. CLI command surface

```text
xtrace init [--project <path>]
xtrace open [--project <path>] [--no-browser]
xtrace tui [--project <path>]
xtrace status [--json]
xtrace doctor [--json] [--bundle <path>]

xtrace scan [--source-only|--runtime] [--json]
xtrace run [capture flags] -- <application command...>
xtrace attach [--pid <pid>] [capture flags]
xtrace stop [--session <id>]

xtrace endpoint list [filters] [--revision <id>] [--json]
xtrace endpoint show <operation-id> [--json]
xtrace recording list [--endpoint <id>] [--json]
xtrace recording show <recording-id> [--frame <id>] [--json]
xtrace capture arm --endpoint <id> [--next <n>] [--expires <duration>]

xtrace exercise plan [--selection new-changed-unobserved|all|<ids>]
  [--base-url <url>] [--scenario <file>] [--output <file>]
xtrace exercise approve <plan-id> --plan-hash <hash>
xtrace exercise run <plan-id>

xtrace export --format openapi|postman|curl|bundle
  [--revision <id>] [--output <path>] [--preview] [--json]
xtrace postman connect
xtrace postman publish <export-id> --workspace <id> [--collection <id>]

xtrace history runs [--kind <kind>] [--json]
xtrace history catalog [--json]
xtrace history compare <from-revision> <to-revision> [--json]
xtrace retention preview [--json]
xtrace retention apply --preview-digest <digest>
xtrace store migrate --dry-run
xtrace config validate|show|migrate
```

### 2.1 CLI behavior

- Fully specified commands are non-interactive.
- Missing destructive/safety-critical choices produce an interactive prompt only on a TTY; otherwise they fail with a remediation and required flag.
- `--json` writes one versioned JSON result to stdout. Progress and diagnostics go to stderr; captured values are excluded unless the command explicitly queries them and stdout is a TTY or an explicit reveal flag is used.
- Exit codes: `0` success, `2` usage/validation, `3` policy/approval required, `4` compatibility, `5` unavailable/not found, `6` partial result, `7` external process failure, `8` store/corruption, `10` internal.
- The CLI never executes exported cURL commands.

## 3. Daemon discovery and lifecycle

`xtrace open`, `tui`, and other commands:

1. Resolve canonical project identity.
2. Read owner-only `daemon.json` from project data.
3. Validate PID, process start time, random port, daemon version, project ID, and challenge nonce.
4. Connect and authenticate; if validation fails, quarantine the stale record.
5. Start a daemon child only when no valid daemon exists.

The daemon exits after a configurable idle period only when it has no active runtime session, capture, plan execution, export delivery, migration, or connected keepalive client. Closing the browser alone does not terminate capture.

## 4. Shared client state

Client state is normalized and references server resources by ID:

```ts
type ClientState = {
  projectId: ProjectId;
  catalogRevisionId: CatalogRevisionId;
  operationQuery: OperationQuery;
  selectedOperationId?: OperationId;
  selectedRecordingId?: RecordingId;
  selectedFrameId?: FrameId;
  replayMode: 'canvas' | 'linear';
  replayFilter: ReplayFilter;
  playback: { state: 'paused'|'playing'; speed: number };
  sourceView: { followExecution: boolean; expandedValues: ValueBindingId[] };
  pendingCommands: Record<CommandId, CommandReceipt>;
  connection: ConnectionState;
};
```

Server resources are cached by `{kind,id,version}`. A WebSocket event invalidates or patches a resource only when its version is newer. On reconnect/resync, clients preserve local selection if the referenced recording/frame still exists.

Switching Canvas/Linear changes only `replayMode`. It does not reset operation, recording, frame, filters, playback position, or expanded values.

Playback requests navigation windows; it does not preload an unbounded recording. On play, the client prefetches the next window and pauses at a gap/error according to user preference.

## 5. Web design

The web application uses strict TypeScript and a generated API client. Its stable shell:

1. **Endpoint/scenario region:** catalog search, provenance/coverage, catalog revision, recordings.
2. **Execution region:** Canvas graph or compact Linear execution rail.
3. **Code-evidence region:** read-only source, active line, inline values/deltas, result, gaps.

### 5.1 Linear mode

- Source code is the central and widest region.
- Selecting or playing a frame moves an execution cursor to the exact source location.
- Captured bindings render directly under the active line; before/after deltas are visually distinct.
- Redacted, truncated, unavailable, and dropped values have different labels and explanations.
- The execution rail shows nearby frames, call depth, kind, duration, and gaps.
- When the source hash differs, live source is not highlighted as if it were recorded; the viewer shows a mismatch banner and recorded excerpt when available.

### 5.2 Canvas mode

- The graph is derived from observed frame/interaction structure, optionally overlaid with clearly dashed inferred alternatives.
- The same active `FrameId` highlights a node/edge and synchronizes the code inspector.
- Node movement is animation of selection/flow only; it never implies timing not present in the recording.
- Dense repeated calls collapse into summary nodes with counts and expand on request.
- Keyboard navigation reaches nodes, frames, playback, mode switch, and source without requiring pointer gestures.

### 5.3 Web module boundaries

```text
app-shell/
api/generated/
state/entities/
state/commands/
features/catalog/
features/recordings/
features/replay-core/
features/replay-linear/
features/replay-canvas/
features/source-evidence/
features/exercise/
features/exports/
features/settings/
```

`replay-core` owns navigation/state adapters and has no React Flow or CodeMirror dependency. Canvas and source components consume projections.

## 6. TUI design

The Ratatui application uses an Elm-like update loop:

```rust
fn update(model: &mut Model, message: Message) -> Vec<Effect>;
fn view(model: &Model, frame: &mut Frame);
```

Effects call the generated local client or application facade and return typed messages. Rendering is pure. Network/process/storage work never runs in the input loop.

Default layout:

```text
endpoint list | execution/call tree | source + values
status/help line
```

At narrow widths it becomes one pane with tabs while preserving selection. Keys are discoverable in a contextual footer; default bindings include `/` search, `j/k` navigation, arrows/Enter, Space play/pause, `[`/`]` previous/next frame, `i/o/u` into/over/out, `c` capture arm, `e` exercise/export menu depending context, and `?` help. All actions also have command-palette names so bindings can change later.

TUI snapshots cover 80x24, 120x40, and 200x60. Pseudo-terminal tests verify input, resize, color fallback, screen-reader-friendly plain mode, and reconnect.

## 7. Configuration schema

Repository `.xtrace/config.toml` example:

```toml
schema_version = 1

[project]
name = "checkout"
source_roots = ["src/main/java", "src"]

[[launch.profiles]]
name = "dev"
command = ["./gradlew", "bootRun"]
working_directory = "."
environment_allowlist = ["SPRING_PROFILES_ACTIVE"]

[capture]
application_packages = ["com.example.checkout"]
exclude_paths = ["**/generated/**"]
standard_method_frames = true
request_body = "off"
response_body = "off"

[capture.budgets]
max_value_depth = 4
max_collection_items = 25
max_string_bytes = 2048
max_event_bytes = 65536
max_recording_bytes = 16777216

[[redaction.rules]]
id = "common-secrets"
match_names = ["password", "token", "authorization", "cookie", "secret"]
action = "redact"

[exercise]
default_base_url = "http://127.0.0.1:8080"
allow_non_loopback = false
max_concurrency = 2
requests_per_second = 5
timeout_seconds = 10

[retention]
max_total_bytes = 5368709120
max_age_days = 30
max_recordings_per_operation = 20
```

Not permitted in repository configuration:

- API keys, passwords, bearer tokens, cookie values, private keys;
- arbitrary post-capture scripts;
- remote daemon binding;
- silent mutation approval;
- automatic scheduled runs/uploads.

Config JSON Schema is generated/tested alongside the TOML decoder. `xtrace config show` prints the effective sanitized config with provenance per field.

## 8. Endpoint exercise design

### 8.1 Candidate synthesis

Input priority per field:

1. explicit scenario file supplied for this plan;
2. sanitized observed example allowed by policy;
3. imported OpenAPI example/default/schema;
4. runtime/static type constraints;
5. unresolved placeholder requiring user input.

X-trace never invents credentials or claims random generated data is safe. Values record provenance.

### 8.2 Effect classification

```text
read_only_candidate: GET, HEAD, OPTIONS unless overridden by evidence/policy
mutating: POST, PUT, PATCH, DELETE and any explicitly classified mutation
unknown: ambiguous/custom method or conflicting evidence
```

Read-only is a candidate classification, not a guarantee. The review shows method, route, target, values, auth reference, prerequisites, expected status, and effect class.

### 8.3 Approval and execution

- Plan creation has no network effect.
- Approval covers the canonical plan hash and expires.
- Mutating/unknown items need item or policy-level explicit approval.
- Default repeat selection is new, changed, and never-observed operations.
- Execution enforces loopback, DNS re-resolution checks, redirect policy, concurrency, rate, timeout, request bytes, response bytes, and total duration.
- Credentials are resolved just in time and passed directly to the request builder; recordings see redacted placeholders.
- Every request has an exercise item ID linked to its recording.
- Redirects to non-loopback or disallowed hosts stop before transmission.

## 9. Export model

`ExportRequest` pins:

```text
project_id
catalog_revision_id
selected operations or all visible operations
recording-example policy
redaction policy ID/digest
base URL variable strategy
formats
output naming policy
```

Projection sorts operations by normalized route, method rank, and stable ID. JSON keys follow the target format's canonical order. Generated timestamps appear only in a separate manifest so repeated content from identical input hashes identically.

### 9.1 OpenAPI 3.1

- One path item per display route and operation per method.
- `operationId` is deterministic and collision-resolved from group, handler display name, method, and path; X-trace `OperationId` is stored in `x-xtrace-operation-id`.
- Path parameters are always declared and required.
- Schemas merge compatible claims and expose conflicts/unknowns rather than inventing certainty.
- Observed examples are included only when sanitized and allowed; inferred examples are labelled through vendor extensions and not represented as observed.
- Provenance, catalog revision, source confidence, and recording references use `x-xtrace-*` extensions.
- Security schemes may describe mechanism, never credentials.

### 9.2 Postman Collection v2.1

- Top folder is project; second level uses configured endpoint group/resource.
- Each operation becomes one request with named placeholders for unresolved values.
- Base URL is `{{baseUrl}}`; non-secret shared variables may be emitted, secret values never are.
- Sanitized observed scenarios become examples with recording/provenance descriptions.
- Request names remain stable across exports when operation identity is stable.
- The collection description records catalog revision and policy digest.

### 9.3 cURL

```text
curl/
  README.md
  env.example
  orders/
    post-orders.sh
    get-orders-id.sh
  all.sh
```

- Scripts use portable POSIX shell unless a platform-specific bundle is selected.
- Values are safely shell-quoted; secrets remain `${XTRACE_...}` placeholders.
- Mutating commands contain a warning comment and are not included in executable `all.sh` by default.
- `all.sh` prints commands by default; `--execute` is deliberately not generated in v1.

### 9.4 Developer bundle

Contains `openapi.yaml`, Postman collection, cURL folder, `manifest.json`, and a human-readable `README.md` explaining provenance and omissions. It does not contain trace objects or source snapshots.

## 10. Open in Postman

1. User selects Open in Postman.
2. X-trace creates a local preview export and displays exact operations/examples/omissions.
3. If not connected, user supplies a Postman API key to an OS-credential-store flow; the browser never receives it again.
4. X-trace lists accessible workspaces using the official API.
5. User chooses workspace and create-new or update-known collection.
6. Daemon sends Collection v2.1 to the official API and stores only workspace ID, collection ID, URL, revision, and response receipt metadata.
7. The OS opens the official returned collection URL. The installed Postman app may claim it; otherwise Postman Web opens.

Retrying the same export/workspace/collection uses an idempotent delivery record. A failed upload leaves the local export ready. No upload happens during ordinary export, capture, scan, or app launch.

## 11. Verification pyramid

### 11.1 Domain/property tests

- operation normalization equivalence and collision cases;
- claim-order-independent reconciliation;
- complete vs incomplete scan removal behavior;
- state-machine legal/illegal transitions;
- replay navigation over recursion, async branches, gaps, and filters;
- value-state exhaustiveness;
- exercise approval invalidation on any relevant mutation;
- deterministic exports independent of insertion order.

### 11.2 Store tests

- migration from every released schema;
- crash injection at each segment commit step;
- WAL recovery and stale session finalization;
- content hash corruption/quarantine;
- concurrent readers/single writer;
- retention with shared objects and pins;
- source hash match/mismatch behavior.

### 11.3 Protocol tests

- Rust/Java/Node golden encode/decode;
- version/capability negotiation;
- duplicate, gap, retransmit, partial success;
- throttle ladder and drop priority;
- authentication replay/expiry/wrong pin;
- decompression bomb and size limits;
- malicious strings/paths/IDs.

### 11.4 Real runtime fixtures

Each framework fixture exposes at least:

- simple success;
- validation failure;
- nested service/repository;
- exception path;
- async/reactive path;
- database call;
- outbound HTTP call;
- dynamic/ambiguous route where applicable;
- secret-bearing input proving redaction;
- standard and focused capture.

Java fixtures run launch and supported attach cases. Node fixtures run CJS, ESM, TypeScript/source-map, worker/child-process, and supported packaging cases.

### 11.5 Product journeys

Release evidence must exercise the actual packaged product:

1. install `xtrace` on a clean machine/profile;
2. initialize a sample repository;
3. scan and see inferred routes labelled correctly;
4. launch Java and Node apps through X-trace;
5. attach to a compatible already-running JVM and see exact limitations;
6. send a real request and observe a new recording;
7. replay it in web Linear mode with central code/inline values;
8. switch to Canvas without losing the frame;
9. replay the same recording in TUI;
10. encounter redacted/unavailable/gap/source-mismatch states;
11. create, review, approve, and run a safe exercise plan;
12. export OpenAPI, Postman, cURL, and developer bundle;
13. connect/publish to a Postman test workspace only in an explicit integration test account;
14. restart after forced daemon/adapter crashes and inspect partial evidence;
15. upgrade a previous store fixture and retain replay correctness.

Green unit/build/API checks without these observable journeys are insufficient release evidence.

## 12. Usability validation

The Product gate metric becomes a repeatable study:

- participants have not used the sample codebase;
- half begin from web and half from TUI/CLI before opening web;
- timer begins at the repository and X-trace instructions;
- task: select a named endpoint and explain entry, meaningful intermediate call, final response/failure, and database/outbound interaction when present;
- no breakpoints or IDE debugger configuration;
- success must be grounded in one observed recording, with inferred-only claims identified correctly;
- target: at least 80% correct within 10 minutes;
- failures are categorized as install/start, endpoint discovery, provenance confusion, navigation, code/value comprehension, or missing capture evidence.

The study records no source/value payloads outside the local test environment.

## 13. Release readiness checklist

- compatibility matrix generated from current fixture receipts;
- performance budgets green or capability downgraded;
- no privacy canary present in database, objects, logs, API snapshots, browser state, or exports;
- schema/API/protocol breaking checks green;
- upgrade/recovery fixtures green;
- packaged Java and Node journeys green on supported OSes;
- web keyboard/accessibility and TUI pseudo-terminal journeys green;
- SBOM, signatures, license report, notices, and checksums produced;
- documentation lists supported/preview/unknown combinations and attach limitations exactly;
- the 10-minute usability study meets the Product gate target before general availability.
