# Gate 3 Appendix B: Protocols and Client API

**Status:** approved with Gate 3 on 2026-09-28  
**Purpose:** specify XTP-Agent transport, message behavior, backpressure, XTP-Client HTTP/WebSocket semantics, authentication, pagination, and compatibility.

## 1. Schema ownership

`schema/xtp-agent` is the source of truth for adapter traffic. `schema/xtp-client/openapi.yaml` is the source of truth for browser/CLI client traffic. Generated Rust, Java, and TypeScript files are committed only when their generator version is pinned; CI regenerates and fails on drift.

The domain never imports generated types. Translation modules validate wire input and construct domain values.

## 2. XTP-Agent transport

### 2.1 Connection bootstrap

Launch bootstrap contains:

```text
daemon host/port
ephemeral certificate SHA-256 pin
runtime_session_id
256-bit session secret or owner-readable secret-file path
project_id
maximum protocol major/minor offered by daemon
```

- Java launch receives the bootstrap through an owner-readable temporary properties file referenced by the `-javaagent` argument.
- Java attach writes the same material to an owner-readable file and passes only the path in agent arguments.
- Node launch receives file paths and non-secret identifiers through environment variables; the secret is read from the owner-only file and removed from `process.env` after bootstrap.
- Bootstrap files expire, are deleted after negotiation, and are never copied to diagnostics.

The socket is loopback TCP with TLS 1.3. The adapter pins the ephemeral daemon certificate. After TLS establishment, the adapter proves the session secret in `AdapterHello`; the daemon proves transcript possession in `DaemonHello`. A connection that fails any step receives no project metadata.

### 2.2 Framing and limits

- Four-byte unsigned big-endian message length followed by one Protobuf `AgentEnvelope`.
- Default maximum envelope: 1 MiB; hard maximum: 8 MiB negotiated only for controlled source metadata, never values.
- Keepalive is `Health` every 10 seconds while idle; three missed intervals mark the connection unhealthy.
- Compression is negotiated per `EventBatch`; small control messages remain uncompressed.
- The daemon acknowledges the highest contiguous `session_seq` made durable or safely staged.

### 2.3 Envelope

```proto
message AgentEnvelope {
  uint32 protocol_major = 1;
  uint32 protocol_minor = 2;
  bytes runtime_session_id = 3;
  uint64 session_seq = 4;
  fixed64 sent_monotonic_ns = 5;
  string message_id = 6;
  oneof payload {
    AdapterHello adapter_hello = 20;
    CapabilitySet capability_set = 21;
    EndpointClaimBatch endpoint_claims = 22;
    StaticPathBatch static_paths = 23;
    RecordingStarted recording_started = 24;
    EventBatch event_batch = 25;
    RecordingFinished recording_finished = 26;
    DropNotice drop_notice = 27;
    Health health = 28;
    Ack ack = 40;
    Throttle throttle = 41;
    CaptureCommand capture_command = 42;
    ProtocolError protocol_error = 43;
  }
}
```

`session_seq` begins at 1 after authentication. Hello messages are part of the authenticated transcript but not the durable event sequence.

### 2.4 Handshake

`AdapterHello` includes:

- adapter name/version/build hash/signing identity;
- language and runtime name/version;
- process ID, process start identity, parent launch ID;
- project/repository fingerprint;
- offered protocol range;
- manifest digest;
- random client nonce;
- HMAC over the TLS exporter, runtime session, nonces, and manifest digest.

`DaemonHello` returns:

- selected protocol major/minor;
- daemon version;
- accepted manifest digest;
- random server nonce and proof;
- maximum envelope/batch sizes;
- initial `CapturePolicy` and `RedactionPolicyDigest`;
- clock-synchronization sample;
- a capability acceptance/rejection list.

The adapter sends `CapabilitySet` after hello. Capabilities are granular and may include constraints:

```text
endpoint_discovery(runtime|static)
launch
attach(retransform_loaded_classes: bool)
method_frames(package_filters)
line_cursor(debug_metadata_required: bool)
locals(debug_metadata_required: bool, max_depth)
async_correlation(kind[])
database_interaction(driver[])
outbound_http(client[])
source_maps(kind[])
retransmit(window_batches)
```

Capabilities are a historical snapshot on the runtime session; clients never infer them from adapter name.

## 3. Discovery messages

`EndpointClaimBatch` contains a complete-or-incremental flag and typed claims:

```proto
message EndpointClaim {
  string claim_id = 1;
  HttpOperationKey operation = 2;
  ClaimProvenance provenance = 3;
  HandlerRef handler = 4;
  repeated SourceRange source = 5;
  repeated ParameterClaim parameters = 6;
  repeated MediaTypeClaim consumes = 7;
  repeated MediaTypeClaim produces = 8;
  repeated SecurityClaim security = 9;
  Confidence confidence = 10;
  repeated Limitation limitations = 11;
  bytes claim_digest = 12;
}
```

`StaticPathBatch` references operation claim IDs and emits graph nodes/edges with reason codes. It cannot contain a recording ID or observed provenance.

Batch acceptance returns accepted/rejected counts and per-item errors. One malformed claim does not discard unrelated valid claims unless the batch declared itself atomic.

## 4. Recording messages

### 4.1 Recording start

`RecordingStarted` is structural and highest priority:

```text
recording_id
recording_seq = 1
request identity: method, matched template if known, sanitized URL shape
operation candidate IDs and match evidence
request start monotonic time
thread/task and async context
capture policy ID/digest
redaction policy digest
source revision/fingerprint
```

If the operation is unknown, the daemon records first and reconciles it after runtime discovery. It never discards a request only because a catalog entry is absent.

### 4.2 Event batch

Each event has `event_id`, `recording_seq`, `parent_event_id`, optional async parent, monotonic time, priority, kind, source, symbol, and kind-specific payload.

Kinds:

- `REQUEST_UPDATE`
- `FRAME_ENTER`, `FRAME_EXIT`, `FRAME_THROW`
- `LINE_CURSOR`
- `VALUE_SNAPSHOT`
- `DATABASE_START`, `DATABASE_END`
- `OUTBOUND_HTTP_START`, `OUTBOUND_HTTP_END`
- `ASYNC_LINK`
- `EXCEPTION`
- `RESPONSE`
- `GAP`

Value payloads must already be in the captured-value union; raw arbitrary object graphs are not a protocol type.

### 4.3 Finish

`RecordingFinished` includes final sequence, response/error summary, adapter-observed duration, drop counters by priority, unsupported capability gaps, and a digest over all emitted event IDs/digests. The daemon compares this with accepted data before finalization.

## 5. Ack, retransmission, throttle, and degradation

`Ack` reports:

```text
highest contiguous session_seq
highest contiguous recording_seq per active recording
durability = staged | committed
rejected message IDs with stable reason codes
```

Adapters keep a bounded retransmission ring. Only control/structural messages must be retained until committed; optional detail can expire with a `DropNotice`.

Throttle levels:

| Level | Adapter behavior |
|---|---|
| 0 | configured policy |
| 1 | increase batching; suppress duplicate line cursors and unchanged values |
| 2 | stop value snapshots except exceptions/results; retain method and interaction frames |
| 3 | retain request lifecycle, errors, interactions, and drop notices only |
| 4 | refuse new recordings; finish active recordings as partial |

Every level change is recorded in session diagnostics. Recovery from throttling is hysteretic to prevent oscillation.

The adapter's application-thread enqueue is non-blocking after a very small bounded wait budget. Failure creates or increments a coalesced `DropNotice`; the recorder never recursively traces its own transport work.

## 6. Capture commands

Daemon-to-adapter `CaptureCommand` is authenticated and monotonic by command sequence:

- `UPDATE_STANDARD_POLICY`
- `ARM_FOCUSED_CAPTURE`
- `DISARM_FOCUSED_CAPTURE`
- `STOP_ACCEPTING_RECORDINGS`
- `FLUSH_AND_CLOSE`
- `REQUEST_DISCOVERY_SNAPSHOT`
- `REQUEST_RETRANSMIT`

Focused capture includes operation selectors, package/file allowlists, next-match count, expiry, line/value budgets, and an approval/run reference. An adapter rejects unsupported or unsafe commands with a stable reason; it never silently broadens the scope.

## 7. XTP-Client authentication

- CLI/TUI direct mode uses an owner-only daemon discovery record and per-daemon client token.
- Browser opening creates a single-use 256-bit bootstrap token valid for 60 seconds.
- The token is placed in the URL fragment, exchanged at `POST /auth/exchange`, and immediately removed from browser history using `history.replaceState`.
- Successful exchange creates a same-site strict, HTTP-only cookie scoped to the random daemon origin.
- Mutating requests require an anti-CSRF token delivered in the bootstrap response and sent in a header.
- Host and Origin must match the daemon's explicit loopback origin. No wildcard CORS.

## 8. HTTP API conventions

Base path: `/api/v1`. JSON uses lower camel case. IDs are strings. Unknown response fields are ignored by clients; unknown request fields are rejected.

Every response includes `X-XTrace-Request-Id`. Mutations accept `Idempotency-Key`. Errors use `application/problem+json`:

```json
{
  "type": "https://x-trace.dev/problems/XTR-ATTACH-DYNAMIC-DISABLED",
  "title": "The JVM does not allow dynamic agent loading",
  "status": 409,
  "code": "XTR-ATTACH-DYNAMIC-DISABLED",
  "retry": "after_relaunch",
  "correlationId": "...",
  "remediation": [
    {"kind":"command", "label":"Relaunch with X-trace", "commandRef":"launch_01"}
  ]
}
```

Commands return `202 Accepted` with a run/command receipt when asynchronous, or `200/201` only when the requested result is durable.

Pagination uses opaque signed cursors with a stable sort. A cursor is invalid if filters or sort change. Default/max page sizes are 50/200.

## 9. HTTP resources

### 9.1 Project and health

```text
GET    /health
GET    /project
PUT    /project/policy
GET    /capabilities
GET    /language-packs
POST   /doctor/preview
POST   /doctor/bundles
```

### 9.2 Runs and catalog

```text
POST   /runs/scan
POST   /runs/launch
POST   /runs/attach
POST   /runs/{runId}/cancel
GET    /runs
GET    /runs/{runId}

GET    /catalog/revisions
GET    /catalog/revisions/{revisionId}
GET    /catalog/compare?from=&to=
GET    /operations?revision=&status=&method=&query=&cursor=
GET    /operations/{operationId}?revision=
GET    /operations/{operationId}/recordings?cursor=
```

### 9.3 Recording and replay

```text
GET    /recordings/{recordingId}
GET    /recordings/{recordingId}/graph
GET    /recordings/{recordingId}/frames?fromOrdinal=&limit=&kinds=
GET    /recordings/{recordingId}/frames/{frameId}
GET    /recordings/{recordingId}/navigate?frame=&action=next|previous|into|over|out
GET    /recordings/{recordingId}/source/{sourceArtifactId}?startLine=&endLine=
POST   /operations/{operationId}/focused-captures
DELETE /focused-captures/{armId}
```

`frames` returns a window and navigation hints, not the entire recording. `graph` returns summarized nodes/edges with references to frame windows.

### 9.4 Exercise

```text
POST   /exercise/plans
GET    /exercise/plans/{planId}
POST   /exercise/plans/{planId}/approve
POST   /exercise/plans/{planId}/reject
POST   /exercise/plans/{planId}/execute
```

Creation never executes. Approval submits the exact plan hash. Execution fails if approval is absent, expired, or for a different hash.

### 9.5 Export and Postman

```text
POST   /exports/preview
POST   /exports
GET    /exports/{exportId}
GET    /exports/{exportId}/files/{fileId}
POST   /integrations/postman/connect
GET    /integrations/postman/workspaces
POST   /exports/{exportId}/deliveries/postman
```

`connect` begins a local credential-store flow; no API key is returned to the browser. Delivery consumes an already-ready local export.

### 9.6 Retention

```text
POST   /retention/previews
POST   /retention/applications
GET    /retention/applications/{runId}
```

The apply call includes the preview digest; a changed candidate set requires a new preview.

## 10. WebSocket events

Endpoint: `/api/v1/events`. The client sends a subscribe message with project ID, event types, and optional run/session/operation filters.

Envelope:

```json
{
  "eventId": "...",
  "sequence": 1842,
  "occurredAt": "2026-09-28T12:00:00.000000Z",
  "type": "recording.available",
  "resource": {"kind":"recording", "id":"...", "version":1},
  "data": {}
}
```

Types:

- `daemon.healthChanged`
- `run.changed`
- `catalog.revisionCreated`
- `operation.coverageChanged`
- `runtimeSession.changed`
- `recording.started`, `recording.progress`, `recording.available`
- `focusedCapture.changed`
- `exercisePlan.changed`
- `export.changed`
- `store.warning`

Only durable-state events claim availability. Progress events are coalescible. Reconnect provides the last seen sequence; if the replay buffer no longer covers it, the server sends `resyncRequired` and clients re-query affected resources.

## 11. API view models

View models include explicit evidence and capability fields:

```text
OperationSummary
  id, method, displayRoute, group, lifecycle
  evidenceStates[], currentRevisionId
  recordings: completeCount, partialCount, latestAt
  captureEligibility and reason

RecordingSummary
  id, status, startedAt, duration, sourceRevision
  adapter/runtime/framework facts
  frameCount, interactionCount, gapCount
  capabilities and limitations

FrameView
  id, position, kind, parent, asyncParent
  symbol, source, values[], result
  evidence, gaps[], navigation
```

No view model has a generic `status: string` or untyped `metadata` escape hatch for core semantics.

## 12. Compatibility tests

- Protobuf breaking-change checks reject field-number reuse, required semantic changes, and enum value renumbering.
- Golden envelopes are encoded/decoded by Rust, Java, and Node implementations.
- Current daemon tests current and previous supported adapter minor versions.
- Current web client tests current daemon API; a version mismatch page gives the exact compatible CLI version.
- API consumer-driven contracts run identical application scenarios through the in-process facade and HTTP adapter.
- Fuzz tests target framing, length limits, unknown fields, invalid UTF-8 boundary conversion, sequence gaps, duplicate IDs, decompression limits, and malformed value unions.
