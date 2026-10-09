# ADR 0003: Runtime line, value and outcome probes (Java and Node)

- Status: Accepted (root decision 2026-10-04)
- Date: 2026-10-04
- Context: The approved plans promise active-line cursors, bounded argument,
  return and local values, and the actual recording outcome
  (`docs/plans/x-trace/02-architecture.md` "Capture model",
  `03c-runtime-adapters.md` §3.7, §3.8, §4.7, §4.8; v0.01 mandate lines
  126-135). No approved contract fixes the instrumentation technique, the
  wire additions, the budgets, or the honesty rules, and the current Java
  agent can only emit hard-coded fixture frames. This ADR is the proposed
  Gate 3 amendment AGENTS.md requires before shared protocol, domain and
  replay semantics change. It does not supersede any plan sentence except
  where "Supersession" below says so.

## Decision

### 1. Vocabulary

- **Probe site**: a compile-time-known observation point (a Java
  `LineNumberTable` entry, a method entry/exit, a JavaScript statement or
  function boundary). Sites are numbered per class/module; the number never
  carries application data.
- **Observation**: one event emitted when a probe site executes inside an
  active recording. An observation is evidence that the site executed. The
  absence of an observation is never evidence that a line did not execute.
- **Mode**: `standard` (default background capture) or `focused` (armed by
  `CaptureCommand.ARM_FOCUSED_CAPTURE` for Java, or chosen at launch for
  Node, see section 3.6).
- **Value state**: exactly one of the five existing `CapturedValue` states
  (`captured`, `redacted`, `truncated`, `unavailable`, `dropped`). No sixth
  state and no empty-string stand-in is introduced.

### 2. Java

#### 2.1 Scope: application code only

The launcher (`xtrace run`/`xtrace attach`) computes an `ApplicationScope`
before the agent starts and delivers it in the private bootstrap material:

```text
application_packages[]   package prefixes, e.g. "com.acme.orders."  (max 64)
application_roots[]      canonical directories/jars that hold project classes (max 32)
source_roots[]           repository-relative source directories (max 32)
deny_packages[]          extra user denials (max 64)
```

Derivation order: (1) explicit `--app-package` / project configuration;
(2) a build-output scan of the project (Maven `target/classes`, Gradle
`build/classes/**/main`, a Spring Boot `BOOT-INF/classes/` layout of the
project's own artifact) that collects the top-level package prefixes of
classes physically under `application_roots`; (3) if neither yields a
prefix, no application class is transformed and the session reports
`line_cursor: unavailable` with limitation `handler_unresolved`. Dependency
jars (`BOOT-INF/lib/**`, `~/.m2`, `~/.gradle`) are never application roots.

A class is transformable only when **all** hold: its binary name starts with
an `application_packages` prefix; its `ProtectionDomain` code source is under
an `application_roots` entry (or the nested `BOOT-INF/classes/` entry of a
project-owned executable jar); it is not in the always-deny set; it is
modifiable. The always-deny set cannot be overridden by configuration:
`java.`, `javax.`, `jakarta.`, `jdk.`, `sun.`, `com.sun.`, `org.springframework.`,
`org.apache.`, `org.hibernate.`, `net.bytebuddy.`, `dev.xtrace.`, and any
class whose name contains `$$`, `CGLIB`, `ByteBuddy`, `$Proxy`, or that is a
hidden/lambda-form class. Framework boundaries are instrumented only by a
reviewed framework module (ADR 0005), never by this scope rule.

#### 2.2 Mechanism

Byte Buddy `AgentBuilder` (already in use, `FixtureInstrumentation.java:34-38`)
installs two kinds of transformation per in-scope class:

- **Method boundary probes** with `Advice` (`@OnMethodEnter`,
  `@OnMethodExit(onThrowable = Throwable.class)`): `FRAME_ENTER`,
  `FRAME_EXIT`, `FRAME_THROW`, and the sanitized argument, return and
  exception summaries.
- **Line probes** with an `AsmVisitorWrapper` over Byte Buddy's repackaged
  ASM, because `Advice` cannot insert code at interior line boundaries. A
  probe is inserted at the label of every `LineNumberTable` entry of a
  non-synthetic, non-bridge method (lambda bodies `lambda$...` are included
  because their lines belong to application source). Only `invokestatic` of
  bootstrap-visible `BootstrapBridge` methods taking constants and
  already-live locals is emitted. No field, method, or class is added, so
  `disableClassFormatChanges()` and `RedefinitionStrategy.RETRANSFORMATION`
  (for `agentmain`) remain valid. Stack effect is neutral at every inserted
  point; frames are not recomputed (`COMPUTE_MAXS` only) so existing
  `StackMapTable` entries stay valid.

Probe call shape (all primitives, no allocation on the application thread):

```text
BootstrapBridge.line(int siteId)                       // LINE_CURSOR
BootstrapBridge.valuesBegin(int siteId)                // focused only
BootstrapBridge.valueInt/Long/Float/Double(int slot, int nameId, <prim> v)
BootstrapBridge.valueRef(int nameId, int role, Object v)
BootstrapBridge.valuesEnd()
```

`siteId` is resolved by the private runtime through a registry populated at
transform time: `(classDigest, methodName, descriptor, line, nameIds[])`,
where `classDigest` is the BLAKE3-256 of the `classfileBuffer` bytes
presented to the transformer (the existing `SourceAttestation` input).

#### 2.3 What is observed and when

- Entry/exit/exception probes: always on for in-scope methods in both modes.
- `LINE_CURSOR`: installed in both modes. A line probe is a no-op unless a
  recording is active on the thread. Emission is limited by the per-recording
  line budget (section 5). The observation means "execution reached the first
  instruction of this line table entry"; it carries no claim about the
  instruction before it.
- Values captured at line boundaries are the state **on arrival at** the
  line, i.e. before the line's instructions execute. A "delta" shown by a
  client is the difference between two recorded arrivals; it is never labelled
  an assignment.
- Locals (focused mode only): a local is read at a probe only if a
  `LocalVariableTable` entry for that slot covers the probe's bytecode offset
  (`start_pc <= offset < start_pc + length`). javac ranges begin after the first
  store, so no uninitialized slot is read and the verifier accepts the code.
  Without a `LocalVariableTable` for the method, the frame carries one binding
  with `Unavailable{DEBUG_METADATA_ABSENT}` per declared parameter (names
  `arg0..argN`, role `ARGUMENT`) and a method-level limitation
  `no_local_variable_table`.
- Arguments and return values: always (both modes) as sanitized bounded
  summaries. Names come from `MethodParameters`, else the `LocalVariableTable`,
  else `arg<N>` with `name_origin = SYNTHESIZED`, which the UI shows verbatim
  and never as a source-declared name.
- Exceptions: a thrown exception is observed only when it leaves an
  instrumented method (`FRAME_THROW`). An exception caught inside the same
  method is not observed and is never inferred.

#### 2.4 Source identity

`RecordingEvent.source_binding` and `SourceRange.content_hash` (already on
the `java-evidence` lineage, field 13 / field 6) are extended:

| `SourceBinding` | Meaning |
|---|---|
| `VERIFIED` (1) | Build attestation matched the observed class bytes (existing). |
| `ATTESTATION_MISSING` (2) .. `SOURCE_METADATA_INVALID` (5) | Existing. |
| `OBSERVED_UNATTESTED` (6, new) | Path derived from `SourceFile` + package against `source_roots`; hash is the BLAKE3-256 of that file read at class-load time. No claim that the class was compiled from those bytes. |
| `SOURCE_MAP_ABSENT` (7, new) | Node: no map for a transformed file; positions are generated-file positions. |
| `SOURCE_MAP_UNRESOLVED` (8, new) | Node: map present but its `sources` entry could not be resolved to a readable repository file. |

General Java apps (the six campaign projects) have no build attestation, so
they record `OBSERVED_UNATTESTED`; clients must render it as "source as read
when the class loaded", not as verified. A line whose number exceeds the file's
line count, or whose `SourceFile` name differs from the resolved file name,
downgrades to `SOURCE_METADATA_INVALID`.

### 3. Node.js

#### 3.1 Loading

A single `@xtrace/loader` module calls `module.registerHooks({ resolve, load })`
(synchronous, in-thread; Node 22.15+ and 24). It is registered idempotently
(guarded by `Symbol.for("xtrace.loader.v1")`) from both existing launch forms,
`--require` for CommonJS and `--import` for ESM
(`crates/xtrace-runtime/src/node.rs:216-217` on `slice/v001-node-capture`), so
one hook set covers `require()` and `import` regardless of entry style.
`registerHooks` is feature-detected. If it is absent (Node < 22.15), the
session advertises `source_transform: unavailable` with limitation
`unsupported_mapping`; HTTP-boundary capture (already present) continues.
Because the API's stability is below "stable" in the supported lines, each
supported Node patch release is pinned by a conformance run (section 8).

#### 3.2 Scope

The `load` hook transforms a module only when: the URL is `file:`; its realpath
is under a configured `capture_roots` entry (default: the repository root);
no path segment of the realpath is `node_modules` (a workspace package
symlinked into `node_modules` is included only when its realpath is under
`capture_roots`); it is not `node:`, `data:`, `eval`, X-trace code, or matched by
a policy-deny glob; its source is at most 1 MiB; and it does not look minified
or bundled (average line length > 2000 bytes). Anything skipped is recorded
once per file as limitation `generated_source_skipped` or `scan_budget_exceeded`
and the original source is returned unchanged.

#### 3.3 Transform

Statement-level probes in the style of Istanbul, implemented with `acorn`
(parse) and `magic-string` (edit + map). Both are MIT and are bundled and
version-pinned inside the pack, not added to the user's `package.json`.

- A probe `__xt.l(<siteId>)` is inserted before each statement
  (expression, declaration, `return`, `throw`, `if`/loop/`switch` heads);
  non-block bodies are wrapped in blocks; an arrow function with an expression
  body becomes `(__xt.l(id), expr)`. Directive prologues stay first.
- Function boundary probes wrap the body: enter, `finally`-style exit, and
  throw (`FRAME_ENTER/EXIT/THROW`).
- The runtime handle is read once per module from
  `globalThis[Symbol.for("xtrace.rt.v1")]`; the local alias name carries a
  per-module suffix to avoid collisions.
- Files containing `with`, direct `eval` in sloppy mode, or syntax the
  parser rejects are skipped (limitation `unsupported_mapping`), not guessed.
- The output is re-parsed before it is returned. Any failure returns the
  original source and records the limitation. Application behavior must not
  depend on whether the transform ran.

#### 3.4 Source maps

If a file has an input map (`//# sourceMappingURL` as `data:` URI or a
sibling `.map`, resolved inside `capture_roots`), the output map is composed
(`@jridgewell/remapping`, MIT) so every probe resolves to authored (TypeScript)
path and line. `SourceRange.path` is the repository-relative authored path and
`content_hash` is the BLAKE3-256 of that authored file at transform time. Node's
native TypeScript type stripping (`.ts` loaded with format `*-typescript`)
preserves positions and is recorded as an identity map. The adapter does not
call `process.setSourceMapsEnabled` and does not alter `Error.stack`
formatting; it maps stack frames in its own sanitizer from tables it already
holds, and frames it cannot map are emitted as generated positions with
`SOURCE_MAP_UNRESOLVED`.

#### 3.5 Async context

`AsyncLocalStorage<RecordingContext>` (already entered at the HTTP root,
`http-capture.cts:114`) is read by every probe. Promise continuations and
timers inherit it. Worker threads and child processes create separate runtime
sessions linked by launch metadata; an unrecognized cross-boundary transition
emits `GAP{CORRELATION_LOST}` and capture resumes only at a boundary that
restores identity.

#### 3.6 Modes in Node

Node cannot retransform an already-loaded module (03c §4.7). Therefore the mode
is chosen at launch (`--capture-depth standard|focused`):

- `standard`: function boundary probes plus statement line probes without
  value thunks; line emission is budgeted like Java.
- `focused`: additionally, `__xt.v(siteId, () => [a, b, c])` after the line
  probe, where the thunk lists only bindings that are definitely initialized at
  that point (parameters; `var`/`let`/`const` declared by an earlier statement
  of a lexically enclosing block; never class or switch-case-scoped lexical
  bindings, which can be in the temporal dead zone). The runtime calls the thunk
  inside `try/catch`; a throw becomes `Unavailable{UNSAFE_TO_RENDER}`.
- "Arming later" means relaunching; the UI states this instead of implying a
  live change.

#### 3.7 Node value rendering

The sanitizer never invokes getters, `toString`, `toJSON`, `util.inspect.custom`,
or Proxy traps (`util.types.isProxy` => unavailable). Data properties only,
via `Object.getOwnPropertyDescriptor`. `Buffer`/typed arrays render as
type/length/BLAKE3 only. Streams, sockets, request/response objects, functions,
promises: shape summary only.

### 4. Wire and domain additions

All field numbers are chosen to follow the `slice/v001-java-evidence`
lineage (which already allocated `RecordingEvent.source_binding = 13` and
`SourceRange.content_hash = 6`). The integration base must include that
lineage before this ADR's proto change lands; if it does not, root renumbers
before merge. Additions are additive only (proto breaking-change check must
stay green).

```proto
// recording.proto
message RecordingEvent {
  // existing 1..13
  repeated ValueBinding bindings = 14;   // values observed at this event
  GapPayload gap = 15;                   // set only when kind == GAP
}

message ValueBinding {
  string name = 1;                       // <= 128 UTF-8 bytes
  BindingRole role = 2;
  NameOrigin name_origin = 3;
  CapturedValue value = 4;               // never absent; use unavailable/dropped
}
enum BindingRole { BINDING_ROLE_UNSPECIFIED = 0; BINDING_ROLE_ARGUMENT = 1;
  BINDING_ROLE_RETURN = 2; BINDING_ROLE_LOCAL = 3; BINDING_ROLE_EXCEPTION = 4;
  BINDING_ROLE_RECEIVER = 5; }
enum NameOrigin { NAME_ORIGIN_UNSPECIFIED = 0; NAME_ORIGIN_DECLARED = 1;
  NAME_ORIGIN_SYNTHESIZED = 2; }

message GapPayload { GapReason reason = 1; uint64 count = 2;
  uint64 first_recording_seq = 3; uint64 last_recording_seq = 4; }
enum GapReason { GAP_REASON_UNSPECIFIED = 0; GAP_REASON_LINE_BUDGET = 1;
  GAP_REASON_VALUE_BUDGET = 2; GAP_REASON_THROTTLE = 3; GAP_REASON_QUEUE_FULL = 4;
  GAP_REASON_CORRELATION_LOST = 5; GAP_REASON_CLASS_NOT_TRANSFORMED = 6;
  GAP_REASON_MODULE_LOADED_BEFORE_ARM = 7; GAP_REASON_SOURCE_MAP_ABSENT = 8;
  GAP_REASON_HANDLED_EXCEPTION_UNOBSERVED = 9; }

message RecordingFinished {
  // existing 1..7
  RecordingOutcome outcome = 8;
}
message RecordingOutcome {
  OutcomeKind kind = 1;
  uint32 http_status = 2;                // 0 = not observed
  ExceptionPayload exception = 3;        // set for EXCEPTION_PROPAGATED
  string thrown_from_event_id = 4;       // frame that last observed the throw
}
enum OutcomeKind { OUTCOME_KIND_UNSPECIFIED = 0; OUTCOME_KIND_RESPONDED = 1;
  OUTCOME_KIND_EXCEPTION_PROPAGATED = 2; OUTCOME_KIND_CLIENT_ABORTED = 3;
  OUTCOME_KIND_UNOBSERVED = 4; }
```

Additional enum values: `UnavailableReason` += `FOCUSED_CAPTURE_NOT_ARMED = 6`,
`UNSAFE_TO_RENDER = 7`, `CLASS_NOT_TRANSFORMABLE = 8`; `DropReason` +=
`THROTTLE_SUPPRESSED = 5`, `LINE_BUDGET = 6`, `VALUE_BUDGET = 7`.
`CaptureCommand` gains `uint32 max_line_events = 8; uint64 max_value_bytes = 9;
bool include_locals = 10;` (03b §6 already requires line/value budgets but the
message omits them).

Existing fields reused unchanged: a `LINE_CURSOR` event is
`kind = LINE_CURSOR`, `source.start_line == source.end_line`, and a
`source_binding`; a `FRAME_*` event carries `symbol` and `source` (method
extent); `RESPONSE` keeps its status in `symbol`/`interaction` for older readers,
and `RecordingOutcome.http_status` is authoritative.

Mapping to domain (shared contract, root-controlled): `Frame.kind = Line` for
`LINE_CURSOR`; `Frame.values: Vec<ValueBinding>` (already present,
`recording.rs:131-160`) from `bindings`; `Frame.result` from the `RETURN`
binding; `FrameSource` from `source`; a `Gap` frame from `GapPayload`. The
domain `UnavailableReason`/`DropReason` enums (`value.rs:20-86`) gain the
variants above.

Mapping to store: XTF segments embed `RecordingEvent` verbatim
(`schema/proto/xtf/v1/segment.proto`, `XtfEventEnvelope.event`), so events carry
the new fields with no event migration. Two existing limits need a root decision
(see Open questions): the per-recording event cap of 2,048
(`crates/xtrace-application/src/recording.rs:16`,
`crates/xtrace-ingest/src/validator.rs:84`, and the
`recording_terminal_evidence.event_count <= 2048` CHECK in migration
`v0004` on `slice/v001-shared-replay`), and the read projection
`PersistedEvent` (`recording_queries.rs:110-129`), which today has no
source/values and reports `UnavailableEvidence{source, values, completion}` as
`"unavailable"`; it gains `source`, `source_binding`, `bindings[]`, `gap`.

### 5. Budgets (bench defaults; every limit is configuration with a tested default)

| Limit | standard | focused |
|---|---:|---:|
| Max value preview per binding | 256 bytes | 512 bytes |
| Bindings per event | 16 | 32 |
| Container depth / elements / object fields read | 2 / 16 / 8 | 3 / 32 / 16 |
| Bytes per event (all bindings) | 4 KiB | 16 KiB |
| Line events per recording | 1,024 | 8,192 |
| Value bytes per recording | 256 KiB | 4 MiB |
| Exception message | 512 bytes | 512 bytes |
| Request-thread enqueue budget | p99 <= 200 us (03 §10) | same |

Priorities (lower is shed first, matching 03 §6): local values 10, argument and
return values 15, `LINE_CURSOR` 20, `FRAME_*` 30, interactions 40, exception and
outcome 50, request/lifecycle/structural 60.

**Sampling never silently drops.** v0.01 has no probabilistic sampling. Every
reduction is deterministic and recorded: (a) when a budget or throttle level
suppresses an observation, the adapter increments an allocation-free counter
per `(recording, reason, priority)` and emits one coalesced `GAP` event at the
next successful enqueue plus `RecordingFinished.drop_counts_by_priority`; (b) a
value that cannot be enqueued is replaced by `Dropped{reason}`; (c) a refused
new recording increments a session counter reported in `Health`; (d) if the
terminal marker cannot be enqueued the recording stays partial and the daemon
marks it so. Throttle level 1 "suppress duplicate line cursors" (03b §5) is
implemented as (a), never as a silent skip.

### 6. Redaction and canary rules

1. Adapter-side redaction runs before enqueue; the daemon repeats a policy audit
   before storage and may only downgrade a value to `Redacted` (rule
   `daemon.audit`), never upgrade.
2. Name rule: a binding or field name matching (case-insensitive)
   `password|passwd|pwd|secret|token|authorization|cookie|api[_-]?key|credential|private[_-]?key|session|bearer`
   yields `Redacted{rule_id: "name.secret", shape_hint}` and the value is not
   rendered. Type rule: key/crypto types, streams, `Class`/`ClassLoader`/`Thread`,
   Node `Buffer` contents => `Redacted` or shape-only. SQL parameters, request and
   response bodies, headers, cookies and environment values are excluded by
   default (03c §3.7, §4.8).
3. Content rule on every rendered preview and exception message: JWT-shaped
   strings, `AKIA[0-9A-Z]{16}`, PEM blocks, and `Bearer <token>` become
   `Redacted{rule_id: "content.secret_pattern"}`. Redaction is by pattern list
   version, recorded in the existing `redaction_policy_digest`.
4. `CapturedValueCaptured.content_hash` is the BLAKE3-256 of the **emitted**
   (post-redaction, post-truncation) canonical bytes. It is never a hash of a
   pre-redaction value. Redacted values carry no hash. This supersedes the
   doc comment at `crates/xtrace-domain/src/value.rs:213` ("Content hash over the
   pre-redaction value"), because an unsalted hash of a low-entropy secret is a
   recoverable disclosure.
5. Canary rule: every acceptance journey seeds unique canaries
   `xtrace-canary-<uuid>` into (a) an argument named `password`, (b) a field of a
   map argument, (c) a local variable, (d) an exception message, (e) a request
   header and body, (f) a SQL parameter. The canary must not appear in wire
   plaintext (daemon test hook), XTF bytes, SQLite, logs, API JSON, browser
   DOM/state, exports, or diagnostics. Non-name-matched canaries (b, c) must
   appear only as `captured` where policy allows and never in diagnostics.

### 7. Honesty rules (normative for adapters, daemon, API and every client)

- R1 No value is inferred for an unobserved line, local, or time.
- R2 Timing is only recorded `monotonic_ns`; no interpolation, no synthesized
  elapsed time.
- R3 Parent/async-parent links exist only when the adapter observed the context
  handoff; otherwise a `GAP{CORRELATION_LOST}`.
- R4 An "active line" is only a recorded `LINE_CURSOR`. Method extents are never
  shown as active lines (REL:18).
- R5 Absence of an event is displayed as "not observed", never as "did not run".
- R6 Missing locals, maps, debug tables, attestation, or budget reductions are
  visible with a specific reason.
- R7 Completion comes only from `RecordingFinished` with a matching event digest.
- R8 Handled-in-method exceptions and values between observations are never
  reconstructed.

## Alternatives considered

- **JVMTI agent (native).** Gives locals and line events without bytecode edits,
  but needs a per-platform native library (signing/notarization, ABI per JDK),
  has high per-line cost when `can_generate_single_step_events` is on, and
  conflicts with the pure-Java pack format (ADR 0004). Rejected for v0.01.
- **JDI / JDWP debugger.** Requires the target started with a debug agent,
  suspends threads at breakpoints (changes timing and can deadlock request
  threads), and opens a debug port with a weaker trust model than the pinned
  TLS channel. Rejected; the plans also forbid pausing requests (03c §4.7 for
  Node, 02 "not a JVM debugger").
- **Node inspector / `--inspect` breakpoints, V8 coverage or `Debugger.paused`.**
  Pauses the event loop, exposes a control port, and cannot bound per-line
  overhead; `Profiler.takePreciseCoverage` has no values or ordering. Rejected
  (03c §4.7 already forbids inspector pausing).
- **`Module._compile` / `require.extensions` monkey-patching.** CJS-only, global,
  and not available to ESM. Rejected in favor of `registerHooks`, which is the
  supported synchronous customization point for both systems.
- **Babel/Istanbul as a dependency.** Larger dependency and licence surface; the
  needed subset (statement boundaries, source-map composition) is small and
  testable. Kept as a fallback if the `acorn` visitor proves insufficient.
- **Per-line `Advice` only.** Not possible; `Advice` instruments method
  boundaries only.
- **Always capture all locals at all lines.** Unbounded overhead and
  misleading when the table is absent; rejected by 02 "Capture model".

## Consequences

- Shared contracts change (proto, domain enums, query projection, OpenAPI,
  possibly one store migration); all require root's central write ownership and a
  Gate 3 amendment note in `docs/plans/x-trace/03b-protocol-and-api.md` §4.2 and
  `03c-runtime-adapters.md` §3.7/§3.8.
- The Java bootstrap bridge grows a small primitive API; `BridgeEventKind`
  (`agent-bootstrap/.../BridgeEventKind.java`) currently lacks kinds 5, 6, 12
  and 14 and `BridgeSink.offerEvent` has only an `int detail` parameter, so the
  fixture-only bridge is replaced, not extended in place.
- Node standard mode has a non-zero idle cost (probes are installed at load).
  The 2% p50 / 3% p95 idle budget is a hard acceptance gate; failing it lowers
  the Node line-cursor capability to Preview, which cannot be shipped for
  mandatory rows, so it blocks.
- `OBSERVED_UNATTESTED` makes source identity honest for projects without a
  build plugin but means REPLAY-SOURCE `VERIFIED` is available only where the
  attestation exists.
- Replay cost scales with line events; this is why the line budget and the
  windowed query contract (10,000 frames) are coupled.

## Test and evidence obligations

Java: (1) probe-insertion unit tests with ASM-parsed before/after for methods with
branches, try/catch/finally, switch, loops, lambdas, synchronized blocks, and
`long`/`double` slots; (2) bytecode-verifier tests under `-Xverify:all` on JDK 17
and 21 for the same set; (3) golden vectors for `LineNumberTable` -> site table;
(4) `LocalVariableTable` present/absent fixtures producing `captured` vs
`Unavailable{DEBUG_METADATA_ABSENT}`; (5) scope tests proving no JDK/framework
class is transformed (assert the transformed-class list); (6) attach/retransform
fixture for loaded classes; (7) application-semantics test: results and
exceptions identical with and without the agent for a randomized call corpus;
(8) overhead measurements for idle, standard, focused on the fixture and on the
campaign apps; (9) failure injection: sink throws, queue full, daemon
disconnect.

Node: (1) CJS, ESM, and TypeScript (tsc, esbuild, native type stripping)
fixtures with composed-map assertions on exact authored line/column; (2) TDZ,
switch-case, `with`, ASI, directive-prologue, arrow-body, generator/async, class
field and decorator corpora (semantic equality with and without transform, run
under Node 22.x and 24.x at the pinned patch versions); (3) `node_modules`/bundle/
minified exclusion tests; (4) ALS continuity across promises, timers, and
`EventEmitter`; (5) `registerHooks` absence path; (6) overhead gates.

Protocol/store/UI: golden envelopes encoded and decoded by Rust, Java and Node;
proto breaking-change check; recording with Unavailable/Redacted/Truncated/
Dropped/Gap values round-trips through XTF, query, API, Linear, Canvas and TUI
with the exact reason visible; a 10,000-observation recording opens in <= 1.5 s;
canary sweep (section 6.5) across all sinks on both runtimes; honesty tests that
assert the UI never renders an inferred line or value (R1-R8).

## Open questions

1. Per-recording event cap: keep 2,048 for `standard` and introduce a focused-only
   cap of 10,000 (requires a store CHECK rebuild migration and a 03 §6 table
   amendment), or raise the global cap? The existing plan text is internally
   inconsistent (2,048 events per assembled recording vs a 10,000-frame budget).
2. Is `OBSERVED_UNATTESTED` acceptable for the campaign receipts, or must the
   campaign build apply a documented behavior-preserving attestation plugin?
3. Should Node `standard` install statement probes at all, or only function
   probes, with statement/value probes only under `focused`? Decide after the
   idle-overhead measurement.
4. Confirm `registerHooks` returns CommonJS `source` for `require()` on Node 22.15+
   and 24.x at the pinned patch versions; the Node spike must prove this before
   the loader is built on it.
5. Exception-message capture default: on with pattern redaction (as above) or off
   until the privacy review of the pattern set?
6. Spring Boot fat-jar scope: is `BOOT-INF/classes/` plus package prefix a
   sufficient application-root proof, or must the launcher pass the project's
   own artifact digest?

## Root decision (2026-10-04)

Decided by the root orchestrator under the owner's autonomous v0.01 launch authorization. These answers close the open questions above and supersede any conflicting text in this ADR.

1. Event cap: the 2,048 per-recording cap is raised. Defaults are 16,384 events per recording in `standard` and 131,072 in `focused`, both configuration with tested defaults. A new store migration replaces the `event_count <= 2048` CHECK with a sanity bound of 1,048,576. The replay window API must serve at least 10,000 frames. Overflow is recorded as explicit truncation/drop counts and shown to users; nothing is dropped silently. This amends the plan 03 §6 budget table.
2. `OBSERVED_UNATTESTED` is acceptable for campaign receipts when it is shown honestly per frame. Campaign builds use unmodified upstream build configuration; no attestation plugin is injected.
3. Probe depth: `standard` installs function entry/exit/exception probes plus async linkage only. Statement/line probes and value capture are `focused`-only, for both Java and Node. Idle/standard/focused overhead is measured per framework family.
4. The Node lane's first task is a spike proving `module.registerHooks` returns CommonJS `source` on the pinned Node 22.x and 24.x. If it does not, CommonJS uses a `Module.prototype._compile` wrapper and ESM uses the hooks. The fallback is documented in the Node lane report.
5. Exception messages are captured by default with pattern redaction and a length cap. Privacy canary tests must prove the redaction; if the privacy review rejects the pattern set, the default becomes off.
6. Spring Boot fat jars: `BOOT-INF/classes/` plus the package prefix is sufficient application-root proof for v0.01. The launcher also records the jar digest in recording metadata as provenance only, not as an extra claim.

**Amendment (S0b, 2026-10-08).** The 2,048-event per-recording cap no longer fails the capture and is no longer a SQL CHECK: the `event_count <= 2048` CHECK was removed from migration `v0004` (unreleased), and events past the cap are dropped, counted per their own priority in the finish drop counts (plus `capacity_dropped_events`), and the recording ends Partial. See `crates/xtrace-application/src/recording.rs` (`MAX_RECORDED_EVENTS`, `effective_finish`), `crates/xtrace-ingest/src/validator.rs` (`accept_events`) and `crates/xtrace-store/src/recording_store.rs` (terminal evidence verification). The original text above is kept as written.

**Addendum (wave 1, 2026-10-09): additive wire numbers beyond section 4.** The root approved these additions (plan ruling A5, contracts OPEN-15). They are additive, appear only in `schema/proto/xtp-agent/v1`, and are pinned by `crates/xtrace-protocol/tests/golden_fixtures.rs` (`proto_field_numbers_match_adr_0003`) and the golden envelopes under `schema/fixtures/xtp-agent/`. No existing number is renumbered or repurposed (`proto_baseline_fields_still_present`).

| Message | Field or value | Number | Purpose |
|---|---|---|---|
| `GapReason` | `CHILD_PROCESS_NOT_INSTRUMENTED`, `BOOTSTRAP_CONSUMED` | 10, 11 | Node process linkage gaps |
| `InteractionKind` | `PROCESS` | 6 | process or worker spawn (`symbol` is the command basename only) |
| `Interaction` | `statement_kind`, `tables`, `sanitized_shape`, `port`, `status_code` | 11 to 15 | JDBC statement class, tables, literal-free shape, outbound HTTP port and status |
| `RecordingStarted` | `exercise_item_id` | 14 | links a recording to an exercise plan item (from request header `X-XTrace-Exercise-Item`) |
| `AdapterHello` | `runtime_facts` | 17 | adapter-reported framework and runtime facts; outside the HMAC transcript, so shown as "adapter-reported" |

The standard-mode line budget stays 0 (root decision 1 above supersedes the 1,024 in the budget table); `CaptureBudget::STANDARD.max_line_events` is 0 and ingest enforces it.
