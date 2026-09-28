# Gate 3 Appendix C: Java and Node.js Runtime Adapters

**Status:** approved with Gate 3 on 2026-09-28  
**Purpose:** define the language-pack manifest, Java agent/attach design, Node preload/loader design, instrumentation module contract, capture semantics, and compatibility discipline.

## 1. Language-pack contract

Every installed pack has a signed `xtrace-pack.json`:

```json
{
  "schemaVersion": 1,
  "pack": {"name":"java", "version":"0.1.0", "buildHash":"b3:..."},
  "protocol": {"min":"1.0", "max":"1.2"},
  "runtime": {"language":"java", "versionRange":">=17 <27"},
  "entrypoints": {
    "launch":"...",
    "attach":"...",
    "staticDiscovery":"..."
  },
  "frameworkModules": [],
  "capabilities": {},
  "knownLimitations": [],
  "artifacts": [{"path":"...", "hash":"b3:..."}],
  "signature": {"keyId":"...", "value":"..."}
}
```

The daemon verifies schema, hashes, signature, X-trace release compatibility, runtime range, and OS/architecture before execution. Development mode may load an unsigned local pack only with an explicit flag and a permanent UI warning.

Each framework module declares:

- framework coordinates/package markers and tested range;
- status (`supported`, `preview`, `experimental`);
- discovery and capture capabilities;
- required runtime features;
- instrumented type/method matchers;
- conflicts and ordering requirements;
- public-hook/private-internal posture;
- fixture IDs that justify the declaration.

## 2. Common adapter responsibilities

Adapters own only runtime-local work:

1. detect runtime/framework facts;
2. discover endpoint/handler claims;
3. propagate recording context;
4. instrument selected boundaries;
5. construct ordered runtime events;
6. sanitize and budget values before transport;
7. buffer, batch, throttle, and report loss;
8. accept scoped capture commands;
9. expose health/capabilities.

They do not reconcile the catalog, select exports, authorize exercises, read the daemon store, or render UI state.

Adapter self-instrumentation is excluded by package/module identity and a thread/task-local suppression guard.

## 3. Java pack

### 3.1 Artifact/classloader layout

`xtrace-java-agent.jar` contains only bootstrap entrypoints and shaded agent implementation. Instrumentation advice classes that must be visible to bootstrap/application loaders are isolated from implementation classes.

```text
io.xtrace.agent.bootstrap
  XTraceAgent.premain(String, Instrumentation)
  XTraceAgent.agentmain(String, Instrumentation)
  BootstrapBridge
  ContextToken

io.xtrace.agent.core
  AgentRuntime
  AgentConfiguration
  CapabilityDetector
  InstrumentationRegistry
  TransformationCoordinator
  RecordingContextManager
  EventSequencer
  ValueSanitizer
  EventBuffer
  BatchEncoder
  TransportClient
  CaptureCommandProcessor
  AgentHealthReporter

io.xtrace.agent.instrumentation
  InstrumentationModule
  TypeInstrumentation
  AdviceDescriptor
  ModuleCompatibility
```

Shading relocates Byte Buddy, Protobuf, and supporting libraries. The build verifies no public non-JDK dependency package leaks into the application classloader. The agent does not modify the target application's dependency graph.

### 3.2 Entrypoint lifecycle

`premain`:

1. Parse bootstrap file and validate owner/permissions/expiry.
2. Initialize an isolated agent classloader.
3. Establish transport and negotiate capabilities.
4. Install bootstrap bridge/context helpers.
5. Detect already-present framework classes and register transformers before application startup continues.
6. Send initial capability set and runtime facts.
7. Start the single transport writer and command reader threads.

`agentmain`:

1. Performs the same secure bootstrap.
2. Detects `isRetransformClassesSupported` and class modifiability.
3. Registers transformers.
4. Enumerates already-loaded candidate classes and requests retransformation in bounded batches.
5. Emits per-module coverage: transformed, future-load-only, unmodifiable, failed.
6. Discovers runtime handler mappings when possible.

Attach never claims activity before `agentmain` was observed. If critical request-boundary classes cannot be instrumented, the session remains connected with reduced capabilities or fails with an exact relaunch command.

### 3.3 Module API

```java
public interface InstrumentationModule {
  ModuleDescriptor descriptor();
  CompatibilityResult detect(RuntimeFacts facts, ClassLookup lookup);
  List<TypeInstrumentation> typeInstrumentations();
  List<DiscoveryHook> discoveryHooks();
  List<ContextPropagationHook> contextHooks();
}
```

Modules are data-driven and independently testable. Advice code calls only `BootstrapBridge` methods with primitives, strings, IDs, and sanitized value envelopes; it does not call transport or allocate large graphs.

Module activation is fail-isolated. One incompatible module is disabled with a diagnostic and capability reduction; it does not prevent unrelated modules from loading.

### 3.4 Initial Java modules

| Module | Primary boundaries | Notes |
|---|---|---|
| `servlet-javax` | `javax.servlet` request/filter/async dispatch | servlet 3.x/4.x fixtures by container |
| `servlet-jakarta` | `jakarta.servlet` request/filter/async dispatch | separate artifact to avoid namespace linkage |
| `spring-webmvc` | handler mapping registration and handler adapter invocation | Boot-independent; Boot facts enrich metadata |
| `spring-webflux` | route/handler selection and Reactor context | reactive context fixtures are a Supported gate |
| `app-methods` | configured application packages | standard entry/exit/throw; focused line probes |
| `jdbc` | statement/prepare/execute/result boundary | SQL text sanitized; parameters excluded by default |
| `http-clients` | JDK client, Apache client, OkHttp, Spring clients where tested | outbound URL/headers sanitized |

Spring Boot Actuator mappings are an optional discovery input. The agent never enables or exposes an actuator endpoint.

### 3.5 Recording context

`RecordingContextManager` stores a compact context token in `ThreadLocal` and known async propagation hooks. Reactor uses its context rather than relying on thread affinity. Servlet async dispatch carries the token through request attributes using a collision-resistant internal key.

The token contains IDs and sequence handles, not captured values. Forks create an async link. An unrecognized cross-thread transition opens an explicit correlation gap rather than guessing.

### 3.6 Event path and buffering

Advice path:

```text
advice -> suppression guard -> context lookup -> primitive event builder
-> value sanitizer/budget -> priority enqueue -> return to application
```

- `EventSequencer` uses a session atomic sequence and a recording-local sequence allocator.
- `EventBuffer` is a fixed-capacity multi-producer/single-consumer ring.
- The application thread may spend only the configured enqueue budget; on exhaustion it increments an allocation-free drop counter.
- The writer thread emits coalesced drop notices, builds batches, retains structural batches for ACK/retry, and handles throttle transitions.
- No network write, compression, DNS, file I/O, or SQLite work occurs on application threads.

### 3.7 Value capture

The sanitizer accepts only a bounded traversal budget:

- allow/deny by type, package, field/parameter name, annotation, header, and content type;
- default-deny for known secret names and credential types;
- maximum depth, elements, string bytes, object count, event bytes, and recording bytes;
- stable cycle detection by object identity within one traversal;
- safe scalar rendering without invoking arbitrary application `toString()` by default;
- exceptions capture type/message/stack structure after redaction, never arbitrary fields unless allowed;
- SQL parameters, request/response bodies, cookies, authorization headers, and environment values are excluded by default.

`Captured`, `Redacted`, `Truncated`, and `Unavailable` are decided before enqueue. `Dropped` is assigned when optional events cannot be emitted.

### 3.8 Focused Java capture

Focused capture compiles an instrumentation plan from operation handler evidence and configured application packages. It retransforms only matching modifiable classes and inserts line probes at distinct source-line transitions. Local-variable capture requires a LocalVariableTable and supported bytecode patterns.

Rules:

- never instrument JDK, agent, framework internals, generated proxies, or dependency packages unless a specific reviewed module owns the boundary;
- expire by next matching requests and absolute time;
- restore standard transformers after expiry;
- report classes that could not be retransformed;
- preserve application semantics under verifier and exception tests;
- cap added probes and emitted values before transformation.

Focused capture is unavailable for native images in v1 and capability-graded for Kotlin/synthetic/state-machine bytecode.

### 3.9 Attach helper

`io.xtrace.attach.Main` is a small standalone JAR using `jdk.attach`.

Commands:

```text
java -jar xtrace-attach.jar list --json
java -jar xtrace-attach.jar inspect --pid <pid> --json
java -jar xtrace-attach.jar attach --pid <pid> --agent <jar> --options-file <path> --json
```

It returns stable exit/error codes and structured JSON. Process selection displays PID, start time, command summary, user, JDK, container hints, and attach eligibility without leaking full environment or command-line secrets.

The Rust CLI validates process identity immediately before attach to prevent PID reuse.

### 3.10 Java static analyzer

The analyzer is an isolated Java process, not an agent library loaded into the application. It consumes source roots, compiled classes, dependency metadata, and configuration, then emits XTP discovery fixtures or a bounded local stream.

Initial analyses:

- Spring MVC/WebFlux annotations and functional routes where statically resolvable;
- Servlet annotations and deployment descriptors;
- controller-to-service/repository direct-call graph within application packages;
- declared HTTP clients and common data-access boundaries;
- source ranges and ambiguity/confidence reasons.

It does not execute build scripts without explicit approval. Build-tool integration uses already-built outputs first; an optional requested build is a separate run with visible command and result.

## 4. Node.js pack

### 4.1 Package structure

```text
@xtrace/protocol
@xtrace/adapter-core
@xtrace/loader-cjs
@xtrace/loader-esm
@xtrace/instrumentation-http
@xtrace/instrumentation-express
@xtrace/instrumentation-fastify
@xtrace/instrumentation-nest
@xtrace/instrumentation-koa
@xtrace/static-analyzer
```

The distribution contains version-matched compiled CommonJS and ESM entrypoints plus source maps. It is bundled with X-trace; it is not added to the user's `package.json` or lockfile.

### 4.2 Launch forms

CommonJS:

```text
NODE_OPTIONS="--require <xtrace>/register.cjs" node app.js
```

ESM:

```text
NODE_OPTIONS="--import <xtrace>/register.mjs" node app.mjs
```

For npm/pnpm/yarn scripts, X-trace sets the preload/import in the launched process environment and preserves the user's command. It prints the equivalent invocation with secrets/file tokens elided.

Late `require()`/`import()` of the adapter is allowed only as reduced-coverage development mode and cannot be labelled Supported.

### 4.3 Core modules

```text
bootstrap.ts             validate bootstrap and runtime
capabilities.ts          runtime/hook/source-map feature detection
context.ts               AsyncLocalStorage recording context
sequencer.ts             session and recording sequence assignment
events.ts                typed normalized event builders
redaction.ts             value policy and budgets
queue.ts                 bounded priority queue and drop notices
transport-worker.ts      TLS, batching, ACK/retry, commands
module-registry.ts       framework detector/installer
source-transform.ts      focused probes for repository-owned modules
source-maps.ts           composed generated-to-authored locations
self-suppression.ts      prevent recorder recursion
```

Transport and compression run in a dedicated worker thread where supported. The main event loop only performs bounded event construction and queue handoff. Worker failure reduces capture and reports health; it does not crash the target by default.

### 4.4 Instrumentation module API

```ts
export interface InstrumentationModule {
  readonly descriptor: ModuleDescriptor;
  detect(environment: RuntimeEnvironment): CompatibilityResult;
  install(registrar: HookRegistrar, bridge: RuntimeBridge): InstalledModule;
}
```

`HookRegistrar` provides version-gated public hooks and quarantined patching utilities. A framework-specific internal patch must live in a version-scoped compatibility file with fixtures for every declared version. Failure disables that module rather than leaving a half-patched runtime.

### 4.5 Context and request correlation

`AsyncLocalStorage<RecordingContext>` is entered at the earliest HTTP request boundary. Express middleware, Fastify hooks, Nest execution, outbound calls, database callbacks, and promises read the same context. Worker threads and child processes establish new runtime sessions linked by launch metadata; context is not magically shared across processes.

The context contains IDs, parent frame stack, and budget counters. Values remain event-local. If user code deliberately breaks async context, the adapter emits a gap and resumes only when a known boundary restores identity.

### 4.6 Framework modules

| Module | Discovery | Replay boundaries |
|---|---|---|
| Node HTTP/HTTPS | runtime server/listener observation | request, response, exception, outbound request |
| Express | route/middleware registration | middleware order, selected route/handler, errors |
| Fastify | public route/lifecycle hooks | route, hooks, selected handler, response/error |
| NestJS | controller metadata plus underlying adapter | controller/handler identity, guards/pipes/interceptors when safely observable |
| Koa | runtime middleware composition | request/middleware/response; Preview in v1 |

Nest does not duplicate HTTP roots from Express/Fastify. It enriches frames through shared event identity. Fastify integration follows public framework-maintained observability hooks where they satisfy X-trace evidence requirements; custom capture remains responsible for source/value replay.

### 4.7 Focused Node capture

Focused capture uses Node module customization hooks supported by the active runtime. The transformer:

1. resolves and validates the file as repository-owned;
2. excludes `node_modules`, generated bundles, eval, X-trace code, and policy-denied files;
3. parses JavaScript/TypeScript-compatible emitted JavaScript;
4. inserts function/line/value probes under the plan budget;
5. composes an output source map with any input map;
6. verifies the transformed module parses before returning it;
7. records the transformer/source-map versions.

Modules already loaded before arming cannot be retroactively transformed safely in v1. The UI says that a restart or launch with an armed plan is required. Standard capture continues.

The implementation never uses Node Inspector to pause requests and never rewrites dependency modules.

### 4.8 Node value capture

- primitives and small plain objects/arrays may be captured within policy;
- getters, proxies, custom inspect hooks, and arbitrary serialization callbacks are not invoked;
- Buffers and typed arrays default to type/length/digest, not contents;
- streams, sockets, requests, responses, functions, promises, and framework objects use safe shape summaries;
- error type/message/stack are sanitized;
- headers, cookies, authorization, request/response bodies, SQL parameters, and environment values are excluded by default.

### 4.9 Node static analyzer

The analyzer is a separate Node process using syntax/TypeScript program information when available. It detects:

- Express router and method registration patterns;
- Fastify route declarations and shorthand methods;
- Nest controller/method decorators;
- direct application-function calls and declared clients within configured roots.

Dynamic composition, computed routes, decorators after transpilation, or runtime plugins may remain uncertain. Findings carry confidence and reason codes. The analyzer does not import or execute the application.

## 5. Compatibility matrix

The checked-in matrix is generated from fixture evidence and includes:

```text
OS / architecture
runtime and exact patch
framework and exact patch
module system / packaging
launch or attach
discovery
standard frames
focused lines
focused values
async/reactive correlation
database/outbound modules
overhead result
known gaps
fixture run ID and release commit
```

Supported claims require green results on the declared range endpoints and representative interior versions. Preview claims may have documented gaps. Untested combinations display `unknown`, not `supported by similarity`.

The first evidence campaign targets:

- JDK 17, 21, 25;
- published stable Spring Boot 3.x/4.x lines, Spring MVC/WebFlux, representative `javax` and `jakarta` containers;
- Node 22 and 24 LTS for Supported; Node 26 Current for Preview until promoted;
- Express, Fastify, Nest-on-Express, Nest-on-Fastify, and Koa Preview;
- Linux, macOS, Windows on supported architectures.

Exact ranges are published only after fixtures run.

## 6. Adapter conformance suite

Every pack must pass the same black-box scenarios:

1. signed manifest and protocol negotiation;
2. complete/incremental endpoint claims and reconciliation;
3. successful, failed, cancelled, and timed-out requests;
4. nested and recursive frames;
5. async/thread/reactive continuation;
6. database and outbound interactions;
7. redacted, truncated, unavailable, and dropped values;
8. throttling and recovery;
9. transport disconnect/reconnect and retransmission;
10. process crash and daemon crash;
11. source mismatch and source-map/debug-metadata absence;
12. focused capture scope/expiry;
13. self-instrumentation exclusion;
14. malicious/malformed runtime data;
15. idle, standard, focused, and saturation overhead.

Golden event expectations are language-neutral; language-specific fixtures prove the runtime mechanisms.
