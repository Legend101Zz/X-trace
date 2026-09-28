# Status: X-trace

- Gate 1 - Product: APPROVED 2026-09-28, amended with Node.js and export scope
- Gate 2 - Architecture: APPROVED 2026-09-28
- Gate 3 - Program Design: APPROVED 2026-09-28
- Gate 4 - Slice plan: APPROVED 2026-09-28; implementation begins with Slice 1

## Gate 3 review set

- [Program design](03-program-design.md)
- [Domain and storage](03a-domain-and-storage.md)
- [Protocols and client API](03b-protocol-and-api.md)
- [Java and Node.js runtime adapters](03c-runtime-adapters.md)
- [Clients, configuration, exports, and verification](03d-clients-config-export-verification.md)

## Gate 4 review set

- [Visible vertical slice plan](04-vertical-slices.md)

## Proposed slices

- [ ] Slice 1 - one real Spring Boot request from launch to Linear replay
- [ ] Slice 2 - inferred catalog, durable history, basic Canvas, and TUI replay
- [ ] Slice 3 - JVM attach, focused capture, values, and failure honesty
- [ ] Slice 4 - Node HTTP and Express parity across CommonJS and ESM
- [ ] Slice 5 - Java and Node framework breadth with compatibility evidence
- [ ] Slice 6 - production-quality Canvas, replay scale, and source evidence
- [ ] Slice 7 - reviewed endpoint exercise plans and bounded execution
- [ ] Slice 8 - OpenAPI, Postman, cURL, developer bundle, and explicit Postman delivery
- [ ] Slice 9 - security, recovery, packaging, performance, and usability release gate

## Notes for a fresh session

- Product name is **X-trace**.
- The product is not a chatbot.
- The primary experience is a Swagger-like endpoint catalog combined with a read-only debugger replay.
- The web experience has three stable regions: endpoint/scenario context, execution navigation, and code evidence. Execution navigation switches between a spatial Canvas and a conventional Linear trace while preserving selection and playback position.
- V1 framework scope includes Spring Boot, Spring MVC/WebFlux, Servlet, Node HTTP, Express, Fastify, and NestJS; Koa is preview. Support is declared per language/framework/version/capability.
- The approved product shape is a Rust local daemon/CLI/TUI, a browser viewer, and out-of-process runtime-native language packs.
- An application can be launched with recording enabled; best-effort attachment to an already-running compatible JVM is required in the first release.
- An endpoint can be discovered and display a clearly labelled inferred path without having a recording. An observed trace exists only after a request, test, or explicitly requested exercise runs it.
- Static/inferred and runtime-observed information must never be presented as the same evidence.
- Automated endpoint exercising is first-release scope only when explicitly requested by the user, with plan preview, endpoint scoping, authentication inputs, and safeguards for mutating requests.
- The endpoint catalog should be exportable as OpenAPI and as an importable Postman collection, with secrets omitted.
- Web and TUI offer OpenAPI, Postman, cURL, and combined exports. Connected Postman creation is explicit and credentialed.
- SQLite is bundled with X-trace; users do not install or administer it separately.
- Local catalog revisions and immutable run records track endpoint evolution. No scheduled scan, exercise, upload, or network request occurs by default.
- The first UI mockups were developed separately by a GPT-5.6-Sol design lane. Canvas remains graph-first; Linear is now code-first with an execution cursor, inline values, and a compact execution rail.

## Approved architecture inputs carried into Gate 3

- Treat Java and Node.js as v1 language integrations, not as the architecture of the whole product.
- Start with Java and Node.js language packs; design the extension boundary so Python, Ruby, Rust, Go, and their frameworks can follow without changing the core product model.
- Evaluate a Rust core engine and Rust TUI, with execution/instrumentation adapters implemented in the target runtime where appropriate.
- The TUI and web application should share one domain model, protocol, commands, endpoint states, filters, and replay semantics. Shared behavior matters more than forcing both surfaces to share rendering code.
- Establish repository layout, dependency direction, error model, compatibility policy, formatting, linting, testing, versioning, telemetry/privacy, and contribution standards before implementation begins.
- Gate 2 research compared architecture patterns and extension contracts from strong open-source tracing, debugger, language-server, TUI, and graph-canvas repositories. Any reuse still requires license and maintenance checks.
