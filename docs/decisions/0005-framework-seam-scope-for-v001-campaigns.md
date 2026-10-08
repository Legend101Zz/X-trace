# ADR 0005: Framework seam scope for v0.01 campaigns

- Status: Accepted (root decision 2026-10-04)
- Date: 2026-10-04
- Context: The v0.01 mandate requires six pinned real-project campaigns and
  names the framework families they must exercise, while the approved plans
  (`02a-language-framework-support.md`, `03c-runtime-adapters.md` §5) list a
  broader and partly different matrix (Koa as Preview, JDK 25, Node 26, Windows).
  The requirements ledger (`evidence/v0.01/requirements.json` on
  `slice/v001-release-control`) has no row for JAX-RS/Jersey, yet the mandated
  `apache/fineract` campaign exposes REST through Jersey. This ADR fixes the
  seam each framework family must provide for v0.01, what is explicitly out of
  scope, and the version matrix, so campaign receipts and support claims cannot
  silently exceed or fall short of the mandate. It narrows the v0.01 release
  matrix; it does not alter the long-term plan matrix.

## Decision

Mandate citations use `M:<line>` for the owner-provided v0.01 launch mandate
(line numbers of the original, untracked text; its substance is mirrored in
`docs/releases/v0.01.md` on `slice/v001-release-control`).

### 1. Java seams

| Family | v0.01 seam | Notes |
|---|---|---|
| Spring MVC (Boot and non-Boot) | `RequestMappingHandlerAdapter.handleInternal` handler-method identity (`HandlerMethod.getBeanType()/getMethod()`), plus servlet root | Replaces the fixture-only literals at `FixtureInstrumentation.java:158` and `BootstrapBridge.java:30` with route template from the matched handler mapping. |
| Spring WebFlux | route/handler selection and Reactor context propagation | Reactive correlation uses Reactor `Context`, not thread affinity (03c §3.5). |
| Servlet family | `javax.servlet.http.HttpServlet#service` and `jakarta.servlet.http.HttpServlet#service` as the request root; `Filter.doFilter` only for frames; `AsyncContext` dispatch/start for async | Separate modules per namespace (03c §3.4). Exactly one request root per request; forward/include add framework frames, not roots. Mandate M:118-119 ("Servlet families"). |
| **JAX-RS / Jersey (new)** | Jersey runs on top of the servlet root; **resource-method identity is taken at the Jersey resource-method invocation**: the `org.glassfish.jersey.server.model.ResourceMethodInvoker` dispatch (`apply` on the version-pinned signature) from which the module reads `getResourceMethod()` (the `java.lang.reflect.Method`), the resource class, and the matched URI templates (`ExtendedUriInfo.getMatchedTemplates()` joined to the application path) | Needed by the mandated `apache/fineract` campaign (M:157; REST under a `/fineract-provider/api/v1/*` Jersey application on a Spring Boot servlet container). Matching is by the invoker the framework actually calls, not by static annotation scanning, discovery or `@Path` string reconstruction (that remains the Java static analyzer's job under 03c §3.10). Package markers `org.glassfish.jersey.server` / `jakarta.ws.rs`; module `posture: reviewed_internal` (the invoker is a public class but not a documented extension hook), fixture IDs required for every declared Jersey version. |
| JDBC | statement execute boundary (existing H2 seam generalized), pgjdbc and H2 drivers declared in the matrix | SQL text sanitized, parameters excluded by default (03c §3.4). |

Jersey does **not** add GraphQL-style discovery and does **not** add JAX-RS to
the plan's Supported framework table by implication: the claim is "Servlet
family with Jersey resource-method identity", published per exact Jersey
version in the generated matrix.

### 2. Node seams

| Family | v0.01 seam |
|---|---|
| Built-in HTTP/HTTPS | `node:http`/`node:https` server request root (existing, `http-capture.cts`) |
| Express | route registration, middleware order, selected handler, error handler |
| Fastify | public route/lifecycle hooks, encapsulation context |
| NestJS on Express and on Fastify | controller/handler class and method identity enriching the underlying Express/Fastify root; no duplicate roots (03c §4.6) |

**Vendure GraphQL = HTTP + Nest seams only.** For the mandated
`vendurehq/vendure` campaign (M:161, M:166-167):

- the request root is the HTTP request for `POST /shop-api` and
  `POST /admin-api` (and any REST route Vendure registers), recorded as an
  ordinary HTTP endpoint operation with those paths as the route template;
- handler identity is recorded as a **frame**, not as a catalog claim, where the
  handler is a Nest provider method: a Nest controller method, or a Nest
  `@Resolver()` class method (a provider executed through Nest's external context
  creator); the module is declared `posture: reviewed_internal` with exact Nest
  and `@nestjs/graphql` versions;
- no GraphQL operation discovery: operation names, selection sets, documents,
  variables, and schema introspection are neither captured as claims nor used to
  mint endpoints; request bodies stay excluded by default;
- GraphQL-specific exports (OpenAPI/Postman for operations) are out of scope and
  the UI states "GraphQL operations are not enumerated" for those endpoints.

**Koa is explicitly unsupported in v0.01.** The plan's "Koa: Preview"
(`00-status.md`, `02a`, `03c` §4.6, `04` Slice 5) is superseded for this release by
M:124-125 and `docs/releases/v0.01.md`: no Koa module ships, the pack manifest
lists none, the matrix shows Koa as `unsupported`, and `xtrace doctor` reports
`XTR-FRAMEWORK-UNSUPPORTED` for a detected Koa app. Preview status is not used to
route around a mandatory gate.

### 3. Platform and runtime matrix for v0.01

| Axis | Required (release claim) | Not claimed |
|---|---|---|
| OS/arch | macOS arm64, Linux x86_64 (M:94-95) | Windows (any), macOS x86_64, Linux arm64 |
| JDK | 17 and 21: launch, attach, all journeys | 25: see below |
| Node | 22 and 24: launch, all journeys | 26 (plan "Preview while Current"), 20 and earlier |
| Languages | Java, Node.js | Python, Ruby, Rust, Go |

**Windows is unsupported**: `plans/05` D-4 already excludes it, the pack schema
cannot represent it (`signed_pack.rs:509-540`), and `xtrace init` on Windows exits
with `XTR-PLATFORM-UNSUPPORTED`. The plan's first campaign list naming Windows
(03c §5) is superseded for v0.01.

**JDK 25 is best-effort attach only if installed on the host and is not a release
claim.** Approved attach-version tests (M:96-97) run on 17 and 21. If a JDK 25 is
present, `doctor` and `attach` may attempt it using pack schema field
`runtime.bestEffortMajors` (ADR 0004); the session is labelled `support_level:
best_effort`, the matrix cell reads `unverified`, and no ledger row depends on it.
Without that schema field JDK 25 is refused (`XTR-RUNTIME-UNTESTED`).

**Node 22/24 pinning.** `module.registerHooks` (ADR 0003) requires Node >= 22.15.
Receipts pin the exact patch levels used by each campaign (the preparation file
records Node 22.23.0 and 24.21.0); Node 22.0-22.14 is outside the supported range
for source transforms and shows `source_transform: unavailable`.

**Campaign-to-seam mapping** (each row also needs the packaged-run, privacy,
overhead and browser journey evidence of the mandate):

| Project | Required seams |
|---|---|
| spring-petclinic | Spring MVC, JDBC (H2) |
| jhipster-sample-app | Spring MVC/Boot, JDBC, Servlet root |
| apache/fineract | Servlet root + **Jersey resource-method identity**, JDBC (pgjdbc), JDK 21 |
| directus | Express (and Node HTTP root), Node DB driver seam |
| medusa | Express/Node HTTP, Nest only if the pinned version uses it |
| vendure | Node HTTP + Express + Nest provider-method frames, no GraphQL discovery |

Fixture supplements required by M:169-170: WebFlux, `javax` and `jakarta` servlet
containers, Fastify, CJS/ESM/TypeScript, JVM attach.

## Alternatives considered

- **Treat Jersey as plain Servlet (generic servlet-level evidence only).** Honest
  but yields no resource-method identity or route template for Fineract; handler
  assertions in M:188-189 could not pass. Rejected as the primary path; it
  remains the documented degraded outcome (`handler_unresolved`) if the Jersey
  module is disabled.
- **Substitute another Java project for Fineract.** Forbidden without a material
  scope decision (M:171-173).
- **Static `@Path` scanning to name routes.** Cannot see programmatic resources,
  sub-resource locators or `ResourceConfig` registrations; kept only as
  low-confidence static inference, never as an observed handler.
- **Implement GraphQL operation discovery for Vendure.** Explicitly not implied
  by M:166-167.
- **Ship Koa as Preview.** Contradicts the release specification.
- **Claim JDK 25 attach.** No packaged acceptance on 25; would require
  verification evidence the release cannot produce.
- **Instrument Nest only through Express/Fastify.** Loses controller/provider
  identity; the mandate asks for "HTTP/Nest seams".

## Consequences

- The ledger needs an added requirement or an explicit sub-claim under
  JAVA-SERVLET and CAMPAIGN-FINERACT naming Jersey resource-method identity; the
  pinned canonical-contract digest in `tools/release/check_ledger.py` means a
  ledger row change is a root-reviewed contract change.
- Fineract is the highest-risk campaign: Jersey invoker signatures differ across
  Jersey 2.x/3.x lines and Jersey application path joining is non-trivial; a
  compatibility fixture per Jersey version in the pack's `testedVersions` is
  mandatory before the framework module may say `supported`.
- Vendure resolvers appear as frames only; a reviewer reading the catalog will see
  two endpoints (`/shop-api`, `/admin-api`) with many recordings, which is the
  intended honest outcome.
- Plan documents (`02a`, `03c` §5, `00-status.md`, `04` Slice 5) disagree with
  this ADR on Koa, JDK 25, Node 26, Windows; the ADR governs v0.01 and a
  follow-up plan-amendment note must list the supersessions.
- CI matrix must add Node 24 (current CI has Node 22 only) and keep Java 17/21.

## Test and evidence obligations

- One fixture application per Java seam (Spring MVC/Boot, Spring MVC without Boot,
  WebFlux, `javax` servlet, `jakarta` servlet, **Jersey/JAX-RS with sub-resource
  locator and exception mapper**) asserting: one root per request, correct handler
  class and method, correct route template, correct status, correct recording under
  concurrent requests, and error outcomes.
- Jersey: tests on each declared Jersey version for resource-method identity,
  matched-template join with application path and servlet mapping, `@BeanParam`,
  `ContainerRequestFilter` abort, async resume (`@Suspended`), and exception mapping.
- Node fixtures for HTTP/HTTPS, Express (router and middleware order), Fastify
  (encapsulation), Nest on Express and Fastify (controller/resolver provider
  methods; guards/pipes/interceptors where safely observable), CJS, ESM, and
  TypeScript, on Node 22 and 24.
- Vendure: a negative test proving no GraphQL document, operation name, or variable
  appears on the wire, in storage, API, UI, or exports; a positive test that
  `POST /shop-api` and `POST /admin-api` link to recordings whose frames include the
  Nest provider method.
- Koa: a detect-and-refuse test (`XTR-FRAMEWORK-UNSUPPORTED`); a manifest test that
  no Koa module is listed; matrix shows `unsupported`.
- Windows: `init`/`run` refuse with the stable code on a simulated Windows host
  tuple; pack schema rejects a Windows platform entry.
- JDK 25: if installed, an attach attempt is labelled `best_effort`/`unverified`
  and no receipt references it; if not installed the cell reads `not tested`.
- The generated compatibility matrix (03c §5) is produced from fixture evidence;
  unexercised cells print `unknown`, never "supported by similarity".
- Campaign receipts (CAMPAIGN-*) demonstrate the seams above on the pinned upstream
  SHAs with the mandate's scenarios, privacy canaries, overhead and browser
  evidence; none may count a skipped or synthetic result.

## Open questions

1. Is a ledger-level requirement row for Jersey resource-method identity wanted, or
   is it covered by JAVA-SERVLET plus CAMPAIGN-FINERACT?
2. Which Jersey line does the pinned Fineract use, and does the verified upstream
   tag `1.15.0` in the preparation file match the canonical upstream (the digest
   notes it as unverified)?
3. Nest GraphQL resolver wrapping point: is the Nest external context creator an
   acceptable `reviewed_internal` seam, or should resolver frames be limited to
   Nest controller methods until a public hook is available?
4. Medusa v2's HTTP stack: does the pinned version run on Express only, or does
   Nest enter? The module set should follow the pinned version, not the plan.
5. Do we want a doctor message for detected GraphQL servers explaining that
   operations are not enumerated?

## Root decision (2026-10-04)

Decided by the root orchestrator under the owner's autonomous v0.01 launch authorization. These answers close the open questions above and supersede any conflicting text in this ADR.

1. No new ledger row; the 55 mandatory rows are fixed. Jersey resource-method identity is evidenced under JAVA-SERVLET and CAMPAIGN-FINERACT.
2. The campaign lane verifies the Fineract pin, its canonical upstream URL/tag/SHA and the Jersey line at campaign time and records them in the receipt.
3. Nest/GraphQL: no `reviewed_internal` GraphQL hook. Frames are Nest controller/provider methods and ordinary application method frames from probes on application code. GraphQL operations are not enumerated.
4. Medusa's HTTP stack follows the pinned version; the campaign lane verifies whether Nest is present and limits claims to the seams actually observed.
5. Yes: `doctor` prints an informational message when a GraphQL server is detected, explaining that operations are not enumerated in v0.01.
