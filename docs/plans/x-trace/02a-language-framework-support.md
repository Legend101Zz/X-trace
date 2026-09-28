# X-trace language and framework support contract

**Gate:** 2 appendix  
**Status:** approved 2026-09-28  
**Purpose:** prevent “supports a language” from becoming an ambiguous marketing claim.

## Status vocabulary

- **Supported:** tested in the published version matrix; endpoint discovery, request correlation, source navigation, privacy controls, exports, failure diagnostics, and declared capture depths pass release gates.
- **Preview:** usable but missing one or more supported gates, shown explicitly in the UI and CLI.
- **Experimental:** opt-in development integration with no compatibility promise.
- **Detected only:** X-trace can catalog endpoints or import a specification but cannot produce an observed code replay.
- **Unsupported:** no adapter capability is claimed.

Framework status and capture depth are separate. A framework may be Supported for endpoint and standard request replay while focused local-variable capture is Preview for a particular compiler or build configuration.

## V1 release matrix

| Language | Framework or boundary | Discover | Launch | Attach | Standard replay | Focused line/value replay | V1 status |
|---|---|---:|---:|---:|---:|---:|---|
| Java | Spring Boot + Spring MVC | Yes | Yes | Best effort | Yes | Yes when bytecode metadata permits | Supported |
| Java | Spring Framework MVC | Yes | Yes | Best effort | Yes | Yes when bytecode metadata permits | Supported |
| Java | Spring WebFlux | Yes | Yes | Best effort | Yes | Capability graded for reactive chains | Supported |
| Java | `javax.servlet` applications | Yes | Yes | Best effort | Yes | Application packages only | Supported |
| Java | `jakarta.servlet` applications | Yes | Yes | Best effort | Yes | Application packages only | Supported |
| Node.js | Built-in HTTP/HTTPS | Runtime | Yes | No | Yes | Application modules loaded through X-trace | Supported |
| Node.js | Express | Static + runtime | Yes | No | Yes | CJS/ESM and source-map capability graded | Supported |
| Node.js | Fastify | Static + runtime | Yes | No | Yes | CJS/ESM and source-map capability graded | Supported |
| Node.js | NestJS with Express | Static + runtime | Yes | No | Yes | Controller/service modules capability graded | Supported |
| Node.js | NestJS with Fastify | Static + runtime | Yes | No | Yes | Controller/service modules capability graded | Supported |
| Node.js | Koa | Runtime | Yes | No | Yes | Not a v1 release gate | Preview |

Exact JDK, Node.js, Spring, application-server, and framework version ranges are fixed in Gate 3 after fixture testing. The UI reads the installed language-pack manifest and shows the exact range and gaps; it never derives support from this planning table alone.

## Capability manifest

Every installed language pack publishes the equivalent of:

```text
language
runtime_version_range
adapter_version
protocol_version_range
framework_modules[]
  framework
  framework_version_range
  status
  endpoint_discovery
  static_inference
  launch
  attach
  standard_frames
  focused_line_cursor
  focused_locals
  async_correlation
  database_interactions[]
  outbound_interactions[]
known_limitations[]
```

The daemon stores this manifest with every runtime session and recording. Replaying an old recording therefore uses the historical capability facts rather than the currently installed adapter's claims.

## V1 Node.js architecture

### Startup and loading

- CommonJS starts through an X-trace `--require` preload.
- ESM starts through an X-trace `--import` registration module.
- Modern synchronous Node module hooks are preferred when the runtime supports them. Older supported runtimes use a compatibility loading path declared by the manifest.
- Registration happens before the application entrypoint. Late startup is reported as reduced coverage.

### Correlation

`AsyncLocalStorage` holds X-trace request context through callbacks and promise chains. Worker threads and child processes create separate runtime sessions linked to the parent launch. Correlation gaps are recorded explicitly.

### Framework modules

- **HTTP/HTTPS:** request root, response, status, headers after redaction, exceptions, and outbound requests.
- **Express:** route registration, middleware order, selected handler, errors, parameters, and response.
- **Fastify:** public route and lifecycle hooks, selected handler, encapsulation context, errors, and response.
- **NestJS:** controller and handler identity plus the underlying Express or Fastify execution.

The adapter prefers public framework hooks and isolates unavoidable compatibility code per framework version. An integration cannot call itself Supported when it depends on an untested private router structure.

### Focused replay

Focused capture transforms only repository-owned modules as they load. It inserts bounded observation probes and composes source maps so TypeScript locations point back to authored source. It excludes `node_modules`, generated bundles, eval code, and files denied by policy. If transformation cannot be performed safely, standard replay remains available and the missing capability is visible.

## Adding another language

A language pack can enter Preview only after it provides:

1. signed adapter manifest and generated XTP bindings;
2. runtime launch integration and honest attach capability;
3. at least one base HTTP boundary and one framework module;
4. static/runtime endpoint reconciliation fixtures;
5. request, async, exception, database, and outbound interaction fixtures where applicable;
6. source-location and source-map/debug-metadata tests;
7. redaction, truncation, drop, backpressure, and crash tests;
8. idle, standard, and focused overhead measurements;
9. export conformance for OpenAPI, Postman, and cURL;
10. a published runtime/framework compatibility matrix.

Likely pack composition:

| Language | Runtime boundary | Framework modules |
|---|---|---|
| Python | WSGI and ASGI | Django, Flask, FastAPI, Starlette |
| Ruby | Rack | Ruby on Rails, Sinatra |
| Rust | Hyper and Tower | Axum, Actix Web, Rocket |
| Go | `net/http` | Gin, Echo, Fiber, Chi |

These names are roadmap candidates, not v1 support claims.
