# Product: X-trace

## Problem

A developer joining an unfamiliar backend application can usually find its API list, but cannot quickly see what the application actually does after a request arrives. Using a debugger requires knowing how to start the application, preparing its dependencies, choosing useful breakpoints, and repeatedly stepping through framework code. Existing tracing products are optimized for operations and performance, while code debuggers are optimized for live investigation. Neither gives a newcomer a simple endpoint-by-endpoint replay of the code path.

X-trace should make the first useful question easy: **"When this endpoint is called, where does the request go?"**

## Success metric

In a usability study with developers who have not previously worked in the sample repository, at least **80% must locate an endpoint and correctly explain its recorded controller-to-outcome path within 10 minutes, without setting a breakpoint or configuring an IDE debugger**.

Measure this with a timed onboarding exercise across representative Java and Node.js backend applications. A correct explanation must identify the entry point, at least one important intermediate call, the final response or failure, and any recorded database or external-service interaction.

## Announcement - the blog post before the feature

X-trace turns a backend application into an explorable map of its API behavior. Open an endpoint, choose a recorded request, and replay the execution through source code one step at a time. The current line, call stack, values, database work, and external calls move together on a spatial canvas or code-first linear replay. Run the application through X-trace and it adds endpoint recordings as requests occur. Instead of spending the first hour configuring breakpoints, a new developer can begin with the paths the application has already taken.

## Core user promises

1. **Start from the endpoint.** The user does not need to know which controller, class, or breakpoint matters.
2. **Replay, do not merely diagram.** Moving through a recording updates the current source location, call stack, values, and interactions together.
3. **Show evidence honestly.** Discovered endpoints, possible paths, and observed executions have visibly different states.
4. **Stay out of the way.** Recording runs in the background during normal local development and testing.
5. **Keep the source local by default.** Captured requests and values are treated as sensitive development data.
6. **Cover real backend applications.** V1 must work well for Spring Boot, Spring web, Servlet, Node HTTP, Express, Fastify, and NestJS applications.
7. **Meet the developer where the process already runs.** First release supports both launching through X-trace and best-effort attachment to a compatible running JVM.

## Primary journey

1. A developer opens a Java repository and starts X-trace.
2. X-trace identifies the application, lists its endpoints, and shows clearly labelled inferred paths where static analysis has enough evidence.
3. The developer starts the application with recording enabled, or explicitly attaches to a compatible running JVM.
4. The developer uses the application, runs tests, or sends requests with an existing API client.
5. X-trace adds a recording to the matching endpoint whenever a request completes.
6. The developer opens the local X-trace interface.
7. The developer selects an endpoint and a recorded scenario.
8. The developer chooses either a spatial Canvas or a conventional Linear trace. Both are views of the same selected frame and recording.
9. Replay shows the request moving between the web entry point, application code, data access, external systems, and response.
10. Replay controls move forward, backward, into, over, or out of calls while the exact source line, values at that line, and value changes update together.
11. The developer can distinguish endpoints with observed recordings from endpoints that only have inferred paths or still need a scenario.
12. When the user explicitly requests it, X-trace can exercise eligible endpoints using a reviewed plan and safe defaults; it never silently sends mutating requests.
13. The developer can export the endpoint catalog and sanitized examples for use in Postman.

## Endpoint states

- **Discovered:** X-trace knows the endpoint exists, but no request has been recorded.
- **Recording:** a matching request is currently being captured.
- **Observed:** at least one completed execution is available for replay.
- **Failed capture:** a request occurred, but the recording is incomplete or invalid.
- **Needs setup:** the endpoint requires authentication, data, or another prerequisite before it can be exercised.
- **Excluded:** the user or project policy intentionally prevents recording it.

## Initial scope

### Included

- Local development use
- Endpoint discovery
- Clearly labelled static/inferred endpoint paths before a recording exists
- Passive recording while the application handles requests
- Recording from integration-test execution
- Best-effort attachment to a compatible running JVM
- User-requested automated endpoint exercising with preview, scope controls, authentication inputs, and mutating-request safeguards
- Multiple recorded scenarios per endpoint
- Read-only execution replay
- Source-code stepping
- Call stack and relevant values
- Database and outbound HTTP interactions
- Exceptions and unsuccessful responses
- Background recording status and endpoint coverage
- OpenAPI and Postman-compatible export with sanitized examples
- One sanitized cURL command per endpoint plus a combined script
- Spring Boot, Spring web, and Servlet applications
- Node.js HTTP, Express, Fastify, and NestJS applications

### Not included in the first release

- Editing code from the replay
- Changing variable values
- Arbitrary expression evaluation
- Breakpoint management
- Production monitoring
- Automatically exercising endpoints without an explicit user request and reviewed scope
- Sending mutating requests without explicit configuration and confirmation
- Claiming that every discovered endpoint has been executed
- A codebase chatbot
- Required cloud upload or team account

## Screens

- `mockups/terminal.html` - installation, project initialization, application launch or attach, live capture status, endpoint coverage, and opening the viewer.
- `mockups/web-canvas.html` - a three-region workspace: endpoint/scenario context, switchable Canvas or Linear execution navigation, and synchronized source evidence with values shown at the active code line. Selection and playback position remain stable when switching views.

## Approved product decisions

Approved on 2026-09-28:

1. Best-effort attach-to-running-JVM belongs in the first release, alongside the more reliable launch-through-X-trace path.
2. X-trace shows inferred static paths before a recording exists, with unmistakable provenance and no implication that they were executed.
3. Automated endpoint exercising is available at the start when the user explicitly requests it. Passive capture and test capture remain the default paths.
4. The initial usability target remains 80% of new developers correctly explaining one endpoint within ten minutes.
5. The web viewer uses three stable regions and supports Canvas and Linear execution views. Source and recorded data are synchronized at the active line.
6. Java and Node.js are both v1 language families. Support is published per language, runtime, framework, version range, and capture capability.
7. Local catalog revisions retain endpoint additions, changes, removals, and immutable run history. Scans, capture sessions, exercise runs, exports, and Postman uploads start only through explicit user actions.
8. Web and TUI expose OpenAPI, Postman, cURL, and combined export actions. Connected Postman upload requires an explicit preview, credential, and workspace choice.
