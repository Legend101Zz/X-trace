# ADR 0016: Servlet filter refusal observation before MVC dispatch

- Status: Proposed for #114, under #5.
- Scope: Java launch in a standard synchronous Servlet filter chain.

## Decision

ADR 0005 assigns named request roots to framework handler or servlet service observation. Add a
route-less request observation for a filter chain that returns a refusal before observed service
or dispatcher entry. This covers initial HTTP requests stopped by a filter, such as a security
refusal, even when no Spring handler received the request.

The standard `FilterChain.doFilter` seam owns this fallback. An outer chain must have been
observed from entry to normal exit with dispatcher type `REQUEST`, an allowlisted HTTP method,
and positively observed synchronous state. At least one standard filter must have executed,
and its result must be an observed 4xx or 5xx where the entry status was below 400. A servlet
service, MVC dispatch or handler entry, a continuation dispatch, an async start attempt, an
escaping exception, or a known boundary instrumentation failure disqualifies this fallback.
Existing mapped-handler capture retains its admission and owns its recording. Attach does not
admit the fallback.

Emit one root at exit. The start clock is the observed outer chain entry, so elapsed time covers
that interval. A filter that changes the response after a downstream servlet/handler was entered
does not get another root. The existing ADR 0003 terminal rule applies. Normal synchronous
return establishes status when no error handling is pending. An observed `sendError` gives
provisional status evidence and an unobserved HTTP outcome.

Use the existing absent route and URL shape representation. Request metadata consists of the
allowlisted method and observed boundary and outcome evidence. Record no URI, query, headers,
body, principal, route template, handler, or inferred events. It produces no observed endpoint
or catalog link. Completion refers to the recorded boundary, and contains no claim about work
inside unobserved parts of the request.

## Evidence and limits

The installed JHipster run in #105 (45670018313, product d5518db) exposed pre-dispatch misses.
That campaign remains separately qualified. This change does not claim async correlation,
generic Servlet/Jersey handler entry, or a new supported version or release row. This ADR
introduces no protocol, schema, SQLite, endpoint identity, or replay vocabulary changes.
