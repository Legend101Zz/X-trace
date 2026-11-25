# ADR 0013: Observed exception cause types

- Status: Proposed for #52. The capture mechanism and final schema need independent review.
- Date: 2026-11-25
- Extends ADR 0003's recorded-outcome evidence rules and the optional event exception payload.

## Context

The Java adapter already records the type of a throwable leaving a frame. The store, read API and replay show
that type without projecting exception message or stack text. The current wire payload carries no cause chain.
An outer servlet wrapper can therefore hide the condition the Petclinic scenario is meant to verify. Separate
throw events, matching type names, adjacent frames and stack strings cannot establish a cause relationship.

## Proposed contract

- Extend the event exception payload with an optional, ordered observation of cause type names. The first entry
  identifies the immediate cause of the outer type. The payload excludes messages, stack traces, suppressed
  exceptions and values. An older or unsupported adapter can omit the observation.
- Cap the observation at eight causes and at the existing 256 UTF-8 bytes per type. Retain only the consecutive
  prefix the adapter could observe. A shortened type name does not establish the identity of the cause.
- Represent an observed end, an unobserved end and a bound reached as distinct states. A verified end with zero
  entries means the adapter reached the end at the outer throwable. Absence means the adapter did not record a
  cause observation. A cycle or an unreadable cause leaves the end unobserved.
- Apply the bounds before the adapter queues an event and again at ingest. Keep recorded types in the existing XTF
  event. No SQLite migration or history backfill is required. Add an optional bounded read-API representation.
  Keep the terminal outcome and historical projection compatible. Regenerate the Node protocol, TypeScript client
  and embedded viewer assets with their existing generation steps when the contract lands.

## Capture and privacy constraints

A capture hook cannot invoke an application override of a throwable accessor, block on an application-owned
monitor, retain a throwable in its queue or defer traversal of the throwable to the writer. In particular,
`Throwable.getCause()` is synchronized even when no subclass overrides it. A candidate capture mechanism must
show that it can read a supported JVM's standard cause relationship without acquiring that monitor. A narrowly
scoped JDK field read is a candidate for review. Any change to module opens requires explicit review of the
module access and a fail-open unavailable result on unsupported JVMs. Reflecting on a subclass field or guessing
the relationship from a nested exception is outside this contract.

The read API and viewer expose only bounded type names and the observation state. No sanitized-message or stack
projection is added. A cause with an unsupported or unobserved suffix can still prove an expected type that
appears in its observed prefix. It cannot prove absence of a type beyond that prefix.

## Verification before integration

- Use a real wrapped Spring response to show the expected application type behind its outer throwable.
- Verify the cap, cycles, oversized names, application-defined accessors, a contended throwable monitor, an
  unsupported capture path and older recordings. The application must remain fail-open.
- Verify persisted throw events in the read API and viewer. Inject a canary in a cause message and verify no
  cause message or stack text reaches the event or replay projection.
- Keep the viewer work coordinated with #78 and #89. A packaged Petclinic judge may pass a wrapped exception only
  when the expected type is in its recorded cause chain. Existing unavailable outcomes remain visible.
