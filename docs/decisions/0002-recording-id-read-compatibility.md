# ADR 0002: Recording ID read compatibility

- Status: Accepted 2026-10-01
- Context: The Java capture bootstrap has historically generated RFC UUIDv4
  recording IDs, while the observed endpoint reader and recording continuation
  cursor accepted only UUIDv7. This excluded real historical captures from
  linked and unmatched observed-recording queries.

## Decision

Observed persisted recording reads and their scope-bound continuation cursors
accept canonical RFC UUIDv4 and UUIDv7 recording IDs. Both versions must retain
the RFC UUID variant and lowercase canonical textual representation where a
string is used. All other versions, malformed widths, non-RFC variants, and
non-canonical cursor IDs remain invalid persisted identity or cursor input.

This exception applies only to `RecordingId`. `OperationId` and `ProjectId`
remain UUIDv7. Recording IDs remain byte-for-byte unchanged through reads,
linked and unmatched projections, sidecar-absent historical records, and
cursor continuation. Reads do not re-key, backfill, or migrate recordings.
Project scoping, endpoint identity, cursor scope, canonical cursor bytes,
privacy controls, and corruption validation remain in force.

The Java bootstrap generates RFC UUIDv7 IDs for new real captures. It uses the
48-bit Unix-millisecond timestamp and RFC version/variant bits, with random
remaining UUID bits. The Node adapter has no real capture producer yet; the
synthetic XTP client already generates UUIDv7 recording IDs. This decision
leaves that fixture unchanged and does not define a future Node producer
policy.

## Consequences

- Existing canonical v4 recordings remain readable in linked and unmatched
  endpoint queries, including legacy recordings without an observation sidecar.
- A continuation cursor may carry a canonical v4 or v7 recording ID while
  remaining bound to its project, query kind, and operation where applicable.
- Invalid recording UUID versions and variants continue to fail closed as
  corruption or invalid cursor input.
- No schema migration, identifier rewrite, object rewrite, association rewrite,
  or backfill is introduced.
- Operation IDs and project IDs continue to satisfy the UUIDv7 contract.
