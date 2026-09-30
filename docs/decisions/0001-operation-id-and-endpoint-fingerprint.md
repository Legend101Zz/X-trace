# ADR 0001: Public operation IDs and stable endpoint fingerprints

- Status: Proposed for Slice 1E.3
- Date: 2026-09-30
- Context: `docs/plans/x-trace/03a-domain-and-storage.md` §1 and §2 disagree
  about whether `OperationId` is a public UUIDv7 or a content hash.

## Decision

`OperationId` remains a public UUIDv7 entity ID, as required by §1. It is
allocated when an operation is first persisted and remains stable for that
persisted operation. It is not derived from endpoint content.

Endpoint equality uses a separate deterministic BLAKE3-256 fingerprint. Its
versioned canonical input is the RFC 8949 deterministic CBOR encoding of a
fixed eight-element array, encoded with `minicbor` (pinned in the workspace
lockfile when implemented), not generic Serde map serialization:

```text
["xtrace.endpoint-fingerprint", 1, project_uuid_bytes,
 application_component, "http", binding_key, method, route_template]
```

The UUID is a 16-byte byte string; all other text values are UTF-8 text
strings; the version is an unsigned integer; and the array and all strings
use definite lengths and preferred/minimal CBOR encodings. The fingerprint
is BLAKE3-256 of those exact bytes. This format is the 32-byte internal
matching/uniqueness key, not an ID or API identifier. Persist its format
version and enforce uniqueness on `(project_id, fingerprint_format_version,
endpoint_fingerprint)`. The project UUID in the input and the scoped
uniqueness constraint are intentional defense in depth. Changing
normalization or encoding requires a new fingerprint format version and
explicit migration/reconciliation; it must not silently re-key public IDs.

Handler identity (class/method/symbol) is versioned claim evidence, not part
of operation identity. Handler refactors therefore update evidence or an
operation version while preserving the operation when the canonical endpoint
tuple is unchanged. Competing handlers for one tuple remain claims on one
operation and must not be split into synthetic operations.

For the bounded observed-only Slice 1E.3, the fingerprint only deduplicates
the exact allowlisted `spring-fixture`/`default`/`http`/`POST`/`/orders`
identity within its project. An `OperationId` is assigned on first durable
insertion. A recording without that valid run-scoped context and matched
route remains unmatched; neither a fingerprint nor an operation is inferred
from raw interaction paths. Here `default` is the caller-supplied stable
binding key for the fixture, not a value derived from a request host or a
claim that Gate 3's general virtual-host/base-path normalization is complete.

## Supersession

This ADR explicitly supersedes only the sentence in
`docs/plans/x-trace/03a-domain-and-storage.md` §2 that says, “The ID is
`BLAKE3(canonical CBOR input)`.” Read it as: “The endpoint fingerprint is
`BLAKE3(canonical CBOR input)`.” All listed canonical identity inputs and
normalization rules remain in force. The §1 UUIDv7 rule for public entity IDs
is authoritative. The approved plan file is intentionally left unchanged;
this ADR is the reviewable resolution and does not approve unrelated scope.

## Consequences

- API and persisted references expose UUIDv7 `OperationId`s, never fingerprints.
- Store uniqueness and cross-restart matching use a versioned fingerprint;
  new rows receive a UUIDv7 once and subsequent observations reuse it.
- Before implementation is accepted, commit fixed vectors containing the
  exact CBOR bytes and BLAKE3 digest for a fixed fixture tuple, then one
  changed-field vector for project, component, binding, method, and route;
  prove the bytes are deterministic and handler identity does not affect
  them. The implementation must also update the stale
  `OperationId` comment in `crates/xtrace-domain/src/ids.rs` that currently
  says the ID is computed from endpoint content.
- Fingerprint migration is a storage/domain concern; callers cannot choose or
  submit fingerprints.
