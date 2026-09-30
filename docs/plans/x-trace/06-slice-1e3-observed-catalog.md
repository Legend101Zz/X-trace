# Slice 1E.3 — observed endpoint catalog for the exact Spring fixture

- Status: Proposed bounded design; not implementation authorization.
- Depends on the merged 1E.1 read/query seam and 1E.2 local viewer.
- Identity decision: [ADR 0001](../../decisions/0001-operation-id-and-endpoint-fingerprint.md).
- Scope: one real `xtrace run` journey against the checked-in Spring fixture.

## User-visible outcome and truth boundary

After the fixture handles a request and persists its recording, the viewer's
left pane lists the canonical HTTP method and exact matched route template for
that operation. Selecting it shows only recordings explicitly linked to that
operation. The CLI uses the same application query service and returns the
same endpoint and recording projections. A legacy recording, or a new start
without the exact fixture context and method/route match, stays visible as
unmatched and has no operation link.

“Observed” here means that an accepted `RecordingStarted` supplied the
exact fixture-approved method and route for a persisted recording. It does
**not** mean that X-trace enumerated Spring's registered handlers. This slice
accepts only the current fixture's `POST /orders` matched-route observation;
it must not imply general Spring discovery, route normalization support,
completeness, or framework support. No source line, handler path, request
URL, or inferred route is shown.

## Contracts and ownership

1. Add the explicit CLI opt-in
   `--observed-endpoint-policy spring-orders-v1` alongside optional paired
   identity arguments
   `--application-component <safe-id> --binding-key <safe-id>`.
   Safe IDs match `[a-z0-9][a-z0-9._-]{0,63}`. These are invocation/run
   context, not project defaults. The exact journey passes policy
   `spring-orders-v1`, component `spring-fixture`, and binding key `default`.
   The policy is a CLI-owned operator assertion selecting a compile-time
   finite rule; it is not cryptographic or trusted adapter provenance and
   does not prove which application/agent produced the event. Another adapter
   given the same complete opt-in and matching fields can match; do not claim
   otherwise. The rule only permits `POST` plus byte-for-byte `/orders` and
   that paired safe identity. Identity arguments alone, no policy, or no
   complete opt-in remains unmatched while capture continues. The only
   unmatched reason codes are `observation_policy_missing`,
   `observation_policy_invalid`, `identity_context_missing`,
   `identity_context_invalid`, `method_unsupported`, and `route_unapproved`.
   Choose the first applicable reason in that order and never include
   rejected input in diagnostics. Unknown policy values map to
   `observation_policy_invalid`; do not retain the value.
2. The adapter's `RecordingStarted.method` and `matched_route_template` are
   the only endpoint observation inputs. A link requires accepted policy,
   exact context pair, method parsed by the existing domain `HttpMethod` enum
   as `POST`, and route byte-for-byte `/orders`. Do not add or claim a general
   HTTP-method or route normalizer in this slice. Every other method/route,
   including empty, unknown, query/fragment, scheme, control byte,
   overlength, or secret-canary input, remains unmatched with a stable safe
   reason and no rejected input retained or echoed. Never derive binding from
   request host/URL.
3. Do not persist or inspect `url_shape` for endpoint association. Never
   derive an operation from XTF interactions, including `Interaction.path`.
   Preserve the existing verified XTF decode path for recording details.
4. Add typed domain identity/fingerprint logic per ADR 0001. The store, not
   the adapter, computes the versioned fingerprint and allocates/reuses the
   UUIDv7 `OperationId`. The accepted policy gates whether the observation
   may link and is retained in the sidecar, but is not part of endpoint
   identity. For this slice fingerprint inputs are the project, exact
   component/binding pair, HTTP transport, `POST`, and `/orders` per ADR 0001;
   do not normalize arbitrary route shapes. Compute no fingerprint for an
   unmatched observation.
5. Add a new `recording_endpoint_observations` sidecar/link table; do not
   rebuild or add endpoint columns to the existing recordings table. A row
   represents the disposition for each new recording start: `linked` with
   accepted policy, component/binding, operation ID, method, and route all
   present and reason absent; or `unmatched` with operation/method/route all
   absent, one stable safe reason code, and only accepted policy/context
   values retained. Enforce both all-or-none shapes with SQL CHECKs and
   project-scoped FKs. Never retain rejected raw values or a digest of them.
   A legacy recording with no sidecar row is unmatched.
6. In one explicit begin-recording SQLite transaction, validate project and
   run context, then first check whether the recording ID already exists.
   Durable replay equivalence uses the existing immutable recording identity
   `(project_id, runtime_session_id, opened_at)` plus the persisted safe
   sidecar disposition/reason and retained safe fields. Return the original
   receipt for an equivalent replay; conflict if this identity, disposition,
   reason, or any retained safe field differs. Rejected raw method/route/
   context values are not retained or hashed, so different rejected values
   that map to the same safe unmatched disposition replay the original receipt
   and do not conflict. For a new recording,
   classify the observation, find or insert the operation only for a matched
   observation, insert recording and sidecar disposition, then commit. The
   sidecar may retain only the accepted policy and exact safe component/
   binding pair, including for a method/route-unmatched row. A failure
   before commit leaves none of these new rows. Later segment/append failure
   may leave a partial recording that remains honestly linked to its accepted
   start observation; preserve existing append/finalize semantics. If an
   existing legacy recording has no sidecar row, never create one on retry or
   infer its old disposition; preserve it as legacy-unmatched and return a
   typed `legacy_observation_absent` replay result.
7. A replay with different rejected raw values but identical immutable
   recording identity and identical safe sidecar fields is idempotent; never
   persist raw inputs or guessable hashes to distinguish those retries. A
   replay with different retained safe fields or disposition conflicts; it
   cannot silently relink a recording. For operation deduplication, enforce unique
   fingerprint and unique canonical tuple `(project, component, binding,
   transport, method, route)`. On insert conflict, load both keys and verify
   the complete tuple matches; a fingerprint-to-tuple mismatch is corruption,
   not a second operation. Application validation and SQL constraints both
   reject duplicate rows inconsistent with that tuple.
8. Keep application ownership: an application `ObservedEndpointQueryService`
   calls typed endpoint/recording read ports; SQLite implements those ports.
   CLI and HTTP viewer both use that same service and DTOs. Neither surface
   queries SQLite directly, and store row types do not cross the app boundary.
   Endpoint DTOs contain `operationId`, `projectId`,
   `applicationComponent`, `binding`, `method`, `routeTemplate`,
   `observation: "observed"`, and `observationPolicy: "spring-orders-v1"`.
   The endpoint-first pane labels the policy as operator-selected and states
   that it does not attest which adapter/application produced the event.
   Component and
   binding are included because they are part of endpoint identity; omit
   neither nor merge equal route strings across distinct identities.
   Recording-list DTOs contain the existing recording summary, nullable
   `operationId`, nullable `observationPolicy`, and nullable allowlisted
   `unmatchedReason` (null for legacy sidecar-absent recordings); no raw
   route, URL shape, handler symbol, or XTF payload is added to list
   projections.

## Storage and isolation

Add one forward-only SQLite migration (v3), preserving existing v1/v2 data:

- `operations`: UUIDv7 primary key, project FK, transport, method, exact
  accepted route, run-scoped application component and binding key,
  `fingerprint_format_version`, 32-byte fingerprint, and creation time.
  Enforce `method = 'POST'` and `route_template = '/orders'` for this slice.
  Unique `(project_id, fingerprint_format_version, endpoint_fingerprint)`,
  unique
  `(project_id, application_component, binding_key, transport, method,
  route_template)`, and `UNIQUE(project_id, operation_id)` for scoped FKs.
- `recording_endpoint_observations`: recording ID primary/FK, project ID,
  disposition, nullable observation policy ID, nullable operation ID,
  component, binding, method, route, and reason code. A composite FK binds recording and operation to the same
  project. SQL CHECKs require component/binding to be both null or exactly
  `spring-fixture`/`default`; policy ID to be null or exactly
  `spring-orders-v1`; and either `linked` with accepted policy, non-null
  operation, `POST`, `/orders`, exact component/binding, and null reason, or
  `unmatched` with null operation/method/route and non-null allowlisted reason
  (accepted policy/context may remain on an unmatched row). Require
  `observation_policy_missing`/`observation_policy_invalid` to have null
  policy, `identity_context_missing`/`identity_context_invalid` to have the
  accepted policy but null context, and `method_unsupported`/`route_unapproved`
  to have accepted policy and exact context. New recordings
  always get one disposition row; existing recordings with no row remain
  legacy-unmatched. The existing `recordings`
  table is otherwise unchanged. Add/verify `UNIQUE(project_id, recording_id)`
  on recordings for the composite same-project FK.
- Index operations by project and endpoint ordering. Index the sidecar by
  `(project_id, operation_id, recording_id)` for endpoint-linked lookup and
  `(project_id, disposition, recording_id)` for unmatched lookup. Index
  recordings by `(project_id, opened_at, recording_id)` for stable keyset
  order; operation association is only in the sidecar.

Use `STRICT`/length/check constraints where supported by the repository's
SQLite compatibility floor and verify foreign keys on open. Open read
connections with `query_only` and the existing repository/root fingerprint
guard. Every query is explicitly project-scoped; a caller cannot select
another project's operation by guessing its UUID. Invalid/missing project
root or a mismatched repository fingerprint fails closed. Endpoint reads do
not mutate application rows, recording bytes, or project pointers; only the
explicit migration transaction changes schema/data, and normal SQLite
read-only sidecar behavior is not treated as an application write.

There is deliberately no backfill: old recordings remain unmatched even if
their XTF happens to contain a path-like value. Do not add catalog revisions,
source revisions, handler claims, or a “complete” catalog snapshot in this
slice; these require the run/revision provenance contract and are deferred.

## Read API, pagination, and errors

Add app queries and projections:

- `ListObservedEndpoints(project, limit, cursor)` returns operation summaries
  ordered by enum method, exact route, component, binding, then
  UUIDv7. Join through a linked sidecar row to project `observationPolicy`;
  an operation without its required linked observation is corrupt, not a
  synthetic observed endpoint. Default 50, maximum 100; SQL fetches
  `limit + 1`.
- `ListOperationRecordings(project, operationId, limit, cursor)` returns
  linked recordings ordered by `opened_at DESC, recording_id DESC`. Default
  25, maximum 50; SQL fetches `limit + 1`.
- `ListUnmatchedRecordings(project, limit, cursor)` returns only recordings
  with no sidecar row or a sidecar disposition of `unmatched`, with the same
  stable recording ordering and page bounds as linked recordings.
- Every paged result is `{ items, nextCursor }`; `nextCursor` is null when no
  further row exists. `items` uses the stable shared DTOs above. CLI JSON
  emits the same shape, so a client can pass the returned token back with
  `--cursor` without a surface-specific cursor format.
- Cursors are opaque unpadded base64url tokens over a versioned JSON cursor
  struct with `deny_unknown_fields`. Bind query kind, project, operation ID
  when applicable, filter/sort, and typed last key. Decode, strictly parse,
  re-serialize, and require byte-for-byte canonical equality; also require
  canonical UUID/key values. Reject
  malformed, stale-version, or cross-project/cross-operation cursors.
  Cursors are not MACed/authenticated and are not a security boundary: editing
  a valid last-key can change page position, but cannot change query scope.
  No offset paging.
- CLI adds JSON `xtrace endpoint list` and
  `xtrace endpoint recordings <operation-id>` projections with explicit
  `--limit` and `--cursor` options, plus the existing recording list with an
  explicit unmatched filter and the same options. Viewer adds
  `GET /api/v1/endpoints?limit&cursor` and
  `GET /api/v1/endpoints/{operationId}/recordings?limit&cursor` and
  `GET /api/v1/recordings?unmatched=true&limit&cursor`; legacy sidecar-absent
  recordings are included as unmatched with a null reason, while newly
  unmatched recordings include their allowlisted reason code. Use the same
  DTOs, limits, ordering, cursor validation, and application service.

Return safe typed errors: endpoint-query input/cursor errors (400; limits
outside `1..=max` are rejected, never silently clamped), unknown
project or operation (404), conflicting replay or legacy-sidecar-absent
replay (`legacy_observation_absent`, 409), corrupt persisted
identity (422), query-lane saturation (503), and internal error (500). The
HTTP error envelope is the existing lowerCamel problem shape with
the request/correlation ID. CLI preserves its established structured error
and exit-code conventions. A rejected capture observation remains a successful
unmatched recording disposition, not a 400. Error text must not echo raw route, path, URL,
header, payload, or database values. Keep the existing local viewer
authentication, read-only behavior, and XTP protocol unchanged.

## Privacy and resource bounds

For this feature, persist only the accepted enum method and exact matched
route as endpoint facts.
Never persist/display actual URL/path, query, body, headers, cookies,
interaction paths, SQL/binds, handler source path, or raw `url_shape` for this
feature. Route input is still untrusted and must pass the exact fixture
allowlist before persistence. Keep endpoint summary payloads bounded to 100
rows and recording pages to 50 rows; detail remains on the existing verified
bounded recording query path. No browser-side whole-catalog or whole-recording
load.

## Acceptance tests

1. **Identity/domain:** UUIDv7 public operation IDs; canonical fingerprint
   vectors assert exact CBOR bytes and BLAKE3 digests for the fixture tuple
   plus changed-project, changed-component, changed-binding, changed-method,
   and changed-route cases; same tuple is stable across restarts and
   handler-symbol changes. Fingerprints never appear in
   JSON/API/CLI output. Update the stale OperationId comment in
   `xtrace-domain/src/ids.rs` as part of implementation.
2. **Migration/store:** fresh install and v2→v3 migration; checksum/version
   validation; preexisting recordings have no sidecar and remain unmatched;
   linked/unmatched CHECK and project-FK constraints; project isolation;
   duplicate canonical tuple and fingerprint conflict verification; rollback
   on injected failure between operation, recording, and sidecar persistence;
   retry of a legacy sidecar-absent recording cannot backfill or link it;
   open/read query-only and repository-root/fingerprint mismatch rejection;
   no application-row writes during reads.
3. **Capture/idempotency:** actual accepted `RecordingStarted` with
   `POST /orders` and args `--observed-endpoint-policy spring-orders-v1
   --application-component spring-fixture --binding-key default` links one
   recording and one operation; duplicate start reuses both; conflicting
   retained-safe-field replay conflicts. Identity args alone, no policy, or
   missing policy always remains unmatched. Missing/invalid policy/context,
   standalone daemon without policy, any other valid `HttpMethod`, any route
   except exact `/orders`, and query/fragment/scheme/control/overlength/secret-canary
   inputs produce the expected unmatched reason without retaining or echoing
   rejected values. Assert docs/UI do not claim cryptographic adapter or
   application provenance; another adapter given the full opt-in may match.
4. **Replay equivalence:** compare incoming immutable recording identity
   `(project_id, runtime_session_id, opened_at)` and safe sidecar fields.
   Two different rejected raw methods/routes/contexts that collapse to the
   same unmatched disposition, reason, and retained safe fields return the
   original receipt. No raw value or raw-input digest is stored. A change in
   immutable identity, policy/disposition/reason, or any retained safe field
   conflicts; sidecar-absent legacy recordings are never backfilled.
5. **Application/CLI/HTTP:** both surfaces use the same application service
   and serialized DTO contract; project-bound operation lookup; exact stable
   ordering; first/next/empty pages; invalid, stale, non-canonical,
   extra-field, cross-project, and cross-operation cursor rejection; a
   well-formed edited last-key remains scope-bound; limits outside `1..=max`
   are rejected;
   100/50 limits are enforced in SQL, not after loading.
6. **Privacy/corruption:** use canaries in actual URL, query, header, body,
   `url_shape`, and XTF `Interaction.path`; assert absent from operations,
   sidecar columns (including unmatched rows), DTOs, CLI output, HTTP JSON,
   errors, logs, and browser storage. Corrupt method/route/fingerprint/tuple
   rows fail closed with safe correlation.
7. **Product journey:** launch the exact checked-in Spring fixture through
   `xtrace run` with a real request and all three explicit opt-in values;
   verify persisted recording and endpoint
   after process restart; open viewer and show endpoint-first list, then only
   its linked recording, then existing verified recording detail. Verify an
   older/unmatched recording remains separately identifiable. Other fixture
   routes remain unmatched under the exact-route policy; do not synthesize
   their visibility from source scanning. Assert the UI labels the operator
   policy and disclaims adapter/application attestation. Do not say discovered,
   complete, supported generally, or handler-registered.

## Non-goals and rollout

No static scanner or path hypotheses; no general runtime handler discovery or
`EndpointClaimBatch` processing; no completeness/reconciliation, revisions,
history, handler/source evidence, endpoint health, request-value capture,
XTF frame replay changes, TUI, broader framework support, or changes to XTP.
The existing recording-start idempotency check is extended only to include
the immutable accepted endpoint association described above. This projection
does not complete Gate 3's versioned claim/revision/catalog-history contract.
This slice proves a truthful observed endpoint/recording relation for the
exact fixture only. Keep the UI visibly scoped to “Observed” and preserve an
“Unmatched recordings” path.

Roll out in order: merge the identity ADR; implement and test migration/domain
and store transaction; wire the existing capture use case; expose the shared
application query and CLI; connect the viewer and run the real browser journey.
Do not call the slice done until the exact fixture journey, privacy canaries,
restart persistence, query-only/project-isolation checks, and bounded paging
pass. Revisit broader catalog/revision work only through the approved Gate 3
and Gate 4 design/review process; this proposal does not edit or supersede
those plans beyond the single identity sentence documented in ADR 0001.
