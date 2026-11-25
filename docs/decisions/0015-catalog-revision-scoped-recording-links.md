# ADR 0015: Link recordings to a selected catalog revision

- Status: Proposed for issue #112, part of #4. Review the storage and read contract before activation.
- Date: 2026-11-25
- Related: ADRs 0001, 0002, 0005, 0010 and the bounded Spring observation contract in Slice 1E.3.

## Decision

Add the explicit operator-selected policy `runtime-route-v1` to `xtrace run`. Its scope is one
project, a pair of safe application component and binding IDs, and the immutable catalog revision
selected by `--observed-endpoint-revision <uuid>`. The launcher supplies the typed revision and
normalization dialect to the daemon's observation context. The first dialects are Spring MVC and
Express. Java still requires resolved application scope. The selected revision must be a complete
local static scan of the same project, component, binding and dialect. There is no implicit use of
the latest revision. An unknown, wrong-scope, or missing revision leaves capture available with a
named unmatched disposition. An invalid CLI UUID is a validation error without the rejected value.

The adapter's `RecordingStarted.method` and `matched_route_template` are the input facts. No URL,
host, event path, handler name or later event can supply or repair a missing start template. Express
uses its decorated route and observable literal or declared-parameter mounts. Spring MVC uses the
framework's matched-pattern attribute. The run policy is an operator assertion. It establishes the
selected scope and does not attest framework or application identity.

At the application boundary use a typed selection with a `CatalogRevisionId` and a closed
`SpringMvc | Express` dialect. Raw CLI policy values enter classification as absent, invalid,
`SpringOrdersV1`, or `RuntimeRouteV1`. Model successful and unmatched dispositions as separate
variants. A success carries the scoped `OperationId`, accepted method and canonical catalog
template. An unmatched result carries a closed reason and only context approved for that reason.
Store conversion and JSON projection use explicit string mappings for stable public values.

The first slice accepts bounded slash-prefixed literal segments and whole, simple named parameters
in the launcher dialect, plus the explicit root `/`. Refuse absent, empty, concrete URLs with query or
fragment, control bytes, repeated/trailing separators, percent escapes, wildcards, optional
segments, regex constraints and ambiguous forms. Use the existing dialect normalizer after
eligibility checks. Match the canonical method and identity already present in the pinned revision
with the **full** project/component/binding/transport/method/template tuple. A removed or unknown
revision entry or one with competing handler symbols is ineligible. At scan time, record positive
eligibility only when the accepted static declarations all substantiate the bounded route form,
have compatible literal and parameter shapes, and carry no unresolved mount or computed route
limitation. The current stored claim keeps the normalized identity and can discard distinctions
such as a regex constraint. Use the scanner's bounded pre-normalization facts to make this
decision. The eligibility marker stores no raw declaration. Revisions created before the marker
was introduced remain readable and require a new scan to qualify for runtime linking. Never
pattern-match a concrete request path against declarations. Only
the catalog's resolved canonical tuple is persisted on success. The matching operation's UUIDv7
and fingerprint are validated and reused. Matching establishes the operation identity, not the
controller's identity, discovery completeness, or coverage of another binding.

## Recording and migration

Use the next migration number, v11 as of `4c3002a`. The six historical SQL cases exercise the
unregistered rebuild of the v3 projection. Preserve all v1–v10
labels and checksums and copy every existing observation and operation byte-for-byte. Existing
UUIDv4/v7 recordings, absent sidecars and historical nulls stay as they are. Production tests must
exercise an actual registered migration on v10 and independently exercise bounded FK and null
shapes. Existing SQL checks stay in place as groundwork evidence.

Keep the existing observed operation and disposition projections. Broaden the operation
projection's structural bounds and, on the first successful runtime link, mirror the existing
catalog operation with the same UUID and fingerprint. Static scan alone does not populate the
observed listing. Preserve the existing `spring-orders-v1` rule and its fixture alias. Enforce the
project and complete endpoint tuple in the operation link FK. Runtime links also carry the
matched fingerprint as a consistency witness. Composite FKs ensure the same fingerprint is
present on both the observed alias and the exact canonical catalog tuple. Legacy and unmatched
rows keep a null witness. Add a nullable
`catalog_revision_id` to the observation sidecar. A separate eligibility table binds the scanner's
positive route decision to the immutable project/revision/operation member. A new runtime link
must reference both the project-scoped revision and that eligible member. A qualified unmatched result
can retain a validated revision and its exact scope; an invalid revision or identity cannot.

Classification, alias creation, the recording and its sidecar share the existing immediate
transaction. Existing start retries verify the original recording identity and classified safe
disposition, using the explicit pinned revision. Another revision cannot move an existing link.
A repeated start with equivalent rejected inputs receives the same result; rejected routes and
their digests are never retained, logged, or echoed. Legacy sidecar-absent starts remain absent on
retry. Current scan, stale UI state and concurrent scan publication cannot cause a historical
recording to be reclassified. Keep the project's existing query cursor order and bounds.
Fixture endpoint positions keep their v1 cursor. General endpoint positions use v2 with
canonical-template and scope checks, while preserving the same sort and project binding.

## Additive read contract

Retain the endpoint and recording DTOs and fields. Widen endpoint component, binding, method and
template from fixture constants to bounded catalog identity values, and policy from its fixture
constant to a two-member vocabulary. For an aggregate operation with valid links under both
policies, use `spring-orders-v1` as its representative policy. Per-recording policy always describes
that recording's own sidecar. `operationId`, `observationPolicy` and `unmatchedReason` retain their
null behavior. A recording-detail link field is outside this slice; list and operation-recordings
queries expose the link and detail remains the existing exact-ID read.

Keep the existing unmatched codes. For the runtime policy, use `catalog_revision_unavailable`
for a missing, inaccessible, incomplete, non-static or wrong-scope revision; `method_unsupported` for an unsupported
method after resolving scope; `route_template_unavailable_or_ineligible` for missing or ineligible
template syntax; and `no_catalog_match` for a safe canonical identity absent or ineligible in the
selected revision. Use that precedence after policy and identity checks. Persist only closed
reasons and fields validated for that disposition. The selected revision ID is audit metadata in
the store; no new required response fields are proposed. Coordinate the OpenAPI widening,
generated client and labels with the viewer owner before turning on production behavior. Older
responses remain valid instances of the widened schema.

## Verification

- Make real scans and launches with public CLI entry points. For Express, drive a mounted parameter
  route with different concrete values and verify exactly one scoped operation, its original UUID
  from `catalog list`, and only the linked recordings in `endpoint recordings`. Read each recording
  by its exact ID after restart. Exercise Spring MVC parameters with the same contract.
- Prove scope mismatch, unscanned route, unresolved mount/no route, default policy absence and
  rejected template cases without leaking seeded URL/query, raw route, or identity values. Check
  SQL strict shape handling and the migrated old row bytes, project isolation, idempotency after a
  subsequent scan, and the legacy Spring policy and null projection.
- One focused sponsored Linux proof should cover the real product path and both framework
  fixtures that this slice claims. Archive-installed acceptance, general runtime registration,
  historical reconciliation, and broader framework scope remain part of their tracked work.
