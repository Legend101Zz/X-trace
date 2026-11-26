# ADR 0017: private owner-reviewed exercise plans

- Status: **proposed**; source lifecycle slice for issue #121, not an executor or release qualification.
- Date: 2026-11-26.
- Refs #121, #7. Supplements the endpoint exercise design in `03d-clients-config-export-verification.md` §8.

## Context

The exercise crate already synthesizes, hashes and previews requests without networking. The CLI still needs a
reachable plan/review/approval lifecycle before the approved viewer can safely expose Send again. A recording does
not establish an absent request body, credentials, or ownership of an application listening on loopback. Approval
must refer to exactly what the operator reviewed and must not silently survive edits or retries.

## Decision

The shared application use case is `xtrace_application::exercise::ExercisePlanService<P>`, backed by the
`ExercisePlanPort` evidence and durable compare-and-swap contract. All methods send zero requests. The port must
verify project, catalog revision, operation and actually linked recording identities; a caller-supplied claim of
observation is insufficient. The CLI port opens the existing initialized, admitted project and reads the real
catalog and recording ports. It bounds recording lookup at 10,000 rows; beyond that it reports binding unavailable,
not unobserved. A later indexed exact lookup can remove this adapter limitation.

The recording sidecar establishes a link between a project recording and a stable operation ID. It has no
recording-time catalog revision or operation version. The owner must explicitly supply the desired catalog
revision and its exact operation version in the plan input. The durable adapter resolves that revision and the
service checks the selected version. A mismatched selected version is rejected. Historical version assertions
are unsupported input fields and are rejected even when their values match the selected catalog. Review names
the observed recording and stable operation separately from the operator-selected catalog projection. Historical
revision and version are null with status `not_observed`. The approval hash covers this selected catalog basis.

Each plan pins an independently generated UUIDv7 identity, project, revision, catalog-projection digest, operation
version, component/binding, observed recording, method, route, target, operator inputs and their provenance,
request body provenance, creation/expiry and execution bounds. The underlying exercise engine still provides
synthesis, effect classification, canonical hashing, item IDs and preview. Credential references are projected as
credential provenance without values before that hash is recomputed. A separate domain-separated BLAKE3 lifecycle
hash covers both the complete private content and the synthesized canonical plan. Approval always names this
complete lifecycle hash. Review rebases the visible item ID on that complete hash, so body-only edits or a recreated
plan also receive different exercise item IDs. The underlying synthesis identities are labeled `synthesis_plan_hash`
and `synthesis_item_id` and cannot authorize a request. The catalog digest is explicitly
a projection digest, not an assertion that every catalog/private claim byte was hashed.

There is one selected operation/item per plan in this slice. It is explicitly selected from an actually observed
recording, rather than applying the broader new/changed/unobserved batch default. Read-only remains a candidate
classification, never a guarantee. Conflicting handlers produce unknown effect. All selected items require explicit
item consent, including read-only candidates. The review projects this requirement per item and as an aggregate.
Only a ready, unexpired Reviewed plan reports that approval is currently available.

The CLI creates independent immutable plans. A second creation leaves existing consent intact. An
explicit edit names the original hash, validates a replacement from current catalog/recording evidence and
creates an independently identified draft. The replacement's immutable content includes the original hash and a
BLAKE3 digest of its exact canonical private state, including prior review and consent. Plans created before this
field existed retain their original serialized content and hash. Restoring a sheet or showing a plan changes no
permission. The possible transitions are

```text
Draft -> Reviewed -> Approved -> Consumed (delivery unknown)
Draft, Reviewed or Approved -> Superseded (one independently reviewable replacement draft)
```

A consumed or expired original cannot be edited. Supersession permanently revokes every item consent on the
original. Its private review reports the replacement hash, replacement creation time and prior phase. Retrying the edit on the original
returns `XTR-EXERCISE-SUPERSEDED` after a committed edit. Show the original to recover the exact successor.
Neither review nor approval transfers to the replacement.

Review pins the exact hash but may show unresolved inputs. Approval requires review, a second explicit confirmation
that the exact target is the operator's ordinary local development application, and the exact item ID set. A missing
body remains `not_recorded`; even a GET requires the operator to choose an empty body or provide one. Missing
parameter values block approval; required path placeholders must be declared explicitly. No value is invented from
schema, source or a recording. Parameters supplied by the operator retain `operator` provenance in the private
wrapper; the existing synthesis engine's scenario source is only an internal projection.

Plans expire exclusively at creation plus a caller-selected lifetime of 1–900 seconds. Review and approval cannot
renew expiry. A trusted adapter supplies wall time; time before creation or the latest transition fails closed.
Explicit review of an already reviewed/approved unexpired plan is idempotent and does not restore or expand consent.
A stored draft phase accepts only its phase tag. Surplus fields prevent reading or changing that private document. On every service load, the phase must match its revision and transition chronology. Approved state must contain
the exact item identity and ready inputs. Consumed plans cannot be reviewed, reapproved or reserved again. `consume_once` performs a durable compare-and-swap
before a later executor could resolve credentials or send. Racing callers get at most one successful reservation.
Loss of the response or a crash after publication leaves delivery unknown; storage or UI code must never reset it
for a retry. No CLI command calls `consume_once` in this source slice.

The only admitted target forms here are plain HTTP origins `http://127.0.0.1:<port>` and `http://[::1]:<port>`, with
an explicit canonical nonzero port and an operator-owned-development assertion. This deliberately excludes DNS,
redirects, proxies, target paths, alternate loopback forms and non-loopback targets. Loopback is not an ownership
proof; the operator assertion is separate. There is no endpoint discovery, scanning or automated runner.

Pinned future execution ceilings are concurrency 1, one request start/second, 10 seconds/request and total duration,
131,072 encoded request bytes, 1,048,576 response bytes, and zero redirects. Supplied UTF-8 body content is at most
65,536 bytes and is JSON or plain text. There are at most 64 parameters, with names at most 128 bytes and scalar
values at most 4,096 bytes; document size is at most 262,144 bytes. These are validation and immutable plan constraints
here; no sender exists to demonstrate enforcement. A later executor must enforce encoded request/response bytes,
concurrency/rate, time and connect-time destination constraints, disable inherited proxies and redirects, and bind
the authenticated action to the exact consumed plan. It must not assume these syntax checks are a network guard.

Credential-shaped inputs and all cookie values require opaque credential-store handles. Handles are bounded
identifiers, not paths, URIs, environment expressions or credential text. No credential resolver is called while
creating, previewing, reviewing, approving or reserving. Best-effort existing secret screening rejects recognizable
literal credentials, including secret-shaped body assignments; it is not a proof that arbitrary text is secret-free.
Operator JSON bodies require unique decoded keys within each object. The entire parsed body passes structural secret screening; the reviewed and hashed input retains its original UTF-8 text. The screening covers both handles and
operator literals. Credential-bearing bodies are unsupported in this slice. Operator inputs and body
bytes are private; their Debug representation is redacted. Review deliberately returns them to the operator and
must never be logged or published as evidence. Handle Debug output is redacted too. Expiration revokes action permission; this slice does not implement
automatic deletion of expired private plan inputs. Retention/deletion remains a separate integration requirement.

The CLI stores plans only under the admitted owner-private project data root in `exercise-plans`, never under the
repository pointer directory. Input JSON must itself be a bounded owner-private regular file under an admitted
private parent. No-follow descriptor reads reject symlinks, hard links and nonprivate files. Invalid JSON diagnostics
are fixed text so parse errors cannot echo content. An admitted lock plus immutable-content comparison and revision
check serializes lifecycle updates. Draft admission reserves enough bytes for the largest reachable private phase. Writes use a private staging
descriptor, file sync, atomic rename and directory sync. The CLI store checks trusted time under the lock both
immediately before the admitted rename and after its durability barrier. A crossing of exclusive expiry prevents
a success acknowledgment. A pre-publication failure cleans up only the staging name that still identifies the
owned open descriptor. A failure with ambiguous publication never removes or rolls back the destination. An
executor will also need a fresh clock check immediately before making the approved request.

Creation, review, approval and reservation serialize through the project lifecycle lock and exclusively create the same owner-private
`pending-lifecycle.json` in the plans directory. Termination before rename can strand at most one new
staging file per project, containing at most 262,144 bytes of private input. A subsequent write refuses an
occupied slot with `XTR-EXERCISE-STAGING`; it never reads the occupant as consent, truncates it, unlinks it,
or searches other filenames. Reads of existing named plans remain available. Recovery is an explicit owner
operation with all plan writers stopped: inspect the occupied name privately, move it to an unused name in
owner-private storage to preserve it, check the named destination plan, then reissue the intended lifecycle
command only if still necessary. Keep unrelated entries and the lifecycle lock in place. Erring on an
unadmitted filesystem entry also leaves it untouched. The owner controls retention of preserved content.

### Atomic edits and interruption

An edit holds the same project lock, compares the entire predecessor with its originally read state, and
checks trusted time before the commit rename and after publication. It refuses an occupied regular lifecycle
staging slot. A separate exclusive empty marker claims the edit scratch and intent names before any private
input is written. A preexisting scratch or intent outside a reservation is preserved. Every edit payload uses the
existing 262,144-byte document ceiling.

The synced intent is the replacement draft itself. The commit atomically renames the active original to
an archive named for the replacement, retaining its exact bytes and removing the live predecessor name.
An older client cannot use this archived approval. Every new client checks the edit reservation while holding
the project lock before reading or mutating plans. If the original still owns its name, recovery abandons the
uncommitted intent. If the archive exists, recovery verifies the original state digest and the replacement hash,
writes a small terminal receipt at the original hash and renames the intent to the replacement hash. Only then
does it clear the reservation. A missing or conflicting output inside a committed transaction is handled by
this fixed recovery protocol. Conflicting bytes are preserved and access fails closed. The descriptor-bound
scratch file within an active reservation may be discarded after interruption. An expired plan is never rearmed.
Recovery after the commit can finish naming an already-expired replacement. Approval still checks its own expiry.

## Reachable CLI

`--project-dir` selects the initialized repository; `--json` requests the private review JSON on stdout. Errors use
stable `XTR-EXERCISE-*` codes with no rejected input echoed. These commands send zero requests:

```text
xtrace exercise plan --input <owner-private-json-file> --project-dir <project> --json
xtrace exercise edit --plan-hash <original-hash> --input <owner-private-json-file> --project-dir <project> --json
xtrace exercise show --plan-hash <hash> --project-dir <project> --json
xtrace exercise review --plan-hash <hash> --project-dir <project> --json
xtrace exercise approve --plan-id <id> --plan-hash <hash> --item <item-id> \
  --confirm-owned-development-target --project-dir <project> --json
```

The input codec is the deny-unknown-fields `CreateExercisePlan` type:

```json
{
  "revision_id": "<catalog-revision-uuid>",
  "operation_id": "<operation-uuid>",
  "selected_operation_version_id": "<exact operation version in the selected catalog revision>",
  "recording_id": "<actually-linked-recording-uuid>",
  "target": {
    "base_url": "http://127.0.0.1:8080",
    "operator_owned_development": true
  },
  "inputs": [
    {
      "name": "id",
      "location": "path",
      "required": true,
      "value": {"source": "operator", "value": "7"}
    },
    {
      "name": "Authorization",
      "location": "header",
      "required": true,
      "value": {"source": "credential_reference", "reference": "local_login"}
    }
  ],
  "body": {"source": "empty_by_operator"},
  "lifetime_seconds": 300
}
```

The sample is illustrative, not valid evidence for any catalog. Other value variants are `{"source":"unresolved"}`.
Every body or input tagged with a no-payload source accepts only its source field. Additional content, references or other members are rejected before any draft is created.
Body variants are `{"source":"not_recorded"}` and
`{"source":"operator","content_type":"application/json","content":"{\"quantity\":2}"}`.
Private input declarations do not assert the catalog has observed those parameter requirements. Transport-control
headers and ambiguous path interpolation are refused. The entire lifecycle hash binds all these choices.

The existing explicitly asserted no-plan `approve --plan-hash abc` and bare `show` calls retain their exit-9
not-implemented fallback. A selected plan takes the implemented path. `exercise run` remains exit 9 because there is
no executor. This preserves the old assertions; it does not claim unselected behavior is a completed feature.

## Authenticated viewer planning

The foreground viewer admits the project once and retains its read-only catalog, recording reader and private
project binding. The CLI supplies a planning callback to the daemon. An explicit draft creation can initialize
the private plan directory. Existing-plan reads and transitions require that directory to exist.
The recording, catalog-export and exercise actions share the viewer's bounded blocking-worker capacity.
An authenticated POST requires the exact viewer Origin, host, same-origin fetch metadata, client header,
session cookie and JSON content type. Bodies and private review responses stay within the local viewer.
The GET show route reads the current private phase. The POST routes create, edit, review or approve.
Approval binds the displayed plan ID and hash, selected item IDs and a fresh owner confirmation.

Send again opens for a linked recording. The operator supplies the selected catalog revision and operation
version, an explicit target, missing inputs and body decision. The sheet holds fields in memory. Reopening it
can show the saved identity and requires an explicit read before displaying its current phase. An explicit saved
edit replaces the original. The service verifies the observed relationship again and enforces expiry and consent.
The recording's catalog revision and version at capture remain unobserved.

The shared credential-shape checks and deterministic JSON encoder live in the IO-free domain crate. Their
export interfaces keep their established public paths. This keeps export catalog projection, application
planning and the exercise synthesis engine in an acyclic dependency graph.

## Remaining work and evidence boundary

The installed browser journey, genuine owner-operated exercise, credential resolution, guarded executor and
observed result linkage remain open. Public evidence contains bounded stage counts. Private review data stays
in admitted owner storage and authenticated local responses.

Fixture coverage includes explicit catalog-version selection for two revisions of one observed operation, a
missing historical version, interrupted staging, consent, edits, tampering, unresolved values/body, expiry, clock rollback, privacy and an
observable barrier-based concurrent reservation race. Real CLI fixture checks reuse admitted initialized projects,
public catalog and recording APIs, an ordinary loopback listener, and assert that no request arrives. Those are
storage/lifecycle fixture checks, not application execution or release qualification. They are compiled locally;
execution belongs to hosted CI. Packaged CLI, installed viewer and an operator-owned ordinary real application still
need complete exact-source hosted qualification before any EXERCISE ledger row can be accepted.
