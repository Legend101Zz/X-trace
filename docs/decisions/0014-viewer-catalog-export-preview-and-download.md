# ADR 0014: Viewer catalog export preview and download

- Status: **Proposed**. The extraction described below does not accept these HTTP, download or resource-policy choices.
- Date: 2026-11-25
- Refs: #102, #7, #32 and #80.
- Related: ADR 0010 (CLI exports), ADR 0012 (shared-contract and privacy review), and the approved viewer brief on #7.

## Context and implemented extraction

The approved viewer chooses OpenAPI 3.1, Postman Collection 2.1, cURL recipes or a developer bundle, scopes the
export to this endpoint or all eligible operations, previews what is included and left out, then saves. Postman
online setup and delivery belong in the terminal. Export is by catalog operation, not by recording.

The CLI already renders all four formats. Its preview writes nothing and reports the actual revision, counts,
filenames, byte counts, per-file BLAKE3 digests, aggregate content digest and omissions. It does not return file
contents or a complete operation inventory. The pure exporter neither accesses storage nor sends or executes
requests. It does not export trace objects, source snapshots or captured request/response bodies.

The first slice moves the existing catalog-read conversion and operation-selection validation into
`xtrace-export::catalog`. That infrastructure crate depends inward on the application's catalog read types;
the application does not depend on the renderer. The caller still admits the project and supplies an already-read
revision, operation views and linked observations. No SQL, filesystem writes or CLI types enter the shared seam.
The CLI retains argument validation, read order, error mapping, output metadata and private file publication.
This slice implements no viewer route, client schema, modal, download or snapshot store.

The existing conversion matches linked observations by exact application component, binding, method and route,
with a positive recording count. It does not use route-only reconciliation or infer a match from a request URL.
Unknown revision entries remain unknown. Selection uses stable operation IDs; the first missing requested ID is
an error before rendering. Existing claim gaps, unavailable policy digest and sanitizer refusals stay explicit.

Catalog revision and runtime observations are separate reads today. A new linked observation can change export
bytes without changing the revision or the catalog-identity digest. Neither the extraction nor a revision ID
alone establishes an atomic snapshot or binds a future download to the preview.

## Proposed authenticated read contract

These choices require review before routes or generated clients are added:

1. Add explicit preview and download operations, provisionally JSON POSTs under `/api/v1/exports/`. A POST here
   requests computation of a read projection, not a filesystem write or application request. Reuse the viewer's
   project binding, cookie session, exact Host and Origin, same-origin Fetch Metadata and client header. Accept
   no arbitrary project path, output directory, remote URL, shell command, Postman credential or workspace.
2. Request one format and either all operations of the selected project revision or one stable operation ID in
   that revision. The visible scope label names the revision; "all" does not promise every recording or the latest
   revision of every catalog scope. An unmatched recording or runtime-only endpoint without revision membership
   has an explicit unavailable reason. Do not substitute a similarly named route.
3. Preview returns the resolved revision, selection, selected versus emitted counts, format, controlled relative
   filenames, byte counts, file digests, aggregate content digest, and omissions. OpenAPI native method/path
   counts can differ from selected counts because colliding scopes use alternate-operation metadata. A future
   operation inventory or bounded file-text preview needs its own documented response budget; CLI metadata alone
   must not be labelled as showing file contents. No host output path is returned.
4. Describe typed missing-catalog/revision/operation, stale-preview, invalid-selection, sanitizer-refusal,
   resource-limit and busy failures. Return fixed safe messages and a request correlation ID. Do not echo raw
   operation input, sanitizer offender paths, claims, credential-shaped keys or underlying SQL errors. The CLI's
   existing error and exit-code contract remains separate and unchanged.

## Proposed binding from preview to save

Prefer recomputation plus digest comparison over retaining export payloads or adding a persistent export store.
The browser retains only preview metadata. An explicit Save action supplies the same format/options/selection,
actual preview revision and expected aggregate digest. The daemon recomputes through the shared seam, checks the
digest before sending artifact bytes and returns an explicit stale-preview result on mismatch. The UI offers
Refresh preview; it never silently downloads a replacement. If the request selected latest, a changed latest
revision also requires refresh; an explicitly selected historical revision remains explicit.

The aggregate exporter digest covers sorted, length-prefixed file paths, logical modes and exact bytes. Comparing
only a revision, operation count or catalog hash is insufficient. Tests must change both catalog and linked-runtime
state between preview and save and verify refusal or an unchanged exact payload, including changes during the
separate reads. This proposal binds the eventual bytes to the preview; it does not claim those reads were atomic.

Recomputation avoids long-lived payload retention and cleanup policy but costs a second render and can legitimately
require refresh during capture. Caching exact rendered bytes would avoid that race but would require explicit
per-session memory, expiry, ownership and shutdown rules. A durable snapshot store is outside this slice.

## Proposed download representation and bounds

For one-file OpenAPI or Postman, propose a direct attachment with a controlled filename and media type. For cURL
and bundle, propose a deterministic ZIP containing exactly the exporter's relative paths: sorted entries, fixed
ZIP timestamps, no machine paths, no extra comments, a fixed encoding/compression choice and non-executable modes.
Archive encoding is a new adapter concern; the exporter still returns its existing file collection. Validate
entry membership and extracted bytes against the preview file manifest and CLI output. Bind logical payload
digests independently of any transport/archive digest. Review any archive dependency separately before adding it.

Downloads use authenticated fetch with the required client header; a plain anchor bypasses that client contract.
The response remains no-store with existing security headers. The browser saves locally only after the explicit
Save action. Neither preview nor save publishes, uploads, executes a recipe or writes an arbitrary host path.
Postman credential setup and online delivery remain terminal-only and separate from local collection export.

Candidate bounds, **proposed for review and measurement**, are the existing 1 KiB JSON request ceiling for a single
endpoint/all request, at most 4,096 selected operations, at most 4,101 files, 8 MiB of aggregate admitted catalog
export input and 16 MiB of rendered payload. The largest file count includes one recipe per operation plus the
cURL index and bundle metadata/other formats. Input admission must apply before unbounded materialization, not
only after rendering. Exceeding a bound is a named refusal, never silent truncation or a complete-looking prefix.
Keep the existing two-worker query lane, busy response and 15-second request lifetime; do not raise deadlines to
make an export pass. Exact aggregate input/output accounting and cancellation must be specified before the HTTP
implementation. Existing per-operation claim limits alone do not bound whole-export memory.

## Verification and open review points

The shared-seam tests are authored read-model fixtures, not packaged or framework evidence. Existing export CLI
journeys must remain unchanged and verify all format bytes, selection errors, privacy and preview/write behavior.
The HTTP slice needs authenticated project-isolation, invalid-input, limits, sanitizer and stale-preview tests.
The modal needs choose/preview/save, focus trapping, Escape, focus return, visible omissions and unavailable reasons,
keyboard/coarse-pointer use and narrow layouts. Final acceptance needs a real framework catalog through the
embedded packaged viewer, actual downloaded byte/digest checks at both scopes and the installed archive journey.

Still proposed: final HTTP names/methods and DTOs; preview inventory/text detail; exact latest/historical behavior;
archive encoding/media/naming policy; resource accounting and measured limits. Adding OpenAPI/client fields is
an additive shared-contract change and needs the reviews required by ADR 0012. No proposal here grants Postman
access, replaces owner acceptance evidence or authorizes publication.
