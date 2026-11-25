# ADR 0014: Viewer catalog export preview and download

- Status: **Proposed**. The extraction described below does not accept these HTTP, download or resource-policy choices.
- Date: 2026-11-25
- Refs: #102, #7, #32 and #80.
- Related: ADR 0010 (CLI exports), ADR 0012 (shared-contract and privacy review), and the approved viewer brief on #7.

## Context and implemented exporter seams

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

The CLI reads the revision and linked observations separately. A new linked observation can change export bytes
without changing the revision or the catalog-identity digest. The viewer exporter accepts an already-read
snapshot with full-revision identities and selected operation views. The full identity set supplies the same
catalog digest and application name the CLI uses. Claims and exact linked operation membership apply only to
the selected views. For the same resolved revision and linked evidence, both paths use the same projection
semantics and renderer. The CLI keeps its existing default revision selection. The viewer store reads one
snapshot, and the pure exporter relies on the caller for project admission.

Viewer Latest means the last committed catalog publication for the admitted project, across scopes. The store
seeks the highest ordinal in each scope through the existing index and selects the last inserted scope head.
SQLite assigns the hidden rowid when the append-only publisher inserts each revision in a serialized write transaction.
That internal ordering survives normal reopen and WAL checkpoint. Revision UUID and wall time remain independent
of publication order. SQLite rowids remain internal to the store. Current supported workflows do not rebuild
catalog revision rows. Any future catalog retention, compaction or migration that rewrites rows must preserve
publication order or establish an explicit sequence before using it for Latest. External database rewrites,
including `VACUUM`, are outside this guarantee.

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
3. Preview exposes format, options, resolved revision and selection, selected and emitted operation counts, and
   the byte count, logical mode and exact-byte digest of each file. OpenAPI counts native method/path slots, which
   may be fewer than the selected operations when alternate scopes are attached to a native slot. Fixed artifact
   paths and recipe paths containing only an ordinal, a standard HTTP method and the fixed `root` slug are shown
   as actual relative paths. Other recipe names embed catalog route text, even when their characters and shape
   pass filename checks. Preview returns an explicit filename-withheld state and the recipe ordinal for these
   entries. The raw path is available only in the existing saved artifacts and is included in the aggregate
   digest. Omission entries are grouped by fixed subject and reason and applicable format, with every entry counted. Extra
   reason text, operation IDs on omission entries, parameter and example names, and sanitizer paths stay out of
   preview. Unknown reasons use a fixed `other` group. A future operation inventory or file-text preview needs its
   own response budget. The preview contains metadata and no file contents or host output path.
4. Describe typed missing-catalog/revision/operation, stale-preview, invalid-selection, sanitizer-refusal,
   resource-limit and busy failures. Return fixed safe messages and a request correlation ID. Do not echo raw
   operation input, sanitizer offender paths, claims, credential-shaped keys or underlying SQL errors. The CLI's
   existing error and exit-code contract remains separate and unchanged.

## Preview-to-save binding

The pure viewer exporter recomputes the artifact at Save. The browser retains preview metadata and the approval
value. An explicit Save supplies the same format, options, selection and revision-selection policy, along with
the resolved preview revision and a versioned approval digest. The caller rereads the admitted project, resolving
latest again or reading the same explicitly requested historical revision. It also reads linked observations
again. A valid new snapshot is compared with the approved revision and digest before releasing the exact file
collection from that render. When the approved projection changes, the UI offers Refresh preview.

The approval digest includes resolved revision and ordinal, requested revision policy, scope and selected ID if
present, format/options, selected and emitted counts, the safe file inventory, total bytes and the grouped
omissions. It also includes the existing exporter content digest over sorted, length-prefixed actual file paths,
logical modes and exact bytes. Two projections can have identical files but distinct safe omissions or other
approval metadata. A latest revision change also requires refresh even if the observed files match. For a
historical choice, a newer available revision leaves the explicit historical choice intact. The digest does not
authenticate the project or session, authorize a request, or prove which bytes a browser displayed. The HTTP
adapter owns admission, request validation, safe responses and delivery.

Recomputation costs a second render and can require refresh during capture. Retaining exact rendered bytes
would require per-session memory, expiry, ownership and shutdown rules. No payload is retained between the two
calls by the exporter seam.

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

The viewer exporter refuses supplied snapshots above 4,096 revision members, including endpoint-scoped reads,
and refuses rendered results above 4,101 logical files, 16 MiB aggregate logical file bytes or 32,768 raw omission
entries. Latest refuses projects above 4,096 catalog scopes after a bounded index walk. An explicit historical
revision uses a point lookup and remains available under the other export limits. The file limit covers one
recipe per operation plus the cURL index and bundle metadata/other formats.
The raw omission limit applies before grouping, so the safe preview contains only a fixed vocabulary of subject,
reason and format combinations. These checks reject the whole projection. The byte and omission checks run after
rendering and do not bound the renderer's peak allocation. Input admission must apply at the catalog read.
Measure the full read and render path before accepting these budgets for HTTP. The existing 1 KiB JSON request
ceiling, two-worker query lane, busy response and 15-second request lifetime remain the proposed transport
constraints. Exact response-encoding bounds and cancellation behavior need HTTP review.

## Verification and open review points

The shared-seam tests compare actual renderer files for both scopes and every format against the CLI preparation
path. Authored snapshots exercise changed linked observations on one revision, metadata-only changes, refusal
on malformed selections or resource limits, and safe preview disclosure. Existing export CLI journeys cover its
format bytes, selection errors, privacy and preview/write behavior. Packaged framework verification is separate.
The HTTP slice needs authenticated project-isolation, invalid-input, limits, sanitizer and stale-preview tests.
The modal needs choose/preview/save, focus trapping, Escape, focus return, visible omissions and unavailable reasons,
keyboard/coarse-pointer use and narrow layouts. Final acceptance needs a real framework catalog through the
embedded packaged viewer, actual downloaded byte/digest checks at both scopes and the installed archive journey.

Open questions include final HTTP names/methods and DTOs, any file-text preview, archive encoding/media/naming
policy, transport resource accounting and measured limits. Adding OpenAPI/client fields is
an additive shared-contract change and needs the reviews required by ADR 0012. No proposal here grants Postman
access, replaces owner acceptance evidence or authorizes publication.
