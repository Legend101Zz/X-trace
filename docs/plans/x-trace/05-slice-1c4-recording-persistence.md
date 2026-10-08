# Slice 1C.4: recording persistence and XTF commit seam

**Status:** proposed implementation phase; planning only, 2026-09-29
**Depends on:** Slice 1C.3, merged through f1577d5
**Phase gate:** implementation requires explicit user approval of D-3, D-4, and D-5.

## Purpose and honest boundary

Slice 1C.3 ends at authenticated, volatile ingress: each daemon Session owns an
IO-free IngestValidator, stages accepted envelopes, and sends only Staged ACKs.
There are no SQLite recording rows, XTF objects, recovery, or Committed ACKs.

1C.4 adds only a storage seam: v0002 recording/segment metadata, public typed
storage-local begin_recording and commit_segment behavior, canonical XTF v1
encoding, crash-safe publish-plus-SQLite commit, and deterministic store tests.
It does not drain the daemon queue, alter XTP, transition recording state,
recover/retain objects, build replay/query indexes, snapshot source, or expose
CLI/API/UI behavior. It is not a real capture journey claim.

| Existing seam | Code-proven state | 1C.4 consequence |
|---|---|---|
| xtrace-domain | Owns RecordingId, RecordingState, Recording, ContentHash; IO/protobuf-free. | No domain changes are expected: receipts use existing IDs. |
| xtrace-application | Has no recording use case. | No application port, type, or file change. A future application port belongs to daemon integration/use-case work. |
| xtrace-ingest | Validates typed generated recording messages and event retries without I/O. | Unchanged. Its event retry is distinct from object commit idempotency. |
| xtrace-protocol | Recursively compiles schema/proto and exports generated XTP agent types. | Add a distinct generated XTF module; do not change any XTP wire schema. |
| xtrace-store | Has mutex-serialized SQLite, WAL/synchronous=NORMAL, strict v0001 and checksummed migrations; no object store. | Own public begin/commit operations, XTF, filesystem, and SQL. |
| xtrace-daemon | Session has bounded staged queue and Staged ACK. | No daemon/session/ACK/integration-test change. |

## Ownership and executable storage-local behavior

~~~text
1C.4 direct store tests -> xtrace-store storage-local API
xtrace-store -> xtrace-protocol::xtf generated storage messages -> xtrace-domain
xtrace-domain -> no protobuf/storage/daemon

future 1C.5 daemon composition -> xtrace-application use case/port -> xtrace-store
~~~

XTF is an internal storage format. The store may depend on generated XTF storage
messages because it owns XTF encoding and verification. The domain remains
protocol-free. The later daemon translator builds typed envelopes from admitted
RecordingEvents; it never gives storage opaque caller bytes. In 1C.4 the API is
directly exercised only by store tests. In 1C.5, a new application port/use case
will own daemon composition; the daemon must not directly call xtrace-store.

The storage-local public API follows existing store repository patterns and
returns scoped RecordingStoreError, not an application PortError:

~~~rust
pub struct BeginRecordingRequest {
    pub project_id: ProjectId,
    pub recording_id: RecordingId,
    pub runtime_session_id: RuntimeSessionId,
    pub opened_at: WallTime,
}
pub struct BeginRecordingReceipt {
    pub recording_id: RecordingId,
    pub disposition: BeginRecordingDisposition, // Inserted | ExactReplay
}
pub struct SegmentCommitRequest {
    pub project_id: ProjectId,
    pub recording_id: RecordingId,
    pub segment_ordinal: u32,
    pub events: Vec<xtrace_protocol::xtf::XtfEventEnvelope>,
}
pub struct SegmentCommitReceipt {
    pub recording_id: RecordingId,
    pub segment_ordinal: u32,
    pub object_hash: ContentHash,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub disposition: SegmentCommitDisposition, // Inserted | ExactReplay
}
impl SqliteStore {
    pub fn recording_store(&self, project_root: &Path)
        -> Result<SqliteRecordingStore<'_>, RecordingStoreError>;
}
impl SqliteRecordingStore<'_> {
    pub fn begin_recording(&self, request: &BeginRecordingRequest)
        -> Result<BeginRecordingReceipt, RecordingStoreError>;
    pub fn commit_segment(&self, request: &SegmentCommitRequest)
        -> Result<SegmentCommitReceipt, RecordingStoreError>;
}
~~~

SqliteStore owns the private writer guard inside its shared Arc state, separate
from the connection mutex, so every SqliteStore clone and every
recording_store view uses the same guard. The guard is acquired before any
continuity read and held through filesystem publish, SQLite commit, and staging
cleanup. The connection mutex remains the SQLite access guard; the shared writer
guard prevents local views from interleaving object publication/continuity.

recording_store(project_root) is available only for an on-disk store. It accepts
only an absolute, owner-only, component-by-component symlink-free project root,
without canonicalize-based symlink acceptance. It also requires the SQLite
bootstrap database path itself to be a regular non-symlink file and its parent
to equal that root. In-memory stores cannot publish objects. Focused tests use
an on-disk TempDir store and cover in-memory refusal, database-parent/root
mismatch, symlink root/component rejection, and symlinked/non-regular database
path refusal.

RecordingStoreError is scoped to this API rather than redesigning existing store
repositories. It exposes code(), kind()/category(), correlation_id(), and a
sanitized source description; it maps/wraps StoreError for SQLite failures and
adds only the recording-object validation, conflict, corruption, permission,
and atomic-install cases described below. It is this new scoped type, not the
current generic StoreError, that supplies the stable XTR-STORE codes.

begin_recording holds the store's same-process writer guard, first checks that
the project exists, then inserts a recording anchor in state recording. A
missing project returns RecordingStoreErrorKind::NotFound before insert. Exact replay
requires equal immutable project ID, runtime session ID, and opened_at; it
returns ExactReplay even if a future lifecycle operation has advanced status.
Any differing request for that recording ID is
XTR-STORE-RECORDING-CONFLICT and changes nothing. A raw foreign-key failure is
still wrapped as RecordingStoreErrorKind::Conflict, sourced from StoreErrorKind::Conflict and reserved for an integrity race/corruption after
the explicit check. The API cannot finalize a recording.

commit_segment holds that same writer guard across validation, filesystem
publication, SQLite transaction, and cleanup. Segment ordinals are zero-based:
the first committed segment must be ordinal 0 and begin at recording_seq 2,
because the structural RecordingStarted marker owns sequence 1. A later new
segment must use the immediately prior ordinal plus one and a first sequence of
the prior last sequence plus one, both with checked arithmetic. If the prior
last sequence is u64::MAX, only an exact replay is possible. Before append or
continuity validation, the store checks an existing primary-key row: an exact
replay remains valid even after later segments exist; a different complete
logical uncompressed XTF stream/hash or metadata is conflict.

For a new segment the store validates nonempty typed events, wrapper/nested
recording_seq equality, strict contiguous ascending sequences, and checked
ordinal/count conversion. It derives range, count, all bytes, and hashes.
There is no caller-supplied opaque byte/count/range field.

Ingest event retry and object idempotency are deliberately different.
IngestValidator may accept retransmitted events before this seam. commit_segment
replays only the complete logical uncompressed XTF stream/hash at
(recording_id, segment_ordinal). Same stream/hash and metadata returns
ExactReplay; same key/different stream/hash or metadata is
XTR-STORE-SEGMENT-CONFLICT. Compressed-byte equality is never identity; zstd
bytes are only decompressed, checksummed, and verified. No cross-recording dedup
promise exists: recording_id and ordinal are in the header, so otherwise
identical events yield different complete logical streams.

Returning ExactReplay always re-opens and fully verifies the object referenced
by the existing row against the complete logical uncompressed XTF stream/hash.
A matching row with a missing, unreadable, or corrupt object is
XTR-STORE-OBJECT-CORRUPT, never success.

## Canonical XTF storage protobuf

Add only:

~~~text
schema/proto/xtf/v1/segment.proto
~~~

It imports but does not alter xtp-agent/v1/recording.proto:

~~~proto
syntax = "proto3";
package xtf.v1;
import "xtp-agent/v1/recording.proto";

message XtfHeader {
  uint32 format_major = 1;
  uint32 format_minor = 2;
  bytes project_id = 3;       // store validates exactly 16 bytes
  bytes recording_id = 4;     // store validates exactly 16 bytes
  uint32 segment_ordinal = 5;
  uint64 first_recording_seq = 6;
  uint64 last_recording_seq = 7;
  uint64 event_count = 8;
}
message XtfEventEnvelope {
  uint64 recording_seq = 1;
  xtp.agent.v1.RecordingEvent event = 2;
}
~~~

Both storage messages are map-free. XtfEventEnvelope wraps the existing
RecordingEvent so the storage encoder has a verifiable sequence boundary and
produces the bytes itself. It rejects wrapper/nested recording_seq disagreement.
No XTP wire message changes.

Smallest protocol/dependency changes:

1. Keep build.rs recursive proto discovery and descriptor output; it compiles
   the new schema from the same schema/proto root.
2. Add a distinct xtrace-protocol/src/lib.rs module:
   pub mod xtf { include generated/xtf.v1.rs; }. Do not nest it in generated
   agent or rename XTP exports.
3. Add xtrace-protocol and Prost to xtrace-store dependencies; add approved zstd
   at root/Cargo.lock/store only. Do not add xtrace-application changes.
4. Protocol tests decode the compiled descriptor set and assert XtfHeader/
   XtfEventEnvelope names, tags, map-free shape, and RecordingEvent import.
   Store tests provide byte-level XTF goldens.

## D-3: recommended XTF v1 decision for user approval

Gate 3 specifies components but not framing/width/hash coverage. Approve this
concrete profile:

1. Header is checked-in map-free xtf.v1.XtfHeader, Prost encoded.
2. Events are store-encoded map-free xtf.v1.XtfEventEnvelope values.
3. Logical prefix: ASCII XTF1; u16 big-endian major=1; u16 big-endian minor=0;
   u32 big-endian header length; then repeated u32 big-endian envelope length
   plus envelope bytes. Oversize/untrusted lengths fail before allocation.
4. Footer: ASCII XTFF; u64 big-endian event count; u64 big-endian first seq;
   u64 big-endian last seq; 32 raw BLAKE3-256 bytes.
5. Footer digest is BLAKE3-256 of uncompressed logical bytes from XTF1 through
   the last event entry, excluding XTFF and all footer fields.
6. Content address is BLAKE3-256 of the complete uncompressed logical stream,
   including footer. Compressed bytes are not address bytes.
7. Persist one single-threaded zstd frame with checksum enabled; full
   decompression verifies the frame checksum and reconstructed XTF hashes.

D-3 is an explicit approval, not a hidden implementation choice. Rejection of
schema, framing/endian, footer coverage, or logical address requires ADR/Gate 3
amendment before code. Shared/public XTF interchange is out of scope.

## D-4: recommended publish/durability decision for user approval

Approve this clarification of the approved atomic-rename step for this phase:

- Official tested configurations are local APFS on macOS and ext4 on Linux CI;
  publish the verified compressed staging file with std::fs::hard_link to the
  content-addressed destination.
  hard_link is the atomic no-replace primitive: success creates the destination
  link, and AlreadyExists triggers full logical-uncompressed-XTF verification.
  Existence alone, or compressed-byte comparison, is never success.
- The staging and object paths must be same-filesystem, owner-only, and
  symlink-checked with create_new/symlink_metadata before every boundary; files
  are mode 0600. After successful hard_link, fsync the destination object
  directory before SQLite. Remove the staging hard link only after SQLite
  commit, then fsync its staging directory. After hard_link succeeds, the
  staging handle/path is never written again; tests pin that invariant.
- hard_link, cross-device, or directory-sync failure fails closed with
  XTR-STORE-ATOMIC-INSTALL. No filesystem-type detector is added: unknown or
  network filesystems are unsupported and receive no durability claim; Windows
  is unsupported. Do not add FFI, atomic-file helpers, or filesystem dependencies
  without separately approved authority; no copy/delete fallback.

The same-process writer mutex spans filesystem and SQL. hard_link no-replace
prevents cross-process overwrite, while broader cross-process lifecycle/project
coordination remains out of scope.

## D-5: staged commit-contract deferral for user approval

The approved final Gate 3 commit protocol requires one SQLite transaction to
insert recording_segments, frame-index rows, recording counters, and an outbox
notification after the verified immutable object is published. 1C.4
intentionally commits only the verified XTF object plus recording_segments
metadata: it has no event-to-frame translation, recording-counter semantics,
notification delivery, or recovery behavior yet.

Approve this as a temporary phase split, not a replacement for Gate 3. Under
the approved slice-change rule in 04-vertical-slices.md section 17, a slice may
be split when review risk is reduced without weakening its eventual outcome.
No ADR or Gate amendment is needed while the final Gate 3 transaction remains
unchanged. 1C.4 must not emit Committed ACK or claim a complete recording
commit. Before any Committed ACK or terminal-state claim, a later approved
phase must extend the transaction to the frame-index, counters, and outbox
contract. If D-5 is not approved, 1C.4 must expand and be replanned rather than
silently treating segment metadata as the full commit.

## Crash-safe commit sequence and failure semantics

1. Validate request, anchor/project relationship, typed events, ordinal/count
   INTEGER ranges, and recording-wide continuity before filesystem mutation.
   First look up the primary-key row: exact replay fully verifies its referenced
   object and returns before append/continuity checks; only a new key proceeds.
   Decode prior fixed-width sequence BLOBs to u64 before checked arithmetic.
   Encode header/envelopes and derive footer, footer digest, and full logical
   address.
2. Create staging/recording-id beneath root with secure production temp names
   or injected test names, create_new, owner-only permissions, and symlink
   checks. Write logical bytes; flush/sync_all; fsync staging directory entry on
   supported Unix.
3. Compress to a separate staging file with zstd checksum/no threads. Reopen and
   fully verify decompression, framing, sequences/count, footer, and address;
   sync_all compressed file and staging directory.
4. On the official tested configurations, atomically publish by std::fs::hard_link from the
   verified compressed staging file to objects/b3/first-two/remaining.xtf.zst.
   AlreadyExists opens and fully verifies the complete logical uncompressed XTF
   stream/hash; only a matching stream/hash is object replay. Path existence or
   compressed-byte equality alone is never success.
5. On supported Unix, fsync destination object directory after hard-link publish and
   before SQLite transaction. This is a mandatory durability boundary.
6. Under existing SqliteStore mutex, one transaction inserts the segment row or
   reads primary-key collision: equal complete logical uncompressed XTF
   stream/hash and metadata is ExactReplay, difference is conflict. Commit. No
   frames/counters/outbox/terminal status/ACK; D-5 records this as a temporary
   deferral rather than the final Gate 3 commit contract.
7. Remove the staging hard link only after SQL commit and fsync its staging
   directory when supported. Cleanup/staging-directory fsync failure is safe
   diagnostic residue, never a reason to erase committed evidence.

Process-crash guarantee: fully verified/synced object precedes a reference;
pre-commit bytes can be orphaned and post-commit row/object are authoritative.
Rollback leaves no row. Power-loss guarantee is narrower: existing
synchronous=NORMAL means object+directory syncing strengthens object publication
but this phase cannot claim the SQLite transaction is power-loss durable.
Future recovery validates references/preserves evidence; no recovery worker here.

## v0002 schema and migration discipline

Append v0002_recording_segments only; bump CURRENT_SCHEMA_VERSION to 2; keep
v0001 byte-identical and retain current ordered, checksummed, transactional
migration runner.

~~~text
recordings(
  recording_id        BLOB PRIMARY KEY CHECK(length(recording_id) = 16),
  project_id          BLOB NOT NULL CHECK(length(project_id) = 16)
                      REFERENCES projects(project_id),
  runtime_session_id  BLOB NOT NULL CHECK(length(runtime_session_id) = 16),
  status              TEXT NOT NULL CHECK(status IN
                      ('recording', 'finalizing', 'complete', 'partial', 'invalid')),
  opened_at           TEXT NOT NULL
) STRICT;

recording_segments(
  recording_id          BLOB NOT NULL CHECK(length(recording_id) = 16)
                        REFERENCES recordings(recording_id),
  segment_ordinal       INTEGER NOT NULL CHECK(segment_ordinal >= 0),
  object_hash           BLOB NOT NULL CHECK(length(object_hash) = 32),
  first_recording_seq   BLOB NOT NULL CHECK(length(first_recording_seq) = 8),
  last_recording_seq    BLOB NOT NULL CHECK(length(last_recording_seq) = 8),
  event_count           INTEGER NOT NULL CHECK(event_count > 0),
  uncompressed_bytes    INTEGER NOT NULL CHECK(uncompressed_bytes > 0),
  compressed_bytes      INTEGER NOT NULL CHECK(compressed_bytes > 0),
  checksum              BLOB NOT NULL CHECK(length(checksum) = 32),
  PRIMARY KEY(recording_id, segment_ordinal)
) STRICT;
~~~

No secondary index is necessary: the composite primary key serves commit
idempotency lookup, and 1C.4 exposes no scan/query. Do not add
UNIQUE(recording_id, object_hash). First/last sequence values use exactly
eight-byte big-endian BLOBs, not INTEGER: store code round-trips every u64
without a lossy cast, and fixed-width big-endian representation preserves
lexical ordering for future indexed/range reads. SQLite cannot enforce numeric
last>=first over BLOBs, so Rust decodes both values before every continuity
comparison/arithmetic; golden and round-trip tests own that invariant.
Header/footer remain uint64; event_count and ordinal remain INTEGER after
checked conversion. The store tests 0, 2, i64::MAX, i64::MAX+1, and u64::MAX
where each is applicable.
runtime_session_id is length-validated but no FK exists because
runtime_sessions/durable admission do not exist; it preserves ownership without
pretending that table does. The API only inserts recording today, but the CHECK
allows every current domain RecordingState string to avoid a future rebuild.

Tests prove fresh v2, v1-to-v2 upgrade, v0001 checksum tamper rejected before
v2 writes, v2 checksum tamper rejected on reopen, newer schema no mutation, and
injected v2 migration rollback. Existing v0001 project/idempotency tests remain
green.

## Scoped errors, diagnostics, and deterministic tests

The following codes/kinds belong to RecordingStoreError only. Existing generic
StoreError remains unchanged; SQLite failures are wrapped with their sanitized
source and mapped kind/correlation ID.

| Condition | Code/category | Result |
|---|---|---|
| malformed IDs/events/range/INTEGER overflow | XTR-STORE-SEGMENT-VALIDATION / RecordingStoreErrorKind::Validation | no mutation |
| different Begin request | XTR-STORE-RECORDING-CONFLICT / RecordingStoreErrorKind::Conflict | preserve anchor |
| same segment key, distinct complete logical uncompressed XTF stream/hash | XTR-STORE-SEGMENT-CONFLICT / RecordingStoreErrorKind::Conflict | preserve evidence |
| new segment violates zero-based ordinal/recording-wide sequence continuity | XTR-STORE-SEGMENT-CONTINUITY / RecordingStoreErrorKind::Conflict | no publish or SQL mutation |
| existing object fails full verification | XTR-STORE-OBJECT-CORRUPT / RecordingStoreErrorKind::Corruption | no replay/dedup |
| permission/create/sync failure | XTR-STORE-OBJECT-IO / RecordingStoreErrorKind::Permission or Transport | remediate/retry |
| XTF/zstd failure | XTR-STORE-XTF-VERIFY / RecordingStoreErrorKind::Corruption | no SQL row |
| unproven atomic install | XTR-STORE-ATOMIC-INSTALL / RecordingStoreErrorKind::Compatibility | fail closed |

Diagnostics may include IDs, ordinal, safe code, byte counts, hashes, and
correlation ID; never event bytes, values, headers, URLs, SQL parameters, source
content, secrets, or payload-derived filesystem text.

Tests use fixed IDs/events and injected names/faults where asserted. Production
may use secure random temporary names. No tests use sleeps, timing, wall-clock
ordering, or random-time assumptions.

| Area | Required evidence |
|---|---|
| Proto/XTF | descriptor/tag/import/map-free checks; byte goldens; malformed lengths; wrapper/nested seq mismatch; range/count/footer mismatch; zstd checksum failure; allowed compression settings preserve complete logical uncompressed stream/hash. |
| Public behavior | begin inserts/replays/conflicts/missing-project; first segment must be ordinal 0/seq 2; gaps, overlap, skipped ordinal, first-seq error, checked max boundary, and exact replay after later segments exist; typed commit read-back; same-key conflict; event replay remains an ingest test, not object idempotency. |
| u64 storage | fixed-width BE BLOB round-trip for 0, 2, i64::MAX, i64::MAX+1, and u64::MAX; continuity after u64::MAX permits exact replay only. |
| Store construction and owner safety | on-disk absolute owner-only symlink-free root bound to SQLite parent; in-memory/mismatched-root/symlink refusal; official APFS/ext4 0600 dirs; hard_link no-replace; full existing destination verification; denied root no row; concurrent same-process calls and AlreadyExists publish race; staging path never written after hard_link. |
| Fault boundaries | before logical write; after logical sync; before/after compression; after compressed sync; before/after hard_link; after object-directory fsync; before transaction; before commit; after commit/before staging-link cleanup; staging-directory fsync. No row references missing bytes. |
| Orphans | transaction rollback no row/at most verified orphan; failed stage no final object; retry cannot delete verified object; cleanup stays under root. |
| Migration/quality | all v2 upgrade/tamper/rollback cases; rustdoc; no production unwrap/expect/panic/unsafe; no application/daemon change; deterministic tests; no Committed ACK/terminal-state claim under D-5. |

## File sequence and review

1. Add schema/proto/xtf/v1/segment.proto only.
2. Update xtrace-protocol build.rs/lib.rs and tests for distinct xtf module,
   descriptor, and bytes.
3. Update root Cargo.toml/Cargo.lock and xtrace-store Cargo.toml for the smallest
   approved zstd/Prost/protocol dependency set; license review first.
4. No xtrace-domain changes: the receipt uses existing IDs.
5. Append v0002 in xtrace-store migrations.rs/connection.rs without altering v1.
6. Add xtrace-store xtf.rs and recording_store.rs; update store error.rs/lib.rs
   with scoped RecordingStoreError and shared-Arc writer guard/root binding.
7. Add focused protocol/store/migration/fault/concurrency tests.

Do not change xtrace-application, xtrace-ingest, xtrace-daemon, XTP schemas,
CLI/UI, or existing plans/progress in 1C.4.

Use external SSD caches under the local cache root, written here as `<CACHE>`:

~~~bash
export CARGO_HOME='<CACHE>/cargo'
export CARGO_TARGET_DIR='<CACHE>/cargo-target'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo test -p xtrace-protocol --all-features --no-fail-fast
cargo test -p xtrace-store --all-features --no-fail-fast
cargo test --workspace --all-targets --all-features --no-fail-fast
cargo test --workspace --all-features --no-fail-fast
env -i PATH="$HOME/.cargo/bin:/usr/bin:/bin" \
  HOME="$HOME" \
  USER="$USER" \
  LANG='en_US.UTF-8' \
  LC_ALL='en_US.UTF-8' \
  CARGO_HOME='<CACHE>/cargo' \
  CARGO_TARGET_DIR='<CACHE>/cargo-target' \
  XDG_CACHE_HOME='<CACHE>/xdg' \
  TMPDIR='<CACHE>/tmp' \
  cargo build -p xtrace-protocol --all-features
if command -v cargo-deny >/dev/null 2>&1; then cargo deny check; fi
git diff --check
~~~

HOME remains only so the rustup launcher can locate the installed toolchain;
all task build/cache locations and TMPDIR in the restricted command are on the
external SSD.

Implementation agent runs focused checks. Orchestrator independently reruns
format, strict Clippy/rustdoc, descriptor/golden/fault/migration suites, both
workspace forms, restricted-PATH protocol build, available cargo-deny, and diff
check. Review confirms D-3/D-4/D-5 exactly; v0001 unchanged; root-contained
owner-only/symlink-checked same-filesystem operations; directory fsync before
SQLite; full existing-object verification; no missing-object reference/no
cross-key dedup; and no daemon/Committed ACK/recovery/query/client leakage.

## Acceptance, non-goals, next phase

Accept only after D-3/D-4/D-5 approval, migration safety, public storage-local
begin/commit passing every deterministic boundary, and all checks passing. The
status must say it is not wired to live capture and is only the D-5 staged
segment-metadata commit, not the complete Gate 3 recording commit.

Non-goals: daemon admission/drain/Committed ACK; final states; the D-5-deferred
frame-index rows, recording counters, and outbox transaction work; recovery/
retention; source snapshots/frame-query indexes; runtime_sessions/policies;
XTP/API; adapters; CLI/TUI/web; real capture; zstd threads; cross-process
writers; broad object store abstractions.

After implementation, independent review/verification/status, and user approval,
propose 1C.5: add the application port/use case, then bounded daemon composition
through that abstraction at accepted RecordingStarted. It translates admitted
events to typed XtfEventEnvelope and commits sealed segments, but keeps Staged
ACK behavior until a later approved phase extends the transaction to the D-5
frame-index/counters/outbox contract. Only that later transaction may support a
Committed ACK or terminal-state claim. The daemon must not directly call
xtrace-store. Recovery, retention, query/UI, and complete/partial semantics
stay separately planned.
