# ADR 0011: Persisted recording limitations

- Status: Proposed — pending owner ratification (2026-10-10 batch)
- Date: 2026-10-09
- Amends: nothing; extends the application recording contract and the SQLite
  schema (migration v9). Authorized as item (c) of the ADR 0009 second-batch
  authorization, for owner ratification afterwards.
- Context: CONTRACTS 4.2 says a capture policy claimed by an adapter is not a
  grant: a session is armed for focused capture only by the launch bootstrap's
  private `capture.json`. When an adapter claims `xtrace.focused.v1` on a
  session that was never armed, the daemon serves the recording under the
  standard policy. Until now that downgrade was only a `warn!` log line
  (`capture_policy_not_armed`), the read model always returned
  `limitations: []`, and the focused journey could pass with zero line events
  and no visible explanation. A recording that is weaker than its adapter
  claimed must say so wherever it is read.

## Decision

### 1. Contract change

- `xtrace_application::recording::BeginRecording` gains
  `limitations: Vec<String>`: sorted, unique members of the closed vocabulary
  `RECORDING_LIMITATION_CODES`. The vocabulary has one member in v9,
  `capture_policy_not_armed` (`LIMITATION_CAPTURE_POLICY_NOT_ARMED`). The
  application layer rejects any other value or an unsorted or duplicated list
  with a `Validation` port error before reaching storage. Adding a code
  requires an amendment of this ADR, because the vocabulary is part of the read
  contract.
- The daemon session decides the limitations of a `RecordingStarted`
  admission (`Session::accept_post_hello`, `PostHelloAdmission.limitations`) and
  the recording pipeline forwards them into `BeginRecording`. The code is raised
  exactly when the claimed policy names focused capture and the effective mode
  is not focused.
- `RecordingDetail.limitations` (already present in the read model, the local
  read API and `schema/xtp-client/openapi.yaml` as `limitations: string[]`) is
  now populated from storage for every recording. No OpenAPI change, no
  regeneration of `api.generated.ts`, no change to the generated Node protocol
  code.
- The wire protocol (XTP) is unchanged. `RecordingStarted` carries no
  limitation field and none is added: limitations describe a decision the
  daemon made, so an adapter-supplied value would be untrusted input to a
  trust statement. Adapters (Java, Node) need no change. ADR 0002's
  read-compatibility rule is therefore not engaged; the rule that protocol
  changes stay additive and optional is satisfied trivially.
- `Session.downgraded_claims` (dead state, never read in production) and the
  comments that described an `ARM_FOCUSED_CAPTURE` acknowledgment path that
  does not exist are removed. The only arming path is `capture.json`.

### 2. Migration v9 `recording_limitations`

- `v0009_recording_limitations` creates
  `recording_limitations(recording_id BLOB, code TEXT, PRIMARY KEY(recording_id, code))`,
  `STRICT`, with a foreign key to `recordings(recording_id)`, a 16-byte id check
  and a `CHECK` that `code` is a 1 to 64 byte lowercase identifier
  (`[a-z][a-z0-9_]*`). The table cannot hold free text.
- `CURRENT_SCHEMA_VERSION` is 9. The migration, the constant and the pinned
  prefix-checksum test (`v0009_prefix_checksum_is_pinned`) land in one commit.
  `lane_sql/catalog_v9.sql` is untouched and becomes v10 in a later wave.
- Rows are inserted in the same transaction as the recording anchor and are
  never updated. A replayed `begin_recording` keeps the limitations the
  recording was first opened with.

### 3. Compatibility

- Forward: a v8 store upgrades by running v9, which only adds a table.
  Recordings opened before v9 have no rows, which reads as "none recorded". It
  cannot be told apart from "none applied"; no backfill is attempted, because
  the historical log line was not retained.
- Backward: a v8 binary refuses a v9 store (`SchemaNewer`), as for every
  migration.
- API consumers already tolerate `limitations` arrays; a new code appearing is
  covered by the vocabulary rule above.

### 4. Related `record` and capture-depth changes in the same lane

- `xtrace record` and `xtrace restart` accept and resolve the same capture
  inputs as `xtrace run` (`--capture-depth`, `--app-package`, `--source-root`,
  `--launcher`) through the same validation, and write the resolved scope to
  `capture.json` instead of an empty one. `record` launches nothing, so it has
  no jar to derive a package scope from; without `--app-package` the scope is
  honestly empty and the record document says so.
- `capture_depth_enforced` in the record document is `true` exactly when the
  daemon's own `capture.json` reader (the one that arms every adapter session)
  yields the recorded depth. The CLI no longer carries a second parser; it
  calls the daemon's hardened reader (private, regular, non-symlink,
  size-bounded, same-inode read). `docs/security-local.md` states this.

## Threat and privacy notes

- Limitation codes are fixed vocabulary members. They carry no captured value,
  path, identifier or adapter-supplied string, and are safe to log, store and
  serve. The SQL `CHECK` and the application validation both bound them.
- The limitation is evidence of a weaker guarantee, never of a stronger one.
  An adapter cannot raise or clear it: only the daemon session sets it, from the
  launch-armed mode.
- Limitations do not unlock anything. Capture caps and redaction are decided by
  the effective mode, as before.

## Test obligations

- Migration test: v9 applies on a v8 store, old recordings read as empty,
  duplicate and malformed codes and orphan rows are rejected by SQL, the
  applied checksum changes, and the v1 to v9 prefix checksum is pinned.
- Application test: limitations reach the port; unknown, duplicate or unsorted
  values are rejected before the port.
- Daemon end-to-end test (`crates/xtrace-daemon/tests/recording_limitations.rs`):
  a focused claim on an unarmed session persists `capture_policy_not_armed`,
  is read back through the shared recording read facade and runs under the
  standard cap; an armed session honours the claim with no limitation; a
  standard claim never carries one.
- The focused CLI journey requires either line events or a declared, persisted
  explanation of their absence, and that an armed run does not carry
  `capture_policy_not_armed`.
- `record` tests: scope flags are validated like `run`, the resolved scope is
  written to a private `capture.json`, and a rejected record starts no daemon.

## Alternatives considered

- **Adapter-supplied limitations on the wire.** Rejected: untrusted input to a
  trust statement, and a protocol change for no gain.
- **A column on `recordings`.** Rejected: a rewrite of a hot table's
  constraints, and a list is not a scalar.
- **Keep the log line only.** Rejected: invisible to anyone reading the
  recording, which is the case the finding documents.

## Consequences

- Every read surface can show why a recording is weaker than claimed.
- One new table and one new vocabulary to keep closed.
- Pre-v9 recordings cannot report limitations they may have had.
