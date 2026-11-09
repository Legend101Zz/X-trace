# xtrace-store: notes for agents

- Bundled SQLite store plus the XTF segment store. Migrations are in `src/migrations.rs`. Main has v0001–v0009
  (v9 = `recording_limitations`); catalog links are planned as v10. A new migration is a shared-contract change:
  only in a ticket that says so. Never edit an existing migration.
- `src/recording_store.rs` is about 7,700 lines. Grep for the function you need and read only that part. Do not
  reformat or reorder it. A split is its own behavior-preserving ticket.
- Recording ids: UUIDv4/v7 reads and cursors keep their historical bytes (ADR 0002). No rekey or backfill.
- Store tests use private scratch: source `tools/dev/env.sh` first.
