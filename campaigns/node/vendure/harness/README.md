# Vendure preparation inputs

This remains a preparation-only campaign. There is no new installed adapter, baseline result or release acceptance.
The development pin stays v3.7.3; choosing the final stable release and the six-app common candidate is separate.

`create` still uses the original official create command to produce `.env` and static/email files. `build` then
**explicitly replaces** the nine runnable source/config/package files with the tracked PostgreSQL starter.
The snapshot's historical SQLite-original source is an audit reference, not a compiled entrypoint. Extra TypeScript
sources in the generated app are rejected. Keep a fresh workspace; do not reuse a completed build receipt.

The two manifest lock digests must equal the tracked lock bytes, and package dependency declarations must match
its root entry. `npm ci` uses that exact lock, with no uninstall/install fallback. Checks after installation and
compilation reject source/package/lock drift and mismatched direct dependency versions. The private preparation
receipt records source and compiled server/worker/config hashes, actual Node and bundled npm versions, and the
upstream source pin. It says explicitly that installed registry packages are not a proven byte-identical source rebuild.
The producer saves an exclusive digest of the complete receipt at build time. Later seed and baseline
verification check that digest, the exact receipt shape, the upstream and Node pins, the registry-build flag
and the observed stable npm version. The npm version comes from the build container. The digest detects drift
of the receipt in this private workspace and does not provide an external signature.
Extra `tsconfig.server.json`, `tsconfig.worker.json` and `tsconfig.build.json` files are refused because the pinned
CLI would prefer them over the tracked `tsconfig.json`. That CLI runs `tsc -p ... --noEmitOnError` separately for
the original server/worker targets; the tracked config includes only the admitted `src` files, with no source maps
or declarations. Immediately before the first compiler the harness creates a fresh private `dist` directory and refuses any
existing entry. The original generator's CI path uses ts-node for population. If a real create leaves an
unexpected dist, preparation stops with the original output preserved. Build completion requires exactly `dist/index.js`, `dist/index-worker.js` and
`dist/vendure-config.js` as regular files. Every additional entry (including an empty migrations directory,
executable migration, dashboard, source map, declaration, link or special file) fails admission without deletion.
This exact output identity is checked again before seeding and before a baseline starts. Seeding exclusively adds
the unchanged harness `xtrace-seed-populate.cjs`, verifies its bytes before execution and after population, and
admits only that additional file during later baseline checks. These are source-derived expected outputs, not
evidence that the actual build has completed; any unexpected generated output needs investigation.
The normal hosted shell creates a fresh private parent beneath the runner temporary directory. Create exclusively
claims its preparation subdirectory. Only that subdirectory is mounted as the application workspace. The upstream
checkout and canonical baseline output directory remain separate. Create, build, seed, server and worker run as
the invoking UID/GID with a private writable HOME. The Vendure branch skips the shell's recursive ownership repair.
The generator must exit with code zero before build and seed proceed. A signal or unavailable code fails preparation.
For standalone use, create claims a fresh preparation child under the project directory. Reuse of a completed
workspace requires its matching preparation inputs; create always refuses an existing preparation child.
The existing container image is not promoted to a new immutable image pin by this change.

The existing shell entry verifies the official create tarball SHA-256, retains its verified bytes in an exclusively created private file, and extracts only
regular `assets/` inputs with safe unique names. Before seeding, all extracted files (including initial data, products
and images) must still match that archive. There is no install, request or data repair in these checks. The seed
receipt binds that input tree, archive, unchanged populate helper, build receipt and actual dumped `seed.sql`.
Before a baseline database starts, the dump/helper/build identities are checked again. Both receipts contain hashes
and fixed metadata only; `.env`, SQL content, GraphQL bodies, credentials and logs remain private.
The private seed receipt is never reused directly as baseline metadata. A fresh closed projection requires exact
top-level and asset keys, lowercase SHA-256 digests, the pinned archive, current dump/helper/build bindings and a
positive safe integer asset count no greater than 100,000. The baseline re-verifies the extracted inputs against the retained pinned archive
and checks the receipt’s complete asset count and tree digest against that independent observation. Unknown top-level or nested fields and malformed counts
or identities are rejected before metadata publication. For a baseline leg, the harness reads seed.sql once from an
owner-only regular file. Both reported dump digests refer to those bytes. Immediately before database startup it
revalidates the build, assets, helper and receipt. After startup it sends the retained buffer as psql stdin without
reopening its pathname. Only digests and the closed projection enter baseline metadata. Restore errors carry a
fixed message because database diagnostics can quote SQL. Initial and repeated seed admission report only fixed
file or identity errors when private reads, parsing or the asset verifier fail.

Server is still the starter's `dist/index.js` (`runMigrations` then `bootstrap`). Worker remains its separate
`dist/index-worker.js` (`bootstrapWorker` then `startJobQueue`). The population helper's existing synchronize,
job start and fixed pause are unchanged. The original PostgreSQL reset, readiness, eleven ordinary scenarios,
worker job-effect check, deadlines and cleanup stay intact. Nothing here proves Nest provider/resolver recording.

The generated `.env` and static/email files still come from the original create step, not the closed runnable
snapshot. This is a stated remaining preparation provenance boundary. The historical SQLite and PostgreSQL
receipts also remain distinct. A real hosted build/seed and normal installed workload must establish success;
syntax checks alone do not do so.

License identity is already recorded in campaign.json, including pinned LICENSE/GPL/plugin-exception digests;
the lock identifies @vendure/core as GPL-3.0-or-later. This patch adds original harness code, not copied Vendure
implementation. It prepares disposable test inputs and does not package or distribute Vendure. Conveying a
Vendure-containing fixture/package would require a separate licence review and corresponding source obligations.

Hosted focused regressions (not run locally):

```sh
node --test campaigns/node/vendure/harness/preparation.test.mjs
python3 -B -m unittest discover -s campaigns/node/vendure/harness -p 'test_seed_assets.py'
```
