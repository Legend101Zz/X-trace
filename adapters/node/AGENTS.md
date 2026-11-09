# adapters/node: notes for agents

- npm workspaces: `packages/protocol` (generated protobuf-es code, checked in under `src/gen`), `packages/adapter-core`
  (loader + HTTP/Express capture), `packages/analyzer` (static routes for `xtrace scan`).
- Never hand-edit `packages/protocol/src/gen`. Regenerate from `schema/proto` with `npm run generate`, and keep
  `npm run generate:check` green.
- `npm test` builds first, then runs the `node --test` suites. The Rust CLI tests (`node_run_http`,
  `node_express_journey`, ...) consume the built `dist/` output, so they are the end-to-end check on CI.
- Runtime targets are Node 22 and 24. Fast check: `tools/dev/check.sh node`.
