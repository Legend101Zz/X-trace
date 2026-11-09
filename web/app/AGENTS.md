# web/app: notes for agents

- React 19 + strict TypeScript + Vite; Vitest (jsdom) and Playwright. Hand-written CSS with tokens in
  `src/style.css`. No router, state library or component library yet.
- `src/api.generated.ts` is generated from `schema/xtp-client/openapi.yaml` (`npm run generate:api`, checked by
  `npm run check:api`). Never hand-edit it.
- The built app is embedded into the daemon at `crates/xtrace-daemon/assets/ui/`. After any change, run
  `npm run embed` so `npm run check:embedded` stays green. The embedded `app.js` is minified, so leave it out of greps.
- Contrast is a test: `scripts/check-contrast.mjs` requires 4.5:1 for text tokens and 3:1 for meaningful marks.
  Any new colour token must pass it.
- Honesty copy comes from `schema/fixtures/replay/honesty-strings.json` and `src/replay/source-states.ts` /
  `outcome.ts`. Do not paraphrase it in components.
- Accessibility is a requirement: keyboard paths, visible reasons on disabled controls (not tooltips only), one polite
  live region, 44 px touch targets, no horizontal scroll at 320 px, reduced motion.
- Fast check: `tools/dev/check.sh web[:<file>]`.
