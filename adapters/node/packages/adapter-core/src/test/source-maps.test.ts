import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const require = createRequire(import.meta.url);
const { resolveAuthoredSource, repoRelative } = require("../source-maps.cjs") as typeof import("../source-maps.cjs");

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function vlq(value: number): string {
  let rest = value < 0 ? (-value << 1) | 1 : value << 1;
  let out = "";
  do {
    let digit = rest & 31;
    rest >>>= 5;
    if (rest > 0) digit |= 32;
    out += BASE64[digit];
  } while (rest > 0);
  return out;
}
/** One segment per entry: [genColumn, source, authoredLine, authoredColumn], deltas encoded per spec. */
function mappings(lines: number[][][]): string {
  let source = 0, line = 0, column = 0;
  return lines.map((segments) => {
    let genColumn = 0;
    return segments.map(([g, s, l, c]) => {
      const text = vlq(g! - genColumn) + vlq(s! - source) + vlq(l! - line) + vlq(c! - column);
      genColumn = g!; source = s!; line = l!; column = c!;
      return text;
    }).join(",");
  }).join(";");
}
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

function project(): { root: string; cleanup(): void } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "xtrace-sourcemap-")));
  mkdirSync(join(root, "src"));
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "src/app.ts"), "// authored\nexport function show(id: string) {\n  return id;\n}\n");
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("a sibling map places a generated position on the authored line, repo-relative", () => {
  const { root, cleanup } = project();
  try {
    writeFileSync(join(root, "dist/app.js"), "function show(id) { return id; }\n//# sourceMappingURL=app.js.map\n");
    writeFileSync(join(root, "dist/app.js.map"), JSON.stringify({ version: 3, file: "app.js", sources: ["../src/app.ts"], names: [], mappings: mappings([[[0, 0, 1, 7], [20, 0, 2, 2]]]) }));
    const found = resolveAuthoredSource(join(root, "dist/app.js"), 1, 3, { repoRoot: root, hashContent: sha });
    assert.equal(found.binding, "observed-unattested");
    assert.equal(found.facts?.path, "src/app.ts");
    assert.equal(found.facts?.startLine, 2);
    assert.equal(found.facts?.startColumn, 8);
    assert.match(found.facts?.contentHash ?? "", /^[0-9a-f]{64}$/);
    const later = resolveAuthoredSource(join(root, "dist/app.js"), 1, 25, { repoRoot: root, hashContent: sha });
    assert.equal(later.facts?.startLine, 3);
  } finally { cleanup(); }
});

test("an inline data-URI map resolves the same way", () => {
  const { root, cleanup } = project();
  try {
    const map = Buffer.from(JSON.stringify({ version: 3, sources: ["../src/app.ts"], mappings: mappings([[[0, 0, 1, 0]]]) })).toString("base64");
    writeFileSync(join(root, "dist/app.js"), `x();\n//# sourceMappingURL=data:application/json;base64,${map}\n`);
    const found = resolveAuthoredSource(join(root, "dist/app.js"), 1, 1, { repoRoot: root, hashContent: sha });
    assert.equal(found.binding, "observed-unattested");
    assert.equal(found.facts?.path, "src/app.ts");
  } finally { cleanup(); }
});

test("honest states: no comment and a missing map file are source-map-absent, never a guess", () => {
  const { root, cleanup } = project();
  try {
    writeFileSync(join(root, "dist/plain.js"), "x();\n");
    const none = resolveAuthoredSource(join(root, "dist/plain.js"), 1, 1, { repoRoot: root, hashContent: sha });
    assert.deepEqual([none.binding, none.reason, none.facts], ["source-map-absent", "no_source_map_comment", undefined]);
    writeFileSync(join(root, "dist/dangling.js"), "x();\n//# sourceMappingURL=dangling.js.map\n");
    const dangling = resolveAuthoredSource(join(root, "dist/dangling.js"), 1, 1, { repoRoot: root, hashContent: sha });
    assert.deepEqual([dangling.binding, dangling.reason], ["source-map-absent", "source_map_unreadable"]);
    const missingGenerated = resolveAuthoredSource(join(root, "dist/nowhere.js"), 1, 1, { repoRoot: root });
    assert.equal(missingGenerated.binding, "source-map-absent");
  } finally { cleanup(); }
});

test("honest states: invalid map, unmapped position and an authored file outside the repo are source-map-unresolved", () => {
  const { root, cleanup } = project();
  try {
    writeFileSync(join(root, "dist/bad.js"), "x();\n//# sourceMappingURL=bad.js.map\n");
    writeFileSync(join(root, "dist/bad.js.map"), "{not json");
    assert.deepEqual(
      (({ binding, reason }) => [binding, reason])(resolveAuthoredSource(join(root, "dist/bad.js"), 1, 1, { repoRoot: root, hashContent: sha })),
      ["source-map-unresolved", "source_map_invalid"],
    );
    writeFileSync(join(root, "dist/app.js"), "x();\n//# sourceMappingURL=app.js.map\n");
    writeFileSync(join(root, "dist/app.js.map"), JSON.stringify({ version: 3, sources: ["../src/app.ts"], mappings: mappings([[[4, 0, 1, 0]]]) }));
    const before = resolveAuthoredSource(join(root, "dist/app.js"), 1, 1, { repoRoot: root, hashContent: sha });
    assert.deepEqual([before.binding, before.reason], ["source-map-unresolved", "position_unmapped"], "column before the first segment");
    const beyond = resolveAuthoredSource(join(root, "dist/app.js"), 9, 1, { repoRoot: root, hashContent: sha });
    assert.equal(beyond.reason, "position_unmapped");

    const outside = realpathSync(mkdtempSync(join(tmpdir(), "xtrace-outside-")));
    try {
      writeFileSync(join(outside, "secret.ts"), "export const secret = 1;\n");
      writeFileSync(join(root, "dist/esc.js"), "x();\n//# sourceMappingURL=esc.js.map\n");
      writeFileSync(join(root, "dist/esc.js.map"), JSON.stringify({ version: 3, sources: [join(outside, "secret.ts")], mappings: mappings([[[0, 0, 0, 0]]]) }));
      const escaped = resolveAuthoredSource(join(root, "dist/esc.js"), 1, 1, { repoRoot: root, hashContent: sha });
      assert.deepEqual([escaped.binding, escaped.reason, escaped.facts], ["source-map-unresolved", "authored_outside_repo", undefined]);
      assert.equal(repoRelative(join(outside, "secret.ts"), root), undefined);
    } finally { rmSync(outside, { recursive: true, force: true }); }

    writeFileSync(join(root, "dist/gone.js"), "x();\n//# sourceMappingURL=gone.js.map\n");
    writeFileSync(join(root, "dist/gone.js.map"), JSON.stringify({ version: 3, sources: ["../src/removed.ts"], mappings: mappings([[[0, 0, 0, 0]]]) }));
    const gone = resolveAuthoredSource(join(root, "dist/gone.js"), 1, 1, { repoRoot: root, hashContent: sha });
    assert.deepEqual([gone.binding, gone.reason], ["source-map-unresolved", "authored_unreadable"]);
  } finally { cleanup(); }
});
