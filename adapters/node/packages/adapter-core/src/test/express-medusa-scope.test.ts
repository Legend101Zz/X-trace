import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { expressModule, resolveMedusaExpress } from "../modules.cjs";

const environment = { nodeVersion: "v24.21.0", packageVersion: "" };
const unsupported = { supported: false, reason: "express_version_unsupported" };
const missing = { supported: false, reason: "express_not_found" };

function setup(root: string, nestedPackage: unknown) {
  const entry = join(root, "checkout", "apps", "backend", "package.json");
  const scope = join(root, "checkout", "node_modules", ".pnpm", "medusa", "node_modules");
  const medusa = join(scope, "@medusajs", "medusa");
  const link = join(dirname(entry), "node_modules", "@medusajs", "medusa");
  const express = join(scope, "express", "package.json");
  mkdirSync(dirname(link), { recursive: true });
  mkdirSync(medusa, { recursive: true });
  mkdirSync(dirname(express), { recursive: true });
  writeFileSync(entry, "{}");
  writeFileSync(join(medusa, "package.json"), JSON.stringify({ name: "@medusajs/medusa", main: "index.js" }));
  writeFileSync(join(medusa, "index.js"), "throw new Error('resolution must not load Medusa');");
  writeFileSync(express, JSON.stringify(nestedPackage));
  symlinkSync(medusa, link, "dir");
  return { resolve: createRequire(entry).resolve, entry, express };
}

test("Express detection resolves Medusa's transitive Express in an isolated dependency layout", (context) => {
  const root = mkdtempSync(join(tmpdir(), "express-medusa-scope-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const { resolve, express } = setup(root, { name: "express", version: "4.22.2" });
  assert.throws(() => resolve("express/package.json"), { code: "MODULE_NOT_FOUND" });
  assert.equal(resolveMedusaExpress(resolve), realpathSync(express));
  assert.deepEqual(expressModule(resolve).detect(environment), { supported: true });
});

test("direct detection wins and transitive fallback requires a named supported Express", (context) => {
  const root = mkdtempSync(join(tmpdir(), "express-medusa-scope-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const { resolve, entry } = setup(root, { name: "express", version: "4.22.2" });
  const nested = resolveMedusaExpress(resolve);
  for (const manifest of [{ name: "express", version: "6.0.0" }, { name: "unrelated", version: "4.22.2" }, { name: "express", version: "4fake" }, {}]) {
    writeFileSync(nested, JSON.stringify(manifest));
    assert.deepEqual(expressModule(resolve).detect(environment), unsupported);
  }
  writeFileSync(nested, JSON.stringify({ name: "express", version: "4.22.2" }));
  const direct = join(dirname(entry), "node_modules", "express", "package.json");
  mkdirSync(dirname(direct), { recursive: true });
  writeFileSync(direct, JSON.stringify({ name: "express", version: "6.0.0" }));
  assert.deepEqual(expressModule(resolve).detect(environment), unsupported);
  assert.deepEqual(expressModule(() => { throw new Error("unrelated resolution failure"); }).detect(environment), missing);
});
