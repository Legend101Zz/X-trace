import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createRequire } from "node:module";
import type { LoaderPlan } from "../loader/feature-detect.cjs";

const require = createRequire(import.meta.url);
const { chooseLoaderStrategy } = require("../loader/feature-detect.cjs") as typeof import("../loader/feature-detect.cjs");
const hooksPath = fileURLToPath(new URL("../loader/hooks.cjs", import.meta.url));

function appDir(): string {
  const root = mkdtempSync(join(tmpdir(), "xt-loader-"));
  for (const [name, pkg] of [["cjs", '{"type":"commonjs"}'], ["esm", '{"type":"module"}'], ["untyped", "{}"]] as const) {
    mkdirSync(join(root, name));
    writeFileSync(join(root, name, "package.json"), pkg);
  }
  writeFileSync(join(root, "cjs/a.js"), 'exports.v = "cjs";');
  writeFileSync(join(root, "untyped/a.js"), 'exports.v = "untyped";');
  writeFileSync(join(root, "untyped/b.cjs"), 'exports.v = "cts-ext";');
  writeFileSync(join(root, "untyped/c.mjs"), 'export const v = "mjs-ext";');
  writeFileSync(join(root, "esm/a.js"), 'export const v = "esm";');
  writeFileSync(join(root, "cjs/bad.js"), 'exports.v = "bad-original";');
  return root;
}

/** Runs the script in a fresh process: loader hooks are process-global and cannot be undone. */
function runChild(root: string, script: string, args: string[] = []): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [...args, "-e", script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, XTRACE_TEST_ROOT: root, XTRACE_HOOKS: hooksPath, NODE_OPTIONS: "" },
    timeout: 30_000,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const PRELUDE = `
const seen = [];
const { installSourceTransform } = require(process.env.XTRACE_HOOKS);
const install = installSourceTransform((source, ctx) => {
  seen.push(ctx.format + ":" + ctx.filename.slice(process.env.XTRACE_TEST_ROOT.length));
  if (ctx.filename.endsWith("bad.js")) throw new Error("transform boom");
  return source + "\\n/*xt*/";
});
const root = process.env.XTRACE_TEST_ROOT;
`;

test("loader strategy: registerHooks by default, compile wrapper on Node 22 with an async loader, honest limitations", () => {
  const base = { nodeVersion: "v24.21.0", hasRegisterHooks: true, execArgv: [] as string[], nodeOptions: "" };
  assert.deepEqual(chooseLoaderStrategy(base), { strategy: "register-hooks", limitations: [] } satisfies LoaderPlan);
  const node22Loader = chooseLoaderStrategy({ ...base, nodeVersion: "v22.23.0", nodeOptions: "--import tsx --max-old-space-size=64" });
  assert.equal(node22Loader.strategy, "compile-wrapper");
  assert.ok(node22Loader.limitations.includes("loader_conflict_node22"));
  assert.equal(chooseLoaderStrategy({ ...base, nodeVersion: "v22.23.0", execArgv: ["--experimental-loader=ts-node/esm"] }).strategy, "compile-wrapper");
  assert.equal(chooseLoaderStrategy({ ...base, nodeVersion: "v22.23.0" }).strategy, "register-hooks");
  assert.equal(chooseLoaderStrategy({ ...base, nodeVersion: "v24.21.0", nodeOptions: "--import tsx" }).strategy, "register-hooks");
  const absent = chooseLoaderStrategy({ ...base, hasRegisterHooks: false });
  assert.equal(absent.strategy, "compile-wrapper");
  assert.ok(absent.limitations.includes("register_hooks_unavailable"));
});

test("registerHooks sees CommonJS require, ESM import and extension-typed files on this node, and ignores builtins and data URLs", () => {
  const root = appDir();
  const result = runChild(root, PRELUDE + `
(async () => {
  const a = require(root + "/cjs/a.js").v, u = require(root + "/untyped/a.js").v, c = require(root + "/untyped/b.cjs").v;
  const e = (await import(root + "/esm/a.js")).v, m = (await import(root + "/untyped/c.mjs")).v;
  const d = (await import("data:text/javascript,export default 7")).default;
  require("node:fs");
  console.log(JSON.stringify({ strategy: install.strategy, a, u, c, e, m, d, seen }));
})();`);
  assert.equal(result.status, 0, result.stderr);
  const out = JSON.parse(result.stdout.trim()) as { strategy: string; seen: string[]; [key: string]: unknown };
  assert.equal(out.strategy, "register-hooks");
  assert.deepEqual([out.a, out.u, out.c, out.e, out.m, out.d], ["cjs", "untyped", "cts-ext", "esm", "mjs-ext", 7]);
  assert.deepEqual([...out.seen].sort(), [
    "commonjs:/cjs/a.js", "commonjs:/untyped/a.js", "commonjs:/untyped/b.cjs", "module:/esm/a.js", "module:/untyped/c.mjs",
  ].sort());
});

test("a throwing transform serves the original source and never breaks require", () => {
  const root = appDir();
  const result = runChild(root, PRELUDE + `
const v = require(root + "/cjs/bad.js").v;
console.log(JSON.stringify({ v, failures: install.failures() }));`);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { v: "bad-original", failures: 1 });
});

test("the compile-wrapper fallback transforms CommonJS, survives failure, and install is idempotent", () => {
  const root = appDir();
  const result = runChild(root, `
const { installSourceTransform } = require(process.env.XTRACE_HOOKS);
const root = process.env.XTRACE_TEST_ROOT;
let calls = 0;
const plan = { strategy: "compile-wrapper", limitations: ["esm_source_transform_unavailable"] };
const first = installSourceTransform((source, ctx) => { calls += 1; if (ctx.filename.endsWith("bad.js")) throw new Error("boom"); return source + '\\nexports.marked = true;'; }, plan);
const second = installSourceTransform(() => { throw new Error("second install must be ignored"); });
const a = require(root + "/cjs/a.js");
const bad = require(root + "/cjs/bad.js");
console.log(JSON.stringify({ same: first === second, marked: a.marked === true, bad: bad.v, failures: first.failures(), calls, strategy: first.strategy }));`);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { same: true, marked: true, bad: "bad-original", failures: 1, calls: 2, strategy: "compile-wrapper" });
});

test("our hooks coexist with an application's own registerHooks and module.register loaders", () => {
  const root = appDir();
  const result = runChild(root, `
const nodeModule = require("node:module");
const own = [];
nodeModule.registerHooks({ load(url, ctx, next) { own.push(url.slice(-6)); return next(url, ctx); } });
nodeModule.register("data:text/javascript," + encodeURIComponent("export async function load(u, c, n) { return n(u, c); }"), "file:///x/");
` + PRELUDE + `
(async () => {
  const a = require(root + "/cjs/a.js").v, e = (await import(root + "/esm/a.js")).v;
  console.log(JSON.stringify({ a, e, ownSawBoth: own.some((u) => u.endsWith("a.js")), seen: seen.length }));
})();`);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { a: "cjs", e: "esm", ownSawBoth: true, seen: 2 });
});

test("a Node 22 async loader flag never combines with registerHooks, and the app still starts", () => {
  const root = appDir();
  writeFileSync(join(root, "app-loader.mjs"), 'import { register } from "node:module"; register("data:text/javascript," + encodeURIComponent("export async function load(u, c, n) { return n(u, c); }"), import.meta.url);');
  const result = runChild(root, `
const { installSourceTransform } = require(process.env.XTRACE_HOOKS);
const install = installSourceTransform((source) => source, undefined);
console.log(JSON.stringify({ strategy: install.strategy, major: Number(process.version.slice(1).split(".")[0]) }));
import(process.env.XTRACE_TEST_ROOT + "/esm/a.js").then((m) => console.log("esm " + m.v));`, ["--import", join(root, "app-loader.mjs")]);
  assert.equal(result.status, 0, result.stderr);
  const [first] = result.stdout.trim().split("\n");
  const parsed = JSON.parse(first!) as { strategy: string; major: number };
  assert.equal(parsed.strategy, parsed.major < 24 ? "compile-wrapper" : "register-hooks");
  assert.ok(result.stdout.includes("esm esm"));
});
