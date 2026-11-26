import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { claimWorkspace, generatorExitCode, prepareBaselineSeed, stageStarter, verifyStarter, createCompileDirectory, verifyOutputs, verifyBuild, seedProjection, writeFreshSeed } from "./preparation.mjs";

const snapshot = path.join(path.dirname(fileURLToPath(import.meta.url)), "../starter-snapshot");
function app(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vendure-prep-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(snapshot, root, { recursive: true });
  fs.unlinkSync(path.join(root, "src/vendure-config.sqlite-original.ts"));
  fs.writeFileSync(path.join(root, ".env"), "private-fixture-value");
  return root;
}
test("staging uses the tracked adapted lock without changing private scaffold inputs", t => {
  const root = app(t);
  fs.writeFileSync(path.join(root, "package-lock.json"), "generated-sqlite-lock");
  stageStarter(root);
  verifyStarter(root);
  assert.deepEqual(fs.readFileSync(path.join(root, "package-lock.json")), fs.readFileSync(path.join(snapshot, "package-lock.json")));
  assert.equal(fs.readFileSync(path.join(root, ".env"), "utf8"), "private-fixture-value");
});
test("staging replaces a shared scaffold entry without modifying its other link or mode", t => {
  const root = app(t), target = path.join(root, "package-lock.json");
  const other = path.join(root, "shared-lock-copy");
  fs.chmodSync(target, 0o640);
  fs.linkSync(target, other);
  const original = fs.readFileSync(other);
  stageStarter(root);
  assert.deepEqual(fs.readFileSync(other), original);
  assert.deepEqual(fs.readFileSync(target), fs.readFileSync(path.join(snapshot, "package-lock.json")));
  assert.equal(fs.statSync(target).mode & 0o777, 0o640);
  assert.notEqual(fs.statSync(target).ino, fs.statSync(other).ino);
});
test("seed output requires a fresh destination and preserves existing bytes", t => {
  const root = app(t), target = path.join(root, "seed.sql");
  writeFreshSeed(root, "first");
  assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  assert.throws(() => writeFreshSeed(root, "second"), { code: "EEXIST" });
  assert.equal(fs.readFileSync(target, "utf8"), "first");
});
test("changed dependencies and source bytes fail without being repaired", t => {
  const root = app(t);
  stageStarter(root);
  for (const name of ["package.json", "package-lock.json", "src/index-worker.ts"]) {
    const target = path.join(root, name), original = fs.readFileSync(target);
    fs.writeFileSync(target, "changed");
    assert.throws(() => verifyStarter(root), /changed/);
    assert.equal(fs.readFileSync(target, "utf8"), "changed");
    fs.writeFileSync(target, original);
  }
});
test("extra compiled sources and linked inputs are rejected", t => {
  const root = app(t);
  fs.writeFileSync(path.join(root, "src/extra.ts"), "export const unexpected = true;");
  assert.throws(() => stageStarter(root), /unpinned/);
  fs.unlinkSync(path.join(root, "src/extra.ts"));
  const worker = path.join(root, "src/index-worker.ts");
  fs.unlinkSync(worker);
  fs.symlinkSync(path.join(snapshot, "src/index-worker.ts"), worker);
  assert.throws(() => stageStarter(root), /linked/);
});
test("a completed workspace cannot be restaged over its build identity", t => {
  const root = app(t);
  fs.writeFileSync(path.join(root, "xtrace-build-inputs.json"), "{}");
  assert.throws(() => stageStarter(root), /fresh workspace/);
});
test("alternate CLI build configurations fail without removing their contents", t => {
  const root = app(t);
  for (const name of ["tsconfig.server.json", "tsconfig.worker.json", "tsconfig.build.json"]) {
    const target = path.join(root, name);
    fs.writeFileSync(target, "private-unpinned-config");
    assert.throws(() => verifyStarter(root), /unpinned build configuration/);
    assert.equal(fs.readFileSync(target, "utf8"), "private-unpinned-config");
    fs.unlinkSync(target);
  }
});
test("compilation claims a fresh dist and refuses stale output before either compiler writes", t => {
  const root = app(t), dist = path.join(root, "dist");
  createCompileDirectory(root);
  assert.deepEqual(fs.readdirSync(dist), []);
  assert.equal(fs.statSync(dist).mode & 0o777, 0o700);
  assert.throws(() => createCompileDirectory(root), { code: "EEXIST" });
  const existing = path.join(dist, "index.js");
  fs.writeFileSync(existing, "previous-build");
  assert.throws(() => createCompileDirectory(root), { code: "EEXIST" });
  assert.equal(fs.readFileSync(existing, "utf8"), "previous-build");
});
test("a redirected compiler output or application root cannot change another directory", t => {
  const root = app(t), other = path.join(root, "other"), dist = path.join(root, "dist");
  fs.mkdirSync(other);
  fs.symlinkSync(other, dist);
  assert.throws(() => createCompileDirectory(root), { code: "EEXIST" });
  assert.throws(() => createCompileDirectory(dist), /real application directory/);
  assert.deepEqual(fs.readdirSync(other), []);
});
function built(t) {
  const root = app(t);
  fs.mkdirSync(path.join(root, "dist"));
  for (const name of ["index.js", "index-worker.js", "vendure-config.js"]) {
    fs.writeFileSync(path.join(root, "dist", name), "synthetic compile identity for " + name);
  }
  return root;
}
test("normal three-file output identity excludes migrations and every other dist artifact", t => {
  const root = built(t);
  const original = verifyOutputs(root);
  assert.deepEqual(Object.keys(original), ["dist/index.js", "dist/index-worker.js", "dist/vendure-config.js"]);
  for (const name of ["migrations/change.js", "migrations/change.ts", "extra.cjs", "index.js.map", "index.d.ts", "dashboard/index.html"]) {
    const target = path.join(root, "dist", name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "unexpected-runtime-content");
    assert.throws(() => verifyOutputs(root), /unadmitted outputs/);
    assert.equal(fs.readFileSync(target, "utf8"), "unexpected-runtime-content");
    fs.unlinkSync(target);
    if (path.dirname(target) !== path.join(root, "dist")) {
      assert.throws(() => verifyOutputs(root), /unadmitted outputs/);
      fs.rmdirSync(path.dirname(target));
    }
  }
  assert.deepEqual(verifyOutputs(root), original);
});
test("linked, directory and special dist entries are refused without following them", t => {
  const root = built(t);
  const target = path.join(root, "dist/index.js");
  const outside = path.join(root, "outside.js");
  fs.writeFileSync(outside, "outside-unchanged");
  fs.unlinkSync(target);
  fs.symlinkSync(outside, target);
  assert.throws(() => verifyOutputs(root), /linked/);
  assert.equal(fs.readFileSync(outside, "utf8"), "outside-unchanged");
  fs.unlinkSync(target);
  fs.mkdirSync(target);
  assert.throws(() => verifyOutputs(root), /regular file/);
  fs.rmdirSync(target);
  execFileSync("mkfifo", [target]);
  assert.throws(() => verifyOutputs(root), /regular file/);
  fs.unlinkSync(target);
  fs.writeFileSync(target, "restored");
  const directory = path.join(root, "dist"), linked = path.join(root, "saved-dist");
  fs.renameSync(directory, linked);
  fs.symlinkSync(linked, directory);
  assert.throws(() => verifyOutputs(root), /regular directory/);
});
test("only the exact unchanged seed helper is admitted after the build phase", t => {
  const root = built(t), target = path.join(root, "dist/xtrace-seed-populate.cjs");
  const original = verifyOutputs(root);
  fs.copyFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "seed-populate.cjs"), target);
  assert.throws(() => verifyOutputs(root), /unadmitted outputs/);
  assert.deepEqual(verifyOutputs(root, true), original);
  fs.writeFileSync(target, "changed-helper");
  assert.throws(() => verifyOutputs(root, true), /seed helper identity changed/);
  assert.equal(fs.readFileSync(target, "utf8"), "changed-helper");
});
const campaign = JSON.parse(fs.readFileSync(path.join(snapshot, "../campaign.json"), "utf8"));
function buildReceipt(root) {
  const pkg = JSON.parse(fs.readFileSync(path.join(snapshot, "package.json"), "utf8"));
  for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    const directory = path.join(root, "node_modules", name);
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, "package.json"), JSON.stringify({ name, version }));
  }
  return { schemaVersion: 1, kind: "vendure-preparation-inputs", releaseAcceptance: false,
    upstreamSha: campaign.upstream.sha, registryBuildNotSourceRebuild: true, nodeVersion: campaign.runtime.nodeImageVersion,
    npmVersion: "11.0.0", sources: verifyStarter(root, true), outputs: verifyOutputs(root) };
}
function storeReceipt(root, receipt) {
  const bytes = JSON.stringify(receipt);
  fs.writeFileSync(path.join(root, "xtrace-build-inputs.json"), bytes);
  fs.writeFileSync(path.join(root, "xtrace-build-inputs.sha256"), createHash("sha256").update(bytes).digest("hex") + "\n");
}
test("rechecking a sealed build refuses later migrations despite unchanged entry hashes", t => {
  const root = built(t);
  storeReceipt(root, buildReceipt(root));
  verifyBuild(root);
  fs.mkdirSync(path.join(root, "dist/migrations"));
  fs.writeFileSync(path.join(root, "dist/migrations/later.js"), "unexpected migration");
  assert.throws(() => verifyBuild(root), /unadmitted outputs/);
  assert.equal(fs.readFileSync(path.join(root, "dist/migrations/later.js"), "utf8"), "unexpected migration");
});
test("all declared build provenance must survive through seed admission", t => {
  const root = built(t), original = buildReceipt(root);
  for (const key of Object.keys(original)) {
    const candidate = { ...original };
    delete candidate[key];
    storeReceipt(root, candidate);
    assert.throws(() => verifyBuild(root), /provenance/);
  }
  for (const change of [{ upstreamSha: "1".repeat(40) }, { nodeVersion: "0.0.0" },
    { registryBuildNotSourceRebuild: false }, { npmVersion: "not a version" }, { npmVersion: null },
    { extra: "unexpected" }]) {
    storeReceipt(root, { ...original, ...change });
    assert.throws(() => verifyBuild(root), /provenance/);
  }
  storeReceipt(root, original);
  verifyBuild(root);
  fs.writeFileSync(path.join(root, "xtrace-build-inputs.json"), JSON.stringify({ ...original, npmVersion: "11.0.1" }));
  assert.throws(() => verifyBuild(root), /changed after compilation/);
});
function seedReceipt() {
  return { schemaVersion: 1, kind: "vendure-seed-inputs", releaseAcceptance: false,
    assets: { archiveSha256: campaign.starter.package.tarballSha256, files: 3, treeSha256: "a".repeat(64) },
    buildReceiptSha256: "b".repeat(64), helperSha256: "c".repeat(64), seedSha256: "d".repeat(64) };
}
test("seed metadata is a fresh closed digest-only projection", () => {
  const receipt = seedReceipt(), projected = seedProjection(receipt, seedReceipt());
  assert.deepEqual(projected, receipt);
  assert.notEqual(projected, receipt);
  assert.notEqual(projected.assets, receipt.assets);
  receipt.assets.files = 999;
  assert.equal(projected.assets.files, 3);
});
test("added top-level and nested private seed fields cannot enter baseline metadata", () => {
  for (const nested of [false, true]) {
    const receipt = seedReceipt();
    (nested ? receipt.assets : receipt).privateField = "PRIVATE_SEED_RECEIPT_MARKER";
    assert.throws(() => seedProjection(receipt, seedReceipt()), /seed input identity changed/);
  }
});
test("seed projection refuses malformed digests, counts, identities and bindings", () => {
  const invalid = [
    r => { r.assets.files = -1; }, r => { r.assets.files = 1.5; }, r => { r.assets.files = 100001; },
    r => { r.assets.files = "3"; }, r => { r.assets.files = Infinity; },
    r => { r.assets.treeSha256 = "private-content"; }, r => { r.assets.archiveSha256 = "a".repeat(64); },
    r => { r.buildReceiptSha256 = "A".repeat(64); }, r => { r.helperSha256 = null; },
    r => { r.seedSha256 = "e".repeat(64); }, r => { r.releaseAcceptance = true; },
    r => { r.kind = "private-kind"; }, r => { r.assets = []; }, r => { delete r.seedSha256; },
  ];
  for (const mutate of invalid) {
    const receipt = seedReceipt(), expected = seedReceipt();
    mutate(receipt);
    assert.throws(() => seedProjection(receipt, expected), /seed input identity changed/);
  }
});
test("well-formed asset counts and tree hashes must match the independent archive observation", () => {
  for (const change of [{ files: 4 }, { treeSha256: "f".repeat(64) }]) {
    const receipt = seedReceipt(), expected = seedReceipt();
    Object.assign(receipt.assets, change);
    assert.throws(() => seedProjection(receipt, expected), /seed input identity changed/);
  }
});

function baselineInputs(t) {
  const root = built(t);
  const build = buildReceipt(root);
  storeReceipt(root, build);
  const helper = path.join(path.dirname(fileURLToPath(import.meta.url)), "seed-populate.cjs");
  fs.copyFileSync(helper, path.join(root, "dist/xtrace-seed-populate.cjs"));
  const bytes = Buffer.from("synthetic private dump\\n");
  writeFreshSeed(root, bytes);
  const digest = data => createHash("sha256").update(data).digest("hex");
  const receipt = { ...seedReceipt(), buildReceiptSha256: digest(fs.readFileSync(path.join(root, "xtrace-build-inputs.json"))),
    helperSha256: digest(fs.readFileSync(helper)), seedSha256: digest(bytes) };
  fs.writeFileSync(path.join(root, "xtrace-seed-inputs.json"), JSON.stringify(receipt), { flag: "wx", mode: 0o600 });
  return { root, bytes, receipt, digest };
}

test("database restore consumes the exact admitted dump bound to both baseline hashes", async t => {
  const { root, bytes, receipt, digest } = baselineInputs(t);
  const seed = prepareBaselineSeed(root, () => receipt.assets);
  assert.deepEqual(seed.metadata, { preparation: receipt, seedSha256: digest(bytes) });
  assert.deepEqual(JSON.parse(JSON.stringify(seed)), { metadata: seed.metadata });
  const calls = [];
  await seed.startAndRestore({ container: "fixture-db", username: "xtrace", database: "vendure" }, async () => {
    calls.push("start");
    const file = path.join(root, "seed.sql");
    fs.renameSync(file, file + ".admitted");
    writeFreshSeed(root, "replacement after admission");
  }, (argv, options) => {
    calls.push("restore");
    assert.deepEqual(argv, ["exec", "-i", "fixture-db", "psql", "-U", "xtrace", "-d", "vendure", "-q", "-v", "ON_ERROR_STOP=1"]);
    assert.deepEqual(Object.keys(options), ["input"]);
    assert.ok(Buffer.isBuffer(options.input));
    assert.deepEqual(options.input, bytes);
    assert.equal(digest(options.input), seed.metadata.seedSha256);
    assert.equal(digest(options.input), seed.metadata.preparation.seedSha256);
  });
  assert.deepEqual(calls, ["start", "restore"]);
  assert.ok(!JSON.stringify(seed.metadata).includes("synthetic private dump"));
});

test("a restore diagnostic cannot serialize private dump data into a failed baseline receipt", async t => {
  const { root, receipt } = baselineInputs(t);
  const seed = prepareBaselineSeed(root, () => receipt.assets);
  await assert.rejects(seed.startAndRestore({ container: "fixture", username: "fixture", database: "fixture" },
    () => {}, (_args, { input }) => { throw new Error(input.toString()); }),
  { message: "Vendure checked seed restore failed" });
});

test("changed preparation before startup rejects both the start and the restore", async t => {
  const { root, receipt } = baselineInputs(t);
  const assets = { ...receipt.assets };
  const seed = prepareBaselineSeed(root, () => assets);
  assets.files += 1;
  const calls = [];
  await assert.rejects(seed.startAndRestore({ container: "fixture", username: "fixture", database: "fixture" },
    () => calls.push("start"), () => calls.push("restore")), /seed input identity changed/);
  assert.deepEqual(calls, []);
});

test("seed admission requires the campaign's private regular dump and receipt", t => {
  for (const name of ["seed.sql", "xtrace-seed-inputs.json"]) {
    const { root, receipt } = baselineInputs(t);
    const file = path.join(root, name), original = file + ".original";
    fs.renameSync(file, original);
    fs.symlinkSync(original, file);
    assert.throws(() => prepareBaselineSeed(root, () => receipt.assets));
    fs.unlinkSync(file);
    fs.linkSync(original, file);
    assert.throws(() => prepareBaselineSeed(root, () => receipt.assets), /private regular file/);
  }
});

test("the fresh workspace is separate from an existing checkout and cannot be reused or redirected", t => {
  const anchor = app(t);
  const project = path.join(anchor, "vendure"), checkout = path.join(project, "src");
  fs.mkdirSync(checkout, { recursive: true });
  const sentinel = path.join(checkout, "upstream");
  fs.writeFileSync(sentinel, "untouched");
  const workspace = claimWorkspace(project, anchor);
  assert.equal(workspace, path.join(project, "preparation"));
  assert.equal(fs.statSync(workspace).mode & 0o777, 0o700);
  assert.deepEqual(fs.readdirSync(workspace), [".xtrace-home"]);
  assert.throws(() => claimWorkspace(project, anchor), { code: "EEXIST" });
  const linked = path.join(anchor, "linked-parent");
  fs.symlinkSync(project, linked);
  assert.throws(() => claimWorkspace(path.join(linked, "new"), anchor), /real application directory/);
  assert.equal(fs.existsSync(path.join(project, "new")), false);
  assert.equal(fs.readFileSync(sentinel, "utf8"), "untouched");
});

test("only a zero generator exit lets preparation continue", () => {
  assert.equal(generatorExitCode(0), 0);
  for (const code of [1, 2, 125, 143, 255]) assert.equal(generatorExitCode(code), code);
  for (const code of [null, undefined, -1, 256, "0"]) assert.equal(generatorExitCode(code), 1);
});

test("private errors during initial seed admission are reported with fixed categories", t => {
  const { root, receipt } = baselineInputs(t);
  const check = () => prepareBaselineSeed(root, () => receipt.assets);
  const receiptPath = path.join(root, "xtrace-seed-inputs.json");
  fs.writeFileSync(receiptPath, "synthetic-private-input");
  assert.throws(check, { message: "Vendure seed input identity changed" });
  fs.unlinkSync(receiptPath);
  assert.throws(check, { message: "Vendure seed requires a private regular file within its size bound" });
});

test("private verifier and parsing errors during revalidation reach neither startup nor restore", async t => {
  for (const source of ["asset verifier", "seed receipt", "build receipt"]) {
    const { root, receipt, digest } = baselineInputs(t);
    let reads = 0;
    const seed = prepareBaselineSeed(root, () => {
      if (++reads > 1 && source === "asset verifier") throw new Error("synthetic-private-diagnostic");
      return receipt.assets;
    });
    if (source === "seed receipt") fs.writeFileSync(path.join(root, "xtrace-seed-inputs.json"), "private-seed-marker");
    if (source === "build receipt") {
      const invalid = Buffer.from("private-build-marker");
      fs.writeFileSync(path.join(root, "xtrace-build-inputs.json"), invalid);
      fs.writeFileSync(path.join(root, "xtrace-build-inputs.sha256"), digest(invalid) + "\n");
    }
    const calls = [];
    await assert.rejects(seed.startAndRestore({ container: "fixture", username: "fixture", database: "fixture" },
      () => calls.push("start"), () => calls.push("restore")), { message: "Vendure seed input identity changed" });
    assert.deepEqual(calls, []);
  }
});
