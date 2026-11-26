// Preparation reads only local campaign inputs; it never starts Vendure or sends a request.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "../campaign.json"), "utf8"));
const snapshot = path.join(here, "../starter-snapshot");
const files = ["package.json", "package-lock.json", "tsconfig.json", "tsconfig.dashboard.json", "vite.config.mts",
  "src/index.ts", "src/index-worker.ts", "src/vendure-config.ts", "src/environment.d.ts"];
const compiled = ["dist/index.js", "dist/index-worker.js", "dist/vendure-config.js"];
const seedHelper = "dist/xtrace-seed-populate.cjs";
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
function requireDirectory(root) {
  if (!fs.lstatSync(root).isDirectory()) throw new Error("Vendure preparation requires a real application directory");
}
// The hosted shell supplies a fresh 0700 parent outside the upstream checkout. Standalone
// create keeps its preparation in a separate child of the configured project directory.
export function claimWorkspace(parent, runnerTemp) {
  const directory = path.resolve(parent);
  const anchor = runnerTemp ? path.resolve(runnerTemp) : path.parse(directory).root;
  const relative = path.relative(anchor, directory);
  if (!relative || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
    throw new Error("Vendure workspace parent is outside the preparation root");
  }
  let current = anchor;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    try {
      fs.mkdirSync(current, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      requireDirectory(current);
    }
  }
  const owner = fs.lstatSync(directory);
  if (owner.uid !== process.getuid() || (owner.mode & 0o022) !== 0) {
    throw new Error("Vendure workspace parent must be owner-controlled");
  }
  const workspace = path.join(directory, "preparation");
  fs.mkdirSync(workspace, { mode: 0o700 }); // An existing entry never authorizes reuse.
  fs.mkdirSync(path.join(workspace, ".xtrace-home"), { mode: 0o700 });
  return workspace;
}
// A process stopped by a signal has a null exit code. Preserve normal nonzero codes.
export function generatorExitCode(code) {
  return Number.isInteger(code) && code >= 0 && code <= 255 ? code : 1;
}
function read(root, name) {
  requireDirectory(root);
  let current = root;
  for (const part of name.split("/")) {
    current = path.join(current, part);
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error("Vendure preparation refuses linked inputs");
  }
  if (!fs.statSync(current).isFile()) throw new Error("Vendure preparation input is not a regular file");
  return fs.readFileSync(current);
}
function sourceIdentity(root) {
  return Object.fromEntries(files.map(name => [name, hash(read(root, name))]));
}
function verifySnapshot() {
  const lock = read(snapshot, "package-lock.json");
  if (hash(lock) !== campaign.starter.lockfileSha256 || hash(lock) !== campaign.packageManager.lockfileSha256) {
    throw new Error("Vendure tracked lock does not match the campaign pin");
  }
  const pkg = JSON.parse(read(snapshot, "package.json"));
  const locked = JSON.parse(lock).packages[""];
  for (const key of ["dependencies", "devDependencies"]) {
    if (JSON.stringify(pkg[key]) !== JSON.stringify(locked[key])) throw new Error("Vendure package and lock disagree");
  }
  return pkg;
}
// Replace the scaffold directory entry, never truncate its possibly shared inode.
function replaceScaffold(destination, bytes) {
  const mode = fs.statSync(destination).mode & 0o777;
  const directory = fs.mkdtempSync(path.join(path.dirname(destination), ".xtrace-stage-"));
  const staged = path.join(directory, "input");
  try {
    fs.writeFileSync(staged, bytes, { flag: "wx", mode });
    fs.chmodSync(staged, mode);
    fs.renameSync(staged, destination);
  } finally {
    if (fs.existsSync(staged)) fs.unlinkSync(staged);
    fs.rmdirSync(directory);
  }
}
export function writeFreshSeed(app, dump) {
  fs.writeFileSync(path.join(app, "seed.sql"), dump, { flag: "wx", mode: 0o600 });
}
export function stageStarter(app) {
  verifySnapshot();
  // create still supplies its generated .env and static email templates. The runnable
  // source/dependency replacement is explicit, using the already adapted tracked starter.
  read(app, ".env");
  for (const name of ["xtrace-build-inputs.json", "xtrace-build-inputs.sha256"]) {
    if (fs.lstatSync(path.join(app, name), { throwIfNoEntry: false })) {
      throw new Error("Vendure preparation already completed; use a fresh workspace");
    }
  }
  for (const name of files) {
    const destination = path.join(app, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    read(app, name); // Refuse unexpected linked or missing scaffold paths before overwriting.
    replaceScaffold(destination, read(snapshot, name));
  }
  verifyStarter(app);
}
export function verifyStarter(app, dependencies = false) {
  const pkg = verifySnapshot();
  if (JSON.stringify(sourceIdentity(app)) !== JSON.stringify(sourceIdentity(snapshot))) {
    throw new Error("Vendure runnable starter changed from its tracked inputs");
  }
  // The pinned CLI discovers these before tsconfig.json. An extra config would
  // select different compilation inputs even when the tracked config still matches.
  for (const name of ["tsconfig.server.json", "tsconfig.worker.json", "tsconfig.build.json"]) {
    if (fs.lstatSync(path.join(app, name), { throwIfNoEntry: false })) {
      throw new Error("Vendure scaffold contains an unpinned build configuration");
    }
  }
  // Every TypeScript source is compiled by the starter tsconfig. Do not admit an
  // extra generated entry, migration or plugin outside the closed source snapshot.
  const sources = [];
  function walk(directory, prefix = "src") {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error("Vendure preparation refuses linked sources");
      const name = prefix + "/" + entry.name;
      if (entry.isDirectory()) walk(path.join(directory, entry.name), name);
      else if (entry.name.endsWith(".ts")) sources.push(name);
    }
  }
  walk(path.join(app, "src"));
  if (JSON.stringify(sources.sort()) !== JSON.stringify(files.filter(name => name.startsWith("src/")).sort())) {
    throw new Error("Vendure scaffold contains unpinned TypeScript sources");
  }
  if (dependencies) {
    for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
      const installed = JSON.parse(read(app, "node_modules/" + name + "/package.json"));
      if (installed.name !== name || installed.version !== version) throw new Error("Vendure installed direct dependency differs from lock");
    }
  }
  return sourceIdentity(app);
}
export function createCompileDirectory(app) {
  requireDirectory(app);
  // The two compilers can write the same filenames. Establish ownership before the first one runs.
  fs.mkdirSync(path.join(app, "dist"), { mode: 0o700 });
}
export function verifyOutputs(app, seeded = false) {
  // Both normal CLI targets run tsc -p tsconfig.json --noEmitOnError. The pinned
  // config emits these three JS files, without maps/declarations or a dashboard.
  // Refuse every additional dist entry, including the configured migration glob;
  // never clean a stale workspace to make it appear admitted.
  const directory = path.join(app, "dist");
  if (!fs.lstatSync(directory).isDirectory()) throw new Error("Vendure dist is not a regular directory");
  const admitted = [...compiled, ...(seeded ? [seedHelper] : [])].sort();
  const actual = fs.readdirSync(directory).map(name => "dist/" + name).sort();
  if (JSON.stringify(actual) !== JSON.stringify(admitted)) throw new Error("Vendure dist contains unadmitted outputs");
  const outputs = Object.fromEntries(compiled.map(name => [name, hash(read(app, name))]));
  if (seeded && !read(app, seedHelper).equals(fs.readFileSync(path.join(here, "seed-populate.cjs")))) {
    throw new Error("Vendure staged seed helper identity changed");
  }
  return outputs;
}
export function finishBuild(app) {
  const source = verifyStarter(app, true);
  if (process.versions.node !== campaign.runtime.nodeImageVersion) throw new Error("Vendure build Node version differs from pin");
  const outputs = verifyOutputs(app);
  const receipt = { schemaVersion: 1, kind: "vendure-preparation-inputs", releaseAcceptance: false,
    upstreamSha: campaign.upstream.sha, registryBuildNotSourceRebuild: true,
    nodeVersion: process.versions.node, npmVersion: execFileSync("npm", ["--version"], { encoding: "utf8" }).trim(),
    sources: source, outputs };
  validateBuildIdentity(receipt);
  const bytes = JSON.stringify(receipt, null, 2) + "\n";
  const fresh = { flag: "wx", mode: 0o600 };
  fs.writeFileSync(path.join(app, "xtrace-build-inputs.json"), bytes, fresh);
  fs.writeFileSync(path.join(app, "xtrace-build-inputs.sha256"), hash(bytes) + "\n", fresh);
}
function validateBuildIdentity(receipt) {
  const keys = ["schemaVersion", "kind", "releaseAcceptance", "upstreamSha", "registryBuildNotSourceRebuild",
    "nodeVersion", "npmVersion", "sources", "outputs"];
  // This campaign uses the stable npm bundled by the pinned Node release.
  const stableVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
  if (!closedKeys(receipt, keys) || receipt.schemaVersion !== 1 || receipt.kind !== "vendure-preparation-inputs" ||
      receipt.releaseAcceptance !== false || receipt.upstreamSha !== campaign.upstream.sha ||
      receipt.registryBuildNotSourceRebuild !== true || receipt.nodeVersion !== campaign.runtime.nodeImageVersion ||
      typeof receipt.npmVersion !== "string" || receipt.npmVersion.length > 64 || !stableVersion.test(receipt.npmVersion)) {
    throw new Error("Vendure build provenance differs from the preparation contract");
  }
}
export function verifyBuild(app, seeded = false) {
  const bytes = read(app, "xtrace-build-inputs.json");
  if (read(app, "xtrace-build-inputs.sha256").toString() !== hash(bytes) + "\n") {
    throw new Error("Vendure preparation receipt changed after compilation");
  }
  const receipt = JSON.parse(bytes);
  validateBuildIdentity(receipt);
  if (JSON.stringify(receipt.sources) !== JSON.stringify(verifyStarter(app, true))) {
    throw new Error("Vendure build input identity changed");
  }
  if (JSON.stringify(verifyOutputs(app, seeded)) !== JSON.stringify(receipt.outputs)) {
    throw new Error("Vendure built entrypoint identity changed");
  }
  return hash(bytes);
}
function closedKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}
export function seedProjection(receipt, expected) {
  const top = ["schemaVersion", "kind", "releaseAcceptance", "assets", "buildReceiptSha256", "helperSha256", "seedSha256"];
  const assetKeys = ["archiveSha256", "files", "treeSha256"];
  const digest = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  if (!closedKeys(receipt, top) || !closedKeys(receipt.assets, assetKeys) ||
      receipt.schemaVersion !== 1 || receipt.kind !== "vendure-seed-inputs" || receipt.releaseAcceptance !== false ||
      !Number.isSafeInteger(receipt.assets.files) || receipt.assets.files < 1 || receipt.assets.files > 100000 ||
      !digest(receipt.assets.treeSha256) || !digest(receipt.assets.archiveSha256) ||
      receipt.assets.archiveSha256 !== campaign.starter.package.tarballSha256 ||
      assetKeys.some(key => receipt.assets[key] !== expected.assets[key]) ||
      ["buildReceiptSha256", "helperSha256", "seedSha256"].some(key => !digest(receipt[key]) || receipt[key] !== expected[key])) {
    throw new Error("Vendure seed input identity changed");
  }
  // Baseline metadata is a new bounded public projection, never the private JSON.
  return { schemaVersion: 1, kind: "vendure-seed-inputs", releaseAcceptance: false,
    assets: { archiveSha256: receipt.assets.archiveSha256, files: receipt.assets.files, treeSha256: receipt.assets.treeSha256 },
    buildReceiptSha256: receipt.buildReceiptSha256, helperSha256: receipt.helperSha256, seedSha256: receipt.seedSha256 };
}
function readPrivateSeedFile(app, name, maximumBytes) {
  try {
    requireDirectory(app);
    const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
    const fd = fs.openSync(path.join(app, name), flags);
    try {
      const info = fs.fstatSync(fd);
      if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) {
        throw new Error("Vendure seed requires a private regular file");
      }
      if (info.size > maximumBytes) throw new Error("Vendure seed input exceeds its size bound");
      const bytes = Buffer.alloc(info.size);
      let offset = 0;
      while (offset < bytes.length) {
        const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
        if (count === 0) throw new Error("Vendure seed input changed during admission");
        offset += count;
      }
      const after = fs.fstatSync(fd);
      if (after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs) {
        throw new Error("Vendure seed input changed during admission");
      }
      return bytes;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // Filesystem errors may include private filenames. Both admission callers report a fixed category.
    throw new Error("Vendure seed requires a private regular file within its size bound");
  }
}

// Only the digest projection is serializable. The restore callback closes over the bytes admitted here.
export function prepareBaselineSeed(app, verifiedAssets) {
  const dump = readPrivateSeedFile(app, "seed.sql", 256 * 1024 * 1024);
  const seedSha256 = hash(dump);
  function preparation() {
    const receiptBytes = readPrivateSeedFile(app, "xtrace-seed-inputs.json", 65536);
    try {
      const buildReceiptSha256 = verifyBuild(app, true);
      return seedProjection(JSON.parse(receiptBytes), { assets: verifiedAssets(), buildReceiptSha256, seedSha256,
        helperSha256: hash(read(here, "seed-populate.cjs")) });
    } catch {
      // This runs before the baseline and again inside its error-reporting boundary.
      throw new Error("Vendure seed input identity changed");
    }
  }
  const initial = preparation();
  Object.freeze(initial.assets);
  Object.freeze(initial);
  return {
    metadata: Object.freeze({ preparation: initial, seedSha256 }),
    async startAndRestore({ container, username, database }, start, run) {
      if (JSON.stringify(preparation()) !== JSON.stringify(initial)) {
        throw new Error("Vendure baseline preparation changed before database startup");
      }
      await start();
      try {
        run(["exec", "-i", container, "psql", "-U", username, "-d", database, "-q", "-v", "ON_ERROR_STOP=1"],
          { input: dump });
      } catch {
        // The common runner persists exception messages. A psql diagnostic may quote a private input.
        throw new Error("Vendure checked seed restore failed");
      }
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, app] = process.argv.slice(2);
  if (action === "before-compile") {
    verifyStarter(app, true);
    createCompileDirectory(app);
  } else if (action === "verify") verifyStarter(app, true);
  else if (action === "finish") finishBuild(app);
  else throw new Error("unsupported Vendure preparation action");
}
