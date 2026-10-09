import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = join(root, "packages/adapter-core/src");
const target = join(source, "../dist");
// The capability manifest is generated from the compiled module descriptors, never hand-edited.
const require = createRequire(import.meta.url);
const { buildManifest } = require(join(target, "manifest.cjs"));
await writeFile(join(target, "node-capabilities.json"), `${JSON.stringify(buildManifest())}\n`, { mode: 0o644 });

// The launchable dist is self-contained. Copy workspace links by value so the
// manifest covers every executable dependency and its package metadata.
const bundledModules = join(target, "node_modules");
await rm(bundledModules, { recursive: true, force: true });
for (const [name, sourcePath] of [
  ["@xtrace/protocol", join(root, "node_modules/@xtrace/protocol")],
  ["@bufbuild/protobuf", join(root, "node_modules/@bufbuild/protobuf")],
  ["hash-wasm", join(root, "node_modules/hash-wasm")],
  ["uuid", join(root, "node_modules/uuid")],
]) {
  const destination = join(bundledModules, name);
  await mkdir(dirname(destination), { recursive: true });
  await cp(sourcePath, destination, { recursive: true, dereference: true, verbatimSymlinks: false });
}

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error("adapter dist cannot contain symlinks");
    if (entry.isDirectory()) files.push(...await filesUnder(path));
    else if (entry.isFile()) files.push(path);
    else throw new Error("adapter dist contains an unsupported filesystem entry");
  }
  return files;
}

const manifestPath = join(target, "manifest.sha256");
const files = (await filesUnder(target)).filter((path) => path !== manifestPath).sort();
const lines = [];
for (const path of files) {
  const digest = createHash("sha256").update(await readFile(path)).digest("hex");
  lines.push(`${digest}  ${relative(target, path).split(sep).join("/")}`);
}
await writeFile(manifestPath, `${lines.join("\n")}\n`, { mode: 0o644 });
