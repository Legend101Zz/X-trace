import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const workspace = resolve(dirname(scriptPath), "..");
const checkedIn = join(workspace, "packages/protocol/src/gen");
const schema = resolve(workspace, "../../schema/proto");

async function tree(directory, base = directory) {
  const result = [];
  for (const entry of (await readdir(directory, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await tree(path, base));
    else if (entry.isFile()) result.push([relative(base, path), await readFile(path)]);
  }
  return result;
}

function sameTree(left, right) {
  return left.length === right.length && left.every(([path, bytes], index) => {
    const candidate = right[index];
    return candidate?.[0] === path && bytes.equals(candidate[1]);
  });
}

async function normalizeTree(directory) {
  for (const [path, bytes] of await tree(directory)) {
    if (path.endsWith(".ts")) {
      await writeFile(join(directory, path), bytes.toString("utf8").replace(/\n+$/, "\n"));
    }
  }
}

async function generatorOutput(directory) {
  const template = JSON.stringify({
    version: "v2",
    plugins: [{
      local: "protoc-gen-es",
      out: directory,
      opt: "target=ts,import_extension=js",
    }],
  });
  const result = spawnSync(
    "npm",
    ["exec", "--", "buf", "generate", schema, "--template", template],
    { cwd: workspace, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Buf generation failed with status ${result.status}`);
}

async function verifyComparatorDetectsStaleFiles() {
  const root = await mkdtemp(join(tmpdir(), "xtrace-codegen-check "));
  try {
    const expected = join(root, "expected");
    const generated = join(root, "generated");
    await Promise.all([mkdir(expected), mkdir(generated)]);
    await Promise.all([
      writeFile(join(expected, "canonical.ts"), "export {};\n"),
      writeFile(join(generated, "canonical.ts"), "export {};\n"),
    ]);
    if (!sameTree(await tree(expected), await tree(generated))) {
      throw new Error("codegen comparator rejected identical trees");
    }
    await writeFile(join(generated, "stale.ts"), "export {};\n");
    if (sameTree(await tree(expected), await tree(generated))) {
      throw new Error("codegen comparator failed to detect an extra stale file");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

await verifyComparatorDetectsStaleFiles();
const temporaryRoot = await mkdtemp(join(tmpdir(), "xtrace-proto-gen "));
try {
  const generated = join(temporaryRoot, "bindings");
  await mkdir(generated);
  await generatorOutput(generated);
  await normalizeTree(generated);
  if (!sameTree(await tree(checkedIn), await tree(generated))) {
    process.stderr.write("generated protobuf bindings differ from canonical schemas\n");
    process.exitCode = 1;
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
