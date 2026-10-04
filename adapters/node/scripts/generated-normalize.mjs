// The single canonical form of generated TypeScript bindings: every .ts file ends with exactly one
// newline. Shared by `npm run generate` (which writes the checked-in tree) and `generate:check`
// (which normalizes a fresh generation before comparing), so the two cannot diverge.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

async function files(directory) {
  const result = [];
  for (const entry of (await readdir(directory, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await files(path));
    else if (entry.isFile()) result.push(path);
  }
  return result;
}

export async function normalizeTree(directory) {
  for (const path of await files(directory)) {
    if (!path.endsWith(".ts")) continue;
    const text = (await readFile(path)).toString("utf8");
    const canonical = text.replace(/\n+$/, "\n");
    if (canonical !== text) await writeFile(path, canonical);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const target = process.argv[2];
  if (!target) {
    process.stderr.write("usage: node scripts/generated-normalize.mjs <directory>\n");
    process.exit(2);
  }
  await normalizeTree(resolve(target));
}
