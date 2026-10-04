// The single canonical form of generated TypeScript bindings: every .ts file ends with exactly one
// newline (a missing trailing newline is added, extra blank lines are removed). Shared by
// `npm run generate` (which writes the checked-in tree) and `generate:check` (which normalizes a fresh
// generation before comparing), so the two cannot diverge. Symlinks are never followed or rewritten.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

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
    const canonical = text.replace(/\n*$/, "\n");
    if (canonical !== text) await writeFile(path, canonical);
  }
}
