import { copyFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = join(root, "packages/adapter-core/src");
const target = join(source, "../dist");
await Promise.all([
  copyFile(join(source, "node-http-manifest.json"), join(target, "node-http-manifest.json")),
]);
