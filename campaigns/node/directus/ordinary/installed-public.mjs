// Public entry point: all child output goes to private files before closed projection.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { projectPublicOutput } from "./installed-output.mjs";

process.umask(0o077);
let result = projectPublicOutput("", 1);
try {
  if (process.argv.length !== 4 || typeof process.getuid !== "function") throw Error("private arguments required");
  const directory = path.resolve(process.argv[3]);
  for (let current = directory;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || ![0, process.getuid()].includes(stat.uid) || stat.mode & 0o022) throw Error("unsafe directory");
    if (current === path.dirname(current)) break;
  }
  const stat = fs.statSync(directory);
  if (stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) throw Error("unsafe directory mode");
  const out = fs.openSync(path.join(directory, "installed.stdout.private"), "wx", 0o600);
  let err;
  try {
    err = fs.openSync(path.join(directory, "installed.stderr.private"), "wx", 0o600);
    const driver = fileURLToPath(new URL("./installed.mjs", import.meta.url));
    const child = spawnSync(process.execPath, [driver, process.argv[2]], { stdio: ["ignore", out, err] });
    const size = fs.fstatSync(out).size;
    if (size <= 1024 * 1024) result = projectPublicOutput(fs.readFileSync(path.join(directory, "installed.stdout.private"), "utf8"), child.status ?? 1);
  } finally { fs.closeSync(out); if (err !== undefined) fs.closeSync(err); }
} catch { /* Only the fixed failure envelope is public. */ }
process.stdout.write(JSON.stringify(result) + "\n");
process.exitCode = result.result === "passed" ? 0 : 1;
