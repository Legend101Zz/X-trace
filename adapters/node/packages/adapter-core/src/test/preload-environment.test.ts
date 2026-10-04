import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Worker } from "node:worker_threads";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const dist = dirname(dirname(fileURLToPath(import.meta.url)));
const privateVariables = ["XTRACE_BOOTSTRAP_PATH", "XTRACE_NODE_ORIGINAL_OPTIONS", "XTRACE_NODE_OPTIONS_WAS_SET"];

function snapshot(): Record<string, string | null> {
  const names = ["XTRACE_BOOTSTRAP_PATH", "XTRACE_NODE_ORIGINAL_OPTIONS", "XTRACE_NODE_OPTIONS_WAS_SET"];
  return {
    nodeOptions: process.env.NODE_OPTIONS ?? null,
    ...Object.fromEntries(names.map((name) => [name, process.env[name] ?? null])),
  };
}

for (const mode of ["cjs", "esm"] as const) {
  test(`${mode} preload is private to the initial app and does not recurse into children or workers`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "xtrace-node-preload-"));
    try {
      const extension = mode === "cjs" ? "cjs" : "mjs";
      const childPath = join(directory, `child.${extension}`);
      const workerPath = join(directory, `worker.${extension}`);
      const appPath = join(directory, `app.${extension}`);
      const moduleBody = mode === "cjs"
        ? `const { parentPort } = require("node:worker_threads"); parentPort.postMessage((${snapshot.toString()})());`
        : `import { parentPort } from "node:worker_threads"; parentPort.postMessage((${snapshot.toString()})());`;
      await writeFile(childPath, `console.log(JSON.stringify((${snapshot.toString()})()));\n`);
      await writeFile(workerPath, moduleBody);
      const appBody = mode === "cjs"
        ? `const { spawnSync } = require("node:child_process"); const { Worker } = require("node:worker_threads"); (async () => { const child = spawnSync(process.execPath, [${JSON.stringify(childPath)}], { encoding: "utf8" }); if (child.status !== 0) throw new Error("child failed"); const worker = await new Promise((resolve, reject) => { const w = new Worker(${JSON.stringify(workerPath)}); w.once("message", resolve); w.once("error", reject); }); console.log(JSON.stringify({ self: (${snapshot.toString()})(), child: JSON.parse(child.stdout), worker })); })().catch(() => process.exitCode = 2);\n`
        : `import { spawnSync } from "node:child_process"; import { Worker } from "node:worker_threads"; const child = spawnSync(process.execPath, [${JSON.stringify(childPath)}], { encoding: "utf8" }); if (child.status !== 0) process.exit(2); const worker = await new Promise((resolve, reject) => { const w = new Worker(${JSON.stringify(workerPath)}); w.once("message", resolve); w.once("error", reject); }); console.log(JSON.stringify({ self: (${snapshot.toString()})(), child: JSON.parse(child.stdout), worker }));\n`;
      await writeFile(appPath, appBody);
      const preload = join(dist, mode === "cjs" ? "register.cjs" : "register.mjs");
      const injected = mode === "cjs"
        ? `--require="${preload.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`
        : `--import=${pathToFileURL(preload).href}`;
      const result = spawnSync(process.execPath, [appPath], {
        encoding: "utf8",
        env: {
          ...process.env,
          NODE_OPTIONS: `--trace-warnings ${injected}`,
          XTRACE_BOOTSTRAP_PATH: "/private/xtrace-bootstrap-canary",
          XTRACE_NODE_ORIGINAL_OPTIONS: "--trace-warnings",
          XTRACE_NODE_OPTIONS_WAS_SET: "1",
        },
      });
      assert.equal(result.status, 0, "the application and its children complete normally");
      const evidence = JSON.parse(result.stdout.trim()) as { self: Record<string, string | null>; child: Record<string, string | null>; worker: Record<string, string | null> };
      for (const processEvidence of [evidence.self, evidence.child]) {
        assert.equal(processEvidence.nodeOptions, "--trace-warnings");
        for (const name of privateVariables) assert.equal(processEvidence[name], null);
      }
      for (const name of privateVariables) assert.equal(evidence.worker[name], null);
      assert.equal(Boolean(evidence.worker.nodeOptions?.includes("register.")), false);
      assert.equal(result.stdout.includes("/private/xtrace-bootstrap-canary"), false);
      assert.equal(result.stderr.includes("/private/xtrace-bootstrap-canary"), false);
      // Ensure the fixture itself stayed readable while using file-based launch only.
      assert.ok((await readFile(appPath, "utf8")).includes("spawnSync"));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
