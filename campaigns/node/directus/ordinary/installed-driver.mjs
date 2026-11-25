// Runs only inside the campaign's private container. The Unix control socket is
// not published; this process signals only the application/viewer it starts.
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { sha256Hex } from "../../lib/canonical.mjs";
import { readback, requireFact } from "./installed-readback.mjs";
import { captureNoticeOutcome } from "./installed-drain.mjs";

const evidence = "/x/evidence", socket = "/x/control.sock";
if (process.argv.length === 3 && process.argv[2] === "finish") {
  const client = net.connect(socket);
  let response = "";
  client.setTimeout(600000, () => client.destroy(new Error("control_deadline")));
  client.once("error", () => { process.exitCode = 1; });
  client.once("connect", () => client.write("finish\n"));
  client.on("data", (data) => { response += data.toString(); if (response.length > 32) client.destroy(new Error("control_response_bound")); });
  client.once("end", () => { if (response !== "done\n") process.exitCode = 1; });
  client.once("close", () => { if (response !== "done\n") process.exitCode = 1; });
} else if (process.argv.length === 2) {
  process.umask(0o077);
  const config = JSON.parse(fs.readFileSync(evidence + "/config.json"));
  const env = { PATH: process.env.PATH, HOME: "/x/home", TMPDIR: "/x/tmp", XTRACE_DATA_HOME: "/x/data", ...config.appEnv };
  for (const p of [env.HOME, env.TMPDIR, env.XTRACE_DATA_HOME, "/x/extracted", "/x/extensions", "/x/uploads"]) fs.mkdirSync(p, { mode: 0o700, recursive: true });
  const report = { schemaVersion: 1, mode: config.mode, stages: [], analyzer: { status: "unreached" } };
  const write = () => fs.writeFileSync(evidence + "/driver.json", JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  function command(label, executable, args, { cwd = "/x/project", timeout = 60000, allowFailure = false } = {}) {
    const result = spawnSync(executable, args, { cwd, env, timeout, maxBuffer: 32 * 1024 * 1024 });
    fs.writeFileSync(`${evidence}/${label}.stdout`, result.stdout || "", { mode: 0o600 });
    fs.writeFileSync(`${evidence}/${label}.stderr`, result.stderr || "", { mode: 0o600 });
    report.stages.push({ name: label, status: result.status === 0 ? "passed" : "failed", exitCode: result.status }); write();
    if (!allowFailure) requireFact(result.status === 0, "command_" + label);
    return result;
  }
  let sequence = 0;
  const cli = "/x/install/bin/xtrace";
  function call(label, args) {
    const result = command(`${label}-${sequence++}`, cli, [...args, "--project-dir", "/x/project"]);
    try { const doc = JSON.parse(result.stdout); return doc.data ?? doc; }
    catch { throw new Error("cli_json_" + label); }
  }
  let app, exited, finished = false;
  async function finish() {
    requireFact(!finished, "finish_already_requested"); finished = true;
    if (app && app.exitCode === null && app.signalCode === null) app.kill("SIGTERM");
    if (app) {
      const deadline = setTimeout(() => app.kill("SIGKILL"), 25000);
      let status;
      try { status = await exited; } finally { clearTimeout(deadline); }
      report.stages.push({ name: "app_shutdown", status: status.code === 0 || status.code === 143 ? "passed" : "failed",
        exitCode: status.code, signal: status.signal }); write();
    }
    if (config.mode === "instrumented") {
      let outcome = "unavailable";
      try {
        const file = evidence + "/application.stderr";
        const stat = fs.lstatSync(file);
        if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= 32 * 1024 * 1024) outcome = captureNoticeOutcome(fs.readFileSync(file));
      } catch { /* Missing or unreadable notice evidence cannot pass. */ }
      report.stages.push({ name: "capture_notice_check", status: outcome === "absent" ? "passed" : "failed" });
      write();
      try {
        await readback({ cli, project: "/x/project", env, call, outDir: evidence });
        if (report.analyzer.status === "complete") call("catalog-reconciliation", ["catalog", "reconcile", "--json"]);
        report.stages.push({ name: "persisted_readback", status: "passed" });
      } catch { report.stages.push({ name: "persisted_readback", status: "failed" }); }
    }
    write();
  }
  try {
    requireFact(process.version === "v22.23.0", "pinned_node_version");
    requireFact(sha256Hex(fs.readFileSync(process.execPath)) === config.nodeBinarySha256, "pinned_node_binary");
    requireFact(sha256Hex(fs.readFileSync("/x/archive.tar.gz")) === config.archiveSha256, "archive_identity");
    command("package-verifier", "python3", ["/repo/packaging/verify_package.py", "/x/archive.tar.gz", "--version", "0.0.1"], { cwd: "/x" });
    command("extract", "tar", ["-xzf", "/x/archive.tar.gz", "-C", "/x/extracted"], { cwd: "/x" });
    const tops = fs.readdirSync("/x/extracted"); requireFact(tops.length === 1, "archive_root");
    const extracted = path.join("/x/extracted", tops[0]);
    const manifest = JSON.parse(fs.readFileSync(extracted + "/share/xtrace/PACKAGE-MANIFEST.json"));
    requireFact(manifest.sourceCommit === config.candidateSha && manifest.version === "0.0.1"
      && manifest.platform === config.packagePlatform, "package_source_platform");
    command("install", "sh", [extracted + "/install.sh", "--prefix", "/x/install", "--data-home", "/x/data"], { cwd: extracted });
    command("verify-install", "sh", [extracted + "/install.sh", "verify", "--prefix", "/x/install"], { cwd: extracted });
    const payload = fs.realpathSync("/x/install/current/share/xtrace");
    report.identity = { sourceCommit: manifest.sourceCommit, platform: manifest.platform,
      archiveSha256: config.archiveSha256, manifestSha256: sha256Hex(fs.readFileSync(extracted + "/share/xtrace/PACKAGE-MANIFEST.json")),
      cliSha256: sha256Hex(fs.readFileSync(cli)), nodePackManifestSha256: sha256Hex(fs.readFileSync(payload + "/packs/node/dist/manifest.sha256")),
      analyzerSha256: sha256Hex(fs.readFileSync(payload + "/analyzers/node/dist/main.js")), nodeVersion: process.version };
    report.identity.nodeBinarySha256 = sha256Hex(fs.readFileSync(process.execPath));
    command("runtime-packages", "dpkg-query", ["-W", "-f=${Package}\t${Version}\n"]);
    command("version", cli, ["--version"]);
    command("bootstrap", "node", ["api/dist/cli/run.js", "bootstrap"], { timeout: 900000 });
    let observation = [];
    if (config.mode === "instrumented") {
      call("init", ["init"]);
      const result = command("scan", cli, ["scan", "--project-dir", "/x/project", "--source", "/x/project/api/src",
        "--framework", "express", "--application-component", "directus", "--binding-key", "default", "--json"], { allowFailure: true });
      let scan;
      try { const doc = JSON.parse(result.stdout); scan = doc.data ?? doc; } catch { /* Kept private; not a successful analyzer. */ }
      const complete = result.status === 0 && scan?.status === "persisted_complete"
        && scan?.result?.analyzer === "xtrace-node-static 0.0.1" && scan?.result?.rulesetId === "express-routes/1"
        && /^[a-f0-9-]{36}$/.test(scan?.catalogRevisionId || "");
      report.analyzer = { status: complete ? "complete" : "incomplete", linkedCatalogRequested: complete };
      report.stages.push({ name: "installed_analyzer_result", status: complete ? "passed" : "failed" }); write();
      if (complete) observation = ["--observed-endpoint-policy", "runtime-route-v1", "--observed-endpoint-revision", scan.catalogRevisionId,
        "--application-component", "directus", "--binding-key", "default"];
    }
    const out = fs.openSync(evidence + "/application.stdout", "wx", 0o600);
    const err = fs.openSync(evidence + "/application.stderr", "wx", 0o600);
    app = config.mode === "instrumented"
      ? spawn(cli, ["run", "--project-dir", "/x/project", "--node-adapter", payload + "/packs/node/dist", "--node-mode", "auto",
        ...observation, "--", "node", "api/dist/cli/run.js", "start"], { cwd: "/x/project", env, stdio: ["ignore", out, err] })
      : spawn("node", ["api/dist/cli/run.js", "start"], { cwd: "/x/project", env, stdio: ["ignore", out, err] });
    fs.closeSync(out); fs.closeSync(err);
    exited = new Promise((resolve) => {
      app.once("exit", (code, signal) => resolve({ code, signal }));
      app.once("error", () => resolve({ code: null, signal: "spawn-error" }));
    });
    report.stages.push({ name: "app_spawn", status: "passed" }); write();
    const server = net.createServer((connection) => {
      let input = "", handling = false;
      connection.setTimeout(600000, () => connection.destroy());
      connection.on("error", () => { /* The private caller can disconnect during cleanup. */ });
      connection.on("data", async (data) => {
        if (handling) return;
        input += data.toString();
        if (input.length > 32) { handling = true; connection.end("failed\n"); return; }
        if (!input.includes("\n")) return;
        handling = true;
        if (input !== "finish\n") { connection.end("failed\n"); return; }
        try { await finish(); connection.end("done\n"); }
        catch { report.stages.push({ name: "finish", status: "failed" }); write(); connection.end("failed\n"); }
        server.close();
      });
    });
    server.listen(socket); await once(server, "listening");
    exited.then(() => {
      if (!finished) { report.stages.push({ name: "application_early_exit", status: "failed" }); write(); process.exitCode = 1; server.close(); }
    });
    process.once("SIGTERM", async () => { if (!finished) await finish(); server.close(); });
  } catch {
    report.stages.push({ name: "driver", status: "failed" }); write(); process.exitCode = 1;
  }
} else { process.exitCode = 1; }
