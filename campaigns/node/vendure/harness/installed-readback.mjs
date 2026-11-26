// Runs with --network none inside the same image, UID and absolute installed mounts as capture.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { stopOwnedViewer } from "./installed-lifecycle.mjs";
import { pages, inventory, verifiedDetail, judgeObservedWorkload, equal, need } from "./installed-evidence.mjs";

const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let sequence = 0, viewer, viewerClosed, browser;
const report = { status: "failed", cliViewerParity: false, readinessRecordings: 0, workloadRecordings: 0,
  complete: 0, httpRoots: 0, expressHandlers: 0, absentOutcome: 0, orphanParents: 0, orphanAsyncParents: 0,
  aggregateResponseCountMatches: false, perRequestAttribution: "unverified", workerTraceAncestry: "unverified" };
function save(name, bytes) { fs.writeFileSync(path.join(config.output, name), bytes, { flag: "wx", mode: 0o600 }); }
function cli(args) {
  const result = spawnSync(config.cli, ["recording", ...args, "--project-dir", config.project],
    { timeout: 30000, maxBuffer: 16 * 1024 * 1024, stdio: "pipe" });
  const number = ++sequence;
  save(`cli-${number}.json`, result.stdout || Buffer.alloc(0));
  save(`cli-${number}.stderr`, result.stderr || Buffer.alloc(0));
  need(result.status === 0 && !result.error && result.signal === null);
  return JSON.parse(result.stdout);
}
function readiness(child) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => finish(new Error("Vendure viewer readiness deadline")), 60000);
    const exited = () => finish(new Error("Vendure viewer exited before readiness"));
    function finish(error, result) {
      clearTimeout(timer); child.stdout.off("data", read); child.off("close", exited);
      error ? reject(error) : resolve(result);
    }
    function read(bytes) {
      buffer += bytes.toString("utf8");
      if (Buffer.byteLength(buffer) > 65536) return finish(new Error("Vendure viewer readiness exceeds bound"));
      if (!buffer.includes("\n")) return;
      try { finish(null, JSON.parse(buffer.slice(0, buffer.indexOf("\n")))); } catch { finish(new Error("Vendure viewer readiness invalid")); }
    }
    child.stdout.on("data", read); child.once("close", exited);
  });
}
try {
  const listed = await pages(async after => cli(["list", "--limit", "20", ...(after ? ["--after", after] : [])]),
    "recordings", "next_after", 20, 400);
  const { projectId, ids: readyIds } = JSON.parse(fs.readFileSync(config.snapshot, "utf8"));
  const cliRows = inventory(listed, projectId, false);
  const ids = [...cliRows.keys()];
  need(ids.length > 0);
  need(Array.isArray(readyIds) && readyIds.length > 0 && readyIds.every(id => ids.includes(id)));
  report.readinessRecordings = readyIds.length;
  const details = new Map();
  for (const id of ids) {
    const paged = await pages(async cursor => cli(["show", id, "--limit", "100", ...(cursor ? ["--cursor", cursor] : [])]),
      "events", "next_cursor", 100, 4000);
    details.set(id, verifiedDetail(paged, id, projectId, cliRows.get(id), false));
  }
  const stderr = fs.openSync(path.join(config.output, "viewer.stderr"), "wx", 0o600);
  viewer = spawn(config.cli, ["open", "--project-dir", config.project, "--viewer", "--no-browser"], { stdio: ["ignore", "pipe", stderr] });
  fs.closeSync(stderr);
  viewerClosed = once(viewer, "close");
  viewerClosed.catch(() => {});
  const ready = await readiness(viewer);
  need(/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(ready.origin));
  const url = new URL(ready.url);
  need(url.origin === ready.origin && url.pathname === "/" && url.search === "" && /^#token=[A-Za-z0-9_-]{43}$/.test(url.hash));
  // The readiness token is an expected credential transport, stored privately and excluded from privacy scan inputs.
  save("viewer-readiness.private.json", JSON.stringify(ready) + "\n");
  const requireFromViewer = createRequire("/opt/xtrace-vendure-viewer/package.json");
  const { chromium } = requireFromViewer("@playwright/test");
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  await context.route("**/*", route => {
    const request = route.request(), address = new URL(request.url());
    const appRead = request.method() === "GET" && (!address.pathname.startsWith("/api/") ||
      address.pathname === "/api/v1/endpoints" || /^\/api\/v1\/recordings(?:\/[a-f0-9-]{36})?$/.test(address.pathname));
    const exchange = request.method() === "POST" && address.pathname === "/api/v1/auth/exchange";
    return address.origin === ready.origin && (appRead || exchange) ? route.continue() : route.abort();
  });
  const [exchange] = await Promise.all([
    page.waitForResponse(r => r.url() === ready.origin + "/api/v1/auth/exchange" && r.request().method() === "POST", { timeout: 60000 }),
    page.goto(ready.url, { timeout: 60000, waitUntil: "domcontentloaded" }),
  ]);
  const peer = await exchange.serverAddr();
  need(exchange.status() === 200 && peer?.ipAddress === "127.0.0.1" && peer.port === Number(url.port));
  const auth = await exchange.body();
  need(auth.length <= 65536 && JSON.parse(auth).authenticated === true);
  save("api-" + (++sequence) + ".json", auth);
  need((await context.cookies(ready.origin)).some(c => c.name === "xtrace_viewer_session" && /^[A-Za-z0-9_-]{43}$/.test(c.value)));
  const get = async (route, params) => {
    const query = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== undefined));
    const text = await page.evaluate(async url => {
      const response = await fetch(url, { headers: { "X-XTrace-Client": "viewer-v1" }, credentials: "same-origin",
        redirect: "error", signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error("Vendure viewer read failed");
      const reader = response.body.getReader(), decoder = new TextDecoder();
      let size = 0, text = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 16 * 1024 * 1024) { await reader.cancel(); throw new Error("Vendure viewer document too large"); }
        text += decoder.decode(value, { stream: true });
      }
      return text + decoder.decode();
    }, route + "?" + query);
    save("api-" + (++sequence) + ".json", text);
    return JSON.parse(text);
  };
  const apiListed = await pages(after => get("/api/v1/recordings", { limit: 20, after }), "recordings", "nextAfter", 20, 400);
  const apiRows = inventory(apiListed, projectId, true);
  equal([...apiRows], [...cliRows]);
  for (const id of ids) {
    const paged = await pages(cursor => get("/api/v1/recordings/" + id, { limit: 100, cursor }), "events", "nextCursor", 100, 4000);
    equal(verifiedDetail(paged, id, projectId, apiRows.get(id), true), details.get(id));
  }
  judgeObservedWorkload({ save, projectId, cliRows, readyIds, details, config, report });
  report.status = "passed";
} catch { report.status = "failed"; }
finally {
  if (browser) { try { await browser.close(); } catch { report.status = "failed"; } }
  if (viewer) {
    const stopped = await stopOwnedViewer(viewer, viewerClosed);
    report.viewerShutdown = stopped.status;
    report.viewerStop = stopped;
    if (stopped.status !== "normal") report.status = "failed";
  }
  save("readback.json", JSON.stringify(report) + "\n");
  if (report.status !== "passed") process.exitCode = 1;
}
