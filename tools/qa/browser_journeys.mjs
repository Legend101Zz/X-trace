// Run against the installed archive with Playwright from web/app/node_modules.
// Required flags: --xtrace, --project-dir, --out, --source-sha, --package-sha256.
// Both this runner and camp_instr_steps.py accept --widths.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { stopViewer } from "./campaign_child.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => (a.startsWith("--") ? [...acc, [a.slice(2), arr[i + 1]]] : acc), []));
for (const k of ["xtrace", "project-dir", "out"]) {
  if (!args[k]) { console.error(`missing --${k}`); process.exit(2); }
}
const declaredWidths = (args.widths ?? "320,736,1024,1280,1440").split(",");
const widths = declaredWidths.map(Number);
const sourceSha = args["source-sha"];
const packageSha256 = args["package-sha256"];
if (declaredWidths.some((w) => !/^[1-9][0-9]{0,15}$/.test(w))
    || new Set(widths).size !== widths.length || widths.some((w) => !Number.isSafeInteger(w))
    || !/^[0-9a-f]{40}$/.test(sourceSha) || !/^[0-9a-f]{64}$/.test(packageSha256)) {
  console.error("invalid browser widths or package provenance");
  process.exit(2);
}
const out = path.resolve(args.out);
mkdirSync(path.join(out, "dom"), { recursive: true });
const require = createRequire(path.resolve("web/app/package.json"));
const { chromium, expect } = require("@playwright/test");

function findReady(obj) {
  if (obj && typeof obj === "object") {
    if (typeof obj.url === "string" && typeof obj.origin === "string") return obj;
    for (const value of Object.values(obj)) {
      const ready = findReady(value);
      if (ready) return ready;
    }
  }
  return null;
}

function startViewer() {
  return new Promise((resolve, reject) => {
    const p = spawn(args.xtrace, ["open", "--project-dir", args["project-dir"], "--viewer", "--no-browser"], { stdio: ["ignore", "pipe", "ignore"], detached: true });
    let buf = "";
    let settled = false;
    const fail = async error => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      try { await stopViewer(p); } catch (cleanup) { error = new Error("viewer startup cleanup failed", { cause: [error, cleanup] }); }
      reject(error);
    };
    const t = setTimeout(() => { void fail(new Error("viewer readiness timeout")); }, 60000);
    p.once("error", error => { void fail(error); });
    p.once("exit", () => { void fail(new Error("viewer exited before readiness")); });
    p.stdout.setEncoding("utf8").on("data", (d) => {
      buf += d;
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        let ready;
        try { ready = findReady(JSON.parse(line)); } catch { continue; }
        if (ready && !settled) { settled = true; clearTimeout(t); resolve({ p, ready }); return; }
      }
    });
  });
}

async function capture(page, row, name) {
  const stem = `${name}-${row.width}`;
  writeFileSync(path.join(out, "dom", `${stem}.txt`), await page.evaluate(() => document.body.innerText));
  const screenshot = await page.screenshot({ path: path.join(out, `${stem}.png`), fullPage: true });
  const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  row.steps[name] = {
    status: horizontalOverflow ? "fail" : "pass", screenshot: `${stem}.png`, horizontalOverflow,
    screenshotSha256: createHash("sha256").update(screenshot).digest("hex"),
  };
}

async function findRecording(catalog) {
  const recordings = catalog.locator(".recording-list button.recording:visible");
  const unmatched = catalog.getByRole("button", { name: "Not linked to an endpoint", exact: true });
  await unmatched.click({ timeout: 10000 });
  await expect(recordings.first().or(catalog.getByText("No unmatched recordings", { exact: true }))).toBeVisible();
  if (await recordings.first().isVisible()) return recordings.first();

  await catalog.getByRole("button", { name: "Observed endpoints", exact: true }).click({ timeout: 10000 });
  const endpoints = catalog.locator("button.endpoint-card:visible");
  await expect(endpoints.first()).toBeVisible();
  for (const endpoint of await endpoints.all()) {
    const branch = endpoint.locator("..");
    const linked = branch.locator(".recording-list button.recording:visible").first();
    await endpoint.click({ timeout: 10000 });
    await expect(linked.or(branch.getByText("No linked recordings", { exact: true }))).toBeVisible();
    if (await linked.isVisible()) return linked;
  }
  throw new Error("no visible recording row");
}

async function runWidth(browser, width) {
  const row = { width, steps: {}, pageErrors: 0, selectionContinuous: false };
  let viewer;
  let ctx;
  let phase = "list";
  try {
    viewer = await startViewer();
    ctx = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await ctx.newPage();
    page.setDefaultTimeout(10000);
    page.on("pageerror", () => { row.pageErrors += 1; });
    await page.goto(viewer.ready.url, { waitUntil: "domcontentloaded", timeout: 30000 });
    const catalog = page.locator("#recordings-panel");
    await expect(catalog.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
    await expect(catalog.locator("button.endpoint-card:visible").first()
      .or(catalog.getByText("No observed endpoints", { exact: true }))).toBeVisible();
    await capture(page, row, "list");

    phase = "recordings";
    const recording = await findRecording(catalog);
    await expect(recording).toBeVisible();
    const id = (await recording.locator(".recording-title").innerText()).trim();
    if (!id) throw new Error("recording identity unavailable");
    await capture(page, row, "recordings");

    phase = "linear";
    const detailPath = `/api/v1/recordings/${encodeURIComponent(id)}`;
    const [response] = await Promise.all([
      page.waitForResponse((res) => {
        const url = new URL(res.url());
        return url.origin === viewer.ready.origin && url.pathname === detailPath && res.request().method() === "GET";
      }, { timeout: 10000 }),
      recording.click(),
    ]);
    if (!response.ok()) throw new Error("recording read failed");
    const detail = await response.json();
    if (detail.recordingId !== id || !Array.isArray(detail.events)) throw new Error("recording read identity mismatch");
    const replay = page.locator("#events-panel");
    const selectedTab = page.getByRole("tablist", { name: "Open recordings" }).getByRole("tab", { selected: true });
    const checkRecording = async () => {
      await expect(replay.getByRole("heading", { name: id, exact: true })).toBeVisible();
      await expect(selectedTab).toBeVisible();
      await expect(selectedTab).toHaveAttribute("id", `open-recording-${id}`);
    };
    await checkRecording();
    const mode = replay.getByRole("group", { name: "Replay view" });
    const steps = mode.getByRole("button", { name: "Steps", exact: true });
    const map = mode.getByRole("button", { name: "Map", exact: true });
    await expect(steps).toHaveAttribute("aria-pressed", "true");
    // The Map groups adjacent sibling leaves. Choose a recorded parent so
    // its visible tree row must use this exact frame ID as its key.
    const parentIds = new Set(detail.events.filter((event) => event.frameId !== event.parentFrameId)
      .map((event) => event.frameId ? event.parentFrameId : null));
    const chosen = detail.events.find((event) => typeof event.frameId === "string" && event.frameId
      && parentIds.has(event.frameId) && /^(?:recording_event_kind:)?frame_enter$/.test(event.kind));
    const sequence = chosen?.sequence;
    if (typeof sequence !== "string" || !/^\d+$/.test(sequence)) throw new Error("recorded parent frame unavailable");
    const frame = replay.locator(".event").filter({ has: page.locator(".event-seq").filter({ hasText: new RegExp(`^\\s*${sequence}\\s*$`) }) });
    await expect(frame).toBeVisible();
    const currentStep = replay.locator('.event[aria-current="true"] .event-seq');
    const checkSequence = async () => {
      await checkRecording();
      await expect(replay.getByLabel("Recording summary").getByText(new RegExp(`^Event sequence ${sequence}(?: · |$)`))).toBeVisible();
    };
    await frame.click();
    // Selecting a step opens the inspector on phone layouts. Its back control
    // names the selected event and returns to the replay without a new selection.
    if (await page.locator("#events-tab").isVisible()) {
      await page.getByRole("button", { name: `Back to event ${sequence}`, exact: true }).click();
    }
    await expect(currentStep).toHaveText(sequence);
    await checkSequence();
    await capture(page, row, "linear");

    phase = "canvas";
    if (!(await map.count())) {
      row.steps.canvas = { status: "not-implemented" };
      return row;
    }
    await map.click();
    await expect(map).toHaveAttribute("aria-pressed", "true");
    const selectedFrame = replay.getByRole("tree").locator('[role="treeitem"][aria-selected="true"][data-kind="frame"]');
    await expect(selectedFrame).toBeVisible();
    await expect(selectedFrame).toHaveAttribute("data-key", chosen.frameId);
    await expect(replay.locator('svg .canvas-node[data-kind="frame"][data-selected="true"]')).toBeVisible();
    await checkSequence();
    await capture(page, row, "canvas");

    phase = "returnToSteps";
    await steps.click();
    await expect(steps).toHaveAttribute("aria-pressed", "true");
    await expect(currentStep).toHaveText(sequence);
    await checkSequence();
    await capture(page, row, "returnToSteps");
    row.selectionContinuous = true;
  } catch {
    row.steps[phase] = { status: "fail" };
  } finally {
    if (viewer) {
      try { await stopViewer(viewer.p); } catch { row.steps.cleanup = { status: "fail" }; }
    }
    if (ctx) {
      try { await ctx.close(); } catch { row.steps.cleanup = { status: "fail" }; }
    }
  }
  return row;
}

const report = { schemaVersion: 2, kind: "browser_journeys", sourceSha, packageSha256, widths: [] };
let browser;
try {
  browser = await chromium.launch();
  for (const width of widths) report.widths.push(await runWidth(browser, width));
} catch {
  console.error("browser launch or execution failed");
} finally {
  if (browser) {
    try { await browser.close(); } catch { report.browserCloseFailed = true; }
  }
}
function roll(name) {
  if (report.widths.length !== widths.length) return "fail";
  const statuses = report.widths.map((row) => row.steps[name]?.status);
  return statuses.every((status) => status === "pass") ? "pass"
    : statuses.every((status) => status === "not-implemented") ? "not-implemented" : "fail";
}
report.linear = roll("linear");
report.canvas = roll("canvas");
report.overflowAt = report.widths.filter((row) => Object.values(row.steps).some((step) => step.horizontalOverflow)).map((row) => row.width);
writeFileSync(path.join(out, "journeys.json"), JSON.stringify(report, null, 1) + "\n");
const complete = report.linear === "pass" && report.canvas === "pass" && !report.browserCloseFailed
  && report.widths.every((row) => row.selectionContinuous && row.pageErrors === 0
    && ["list", "recordings", "linear", "canvas", "returnToSteps"].every((step) => row.steps[step]?.status === "pass")
    && !row.steps.cleanup);
console.log(`browser journeys: ${complete ? "pass" : "fail"}; widths=[${report.widths.map((row) => row.width)}]`);
process.exitCode = complete ? 0 : 1;
