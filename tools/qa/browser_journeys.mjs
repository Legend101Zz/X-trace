// Browser journeys against the packaged viewer (Playwright from web/app/node_modules).
//   node tools/qa/browser_journeys.mjs --xtrace <bin> --project-dir <dir> --out <dir> [--widths 320,736,1280]
// For each width a fresh viewer is started (the bootstrap token is single-use), the recording list is screenshotted, the
// first recording is opened (Linear view) and screenshotted; a Canvas view is attempted only if the UI offers one.
// Everything that cannot be reached is recorded as failed or not-implemented with a reason; nothing is skipped silently.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
const domDir = () => { const d = path.join(path.resolve(args.out), "dom"); mkdirSync(d, { recursive: true }); return d; };
// visible text of every step is written here so the privacy scan can cover the DOM (class browser-dom)
const dumpDom = async (page, name) => { try { writeFileSync(path.join(domDir(), `${name}.txt`), await page.evaluate(() => document.body.innerText)); } catch { /* page gone */ } };
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
import path from "node:path";

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => (a.startsWith("--") ? [...acc, [a.slice(2), arr[i + 1]]] : acc), []));
for (const k of ["xtrace", "project-dir", "out"]) if (!args[k]) { console.error(`missing --${k}`); process.exit(2); }
const widths = (args.widths || "320,736,1280").split(",").map(Number);
const out = path.resolve(args.out);
mkdirSync(out, { recursive: true });
const require = createRequire(path.resolve("web/app/package.json"));
const { chromium } = require("@playwright/test");

function findReady(obj) {
  if (obj && typeof obj === "object") {
    if (typeof obj.url === "string" && typeof obj.origin === "string") return obj;
    for (const v of Object.values(obj)) { const r = findReady(v); if (r) return r; }
  }
  return null;
}

function startViewer() {
  return new Promise((resolve, reject) => {
    const p = spawn(args.xtrace, ["open", "--project-dir", args["project-dir"], "--viewer", "--no-browser"], { stdio: ["ignore", "pipe", "ignore"], detached: true });
    let buf = "";
    const t = setTimeout(() => { stopViewer(p); reject(new Error("viewer readiness timeout")); }, 60000);
    p.stdout.on("data", (d) => {
      buf += d.toString();
      for (const line of buf.split("\n")) {
        try { const r = findReady(JSON.parse(line)); if (r) { clearTimeout(t); resolve({ p, ready: r }); return; } } catch { /* partial line */ }
      }
    });
    p.on("exit", (c) => { clearTimeout(t); reject(new Error(`viewer exited ${c}`)); });
  });
}

// Signals only the process group this script started.
function stopViewer(p) { try { process.kill(-p.pid, "SIGTERM"); } catch { /* already gone */ } }

const report = { schemaVersion: 1, kind: "browser_journeys", widths: [], linear: "unknown", canvas: "unknown" };
const browser = await chromium.launch();
try {
  for (const w of widths) {
    const row = { width: w, steps: {} };
    const { p, ready } = await startViewer();
    try {
      const ctx = await browser.newContext({ viewport: { width: w, height: 900 } });
      const page = await ctx.newPage();
      const consoleErrors = [];
      page.on("pageerror", (e) => consoleErrors.push(String(e).slice(0, 120)));
      await page.goto(ready.url, { waitUntil: "domcontentloaded", timeout: 30000 });
      await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
      await dumpDom(page, `list-${w}`);
      await page.screenshot({ path: path.join(out, `list-${w}.png`), fullPage: true });
      row.steps.list = { status: "pass", screenshot: `list-${w}.png` };
      // Ensure the Requests pane is visible (narrow viewports start on Requests, but guard defensively).
      const requestsTab = page.locator("#recordings-tab");
      if ((await page.locator("#recordings-panel").getAttribute("data-active").catch(() => null)) !== "true" && (await requestsTab.isVisible().catch(() => false))) {
        await requestsTab.click({ timeout: 10000 });
      }
      // Prefer a linked recording under an observed endpoint when present; otherwise open "Not linked to an endpoint" (or legacy "Unmatched recordings").
      let rowLoc = page.locator("#recordings-panel .recording-list button.recording").first();
      if (!(await rowLoc.count())) {
        const endpointCard = page.locator("#recordings-panel button.endpoint-card").first();
        if (await endpointCard.count()) {
          await endpointCard.click({ timeout: 10000 });
          await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
          await rowLoc.waitFor({ state: "visible", timeout: 5000 }).catch(() => {});
        }
      }
      if (!(await rowLoc.count())) {
        const unmatchedBtn = page
          .locator("#recordings-panel")
          .getByRole("button", { name: /not linked to an endpoint|unmatched recordings/i })
          .or(page.locator("#recordings-panel").getByRole("tab", { name: /not linked to an endpoint|unmatched recordings/i }))
          .first();
        if (await unmatchedBtn.count()) {
          await unmatchedBtn.click({ timeout: 10000 });
          await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
          await rowLoc.waitFor({ state: "visible", timeout: 10000 }).catch(() => {});
        }
      }
      await dumpDom(page, `recordings-${w}`);
      await page.screenshot({ path: path.join(out, `recordings-${w}.png`), fullPage: true });
      if (await rowLoc.count()) {
        await rowLoc.click({ timeout: 10000 });
        await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
        const eventsTab = page.locator("#events-tab");
        if ((await page.locator("#events-panel").getAttribute("data-active").catch(() => null)) !== "true" && (await eventsTab.isVisible().catch(() => false))) {
          await eventsTab.click({ timeout: 10000 });
        }
        await page.locator("#events-panel .event-rail .event").first().waitFor({ state: "visible", timeout: 10000 }).catch(() => {});
        await page.waitForTimeout(300);
        await dumpDom(page, `linear-${w}`);
        await page.screenshot({ path: path.join(out, `linear-${w}.png`), fullPage: true });
        row.linearOverflow = await overflow(page);
        // Linear (Steps): an ordered event row inside #events-panel .event-rail carrying a real event kind.
        const linearShown = await page.locator("#events-panel .event-rail .event[data-event-kind]").evaluateAll((els) =>
          els.some((el) => /request|frame|line|interaction/i.test(el.getAttribute("data-event-kind") || "") && (el.textContent || "").trim().length > 0),
        );
        row.steps.linear = linearShown
          ? { status: "pass", screenshot: `linear-${w}.png` }
          : { status: "fail", reason: "a recording was opened but the Linear (Steps) event window shows no request or frame event", screenshot: `linear-${w}.png` };
      } else {
        row.steps.linear = { status: "fail", reason: "no recording row found in the recordings list" };
      }
      const canvas = page
        .locator("#replay-view-map-tab")
        .or(page.getByRole("tab", { name: /^(map|canvas)$/i }))
        .or(page.getByRole("button", { name: /^(map|canvas)$/i }))
        .first();
      if (await canvas.count()) {
        await canvas.click({ timeout: 10000 });
        await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
        await page.locator(".canvas-view .canvas-node, .canvas-view [role=tree] [role=treeitem]").first().waitFor({ state: "visible", timeout: 10000 }).catch(() => {});
        await page.waitForTimeout(300);
        await dumpDom(page, `canvas-${w}`);
        await page.screenshot({ path: path.join(out, `canvas-${w}.png`), fullPage: true });
        row.canvasOverflow = await overflow(page);
        const drawn = await page.locator(".canvas-view .canvas-node, .canvas-view [role=tree] [role=treeitem], svg .canvas-node").count();
        row.steps.canvas = drawn ? { status: "pass", screenshot: `canvas-${w}.png` }
          : { status: "fail", reason: "Canvas (Map) opened but shows no request or frame node", screenshot: `canvas-${w}.png` };
      } else {
        row.steps.canvas = { status: "not-implemented", reason: "the viewer offers no Canvas/Map control" };
      }
      row.horizontalOverflow = Boolean(row.linearOverflow || row.canvasOverflow || await overflow(page));
      row.pageErrors = consoleErrors.length;
      await ctx.close();
    } catch (e) {
      row.steps.error = { status: "fail", reason: String(e).slice(0, 200) };
    } finally { stopViewer(p); }
    report.widths.push(row);
  }
} finally { await browser.close(); }
const all = (k) => report.widths.map((r) => r.steps[k]?.status ?? "fail");
const roll = (k) => (all(k).every((s) => s === "pass") ? "pass" : all(k).every((s) => s === "not-implemented") ? "not-implemented" : "fail");
report.linear = roll("linear");
report.canvas = roll("canvas");
report.overflowAt = report.widths.filter((r) => r.horizontalOverflow).map((r) => r.width);
writeFileSync(path.join(out, "journeys.json"), JSON.stringify(report, null, 1));
console.log(`browser journeys: linear=${report.linear} canvas=${report.canvas} overflowAt=[${report.overflowAt}]`);
process.exit(report.linear === "pass" && report.overflowAt.length === 0 ? 0 : 1);
