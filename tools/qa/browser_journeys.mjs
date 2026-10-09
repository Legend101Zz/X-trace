// Browser journeys against the packaged viewer (Playwright from web/app/node_modules).
//   node tools/qa/browser_journeys.mjs --xtrace <bin> --project-dir <dir> --out <dir> [--widths 320,736,1280]
// For each width a fresh viewer is started (the bootstrap token is single-use), the recording list is screenshotted, the
// first recording is opened (Linear view) and screenshotted; a Canvas view is attempted only if the UI offers one.
// Everything that cannot be reached is recorded as failed or not-implemented with a reason; nothing is skipped silently.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
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
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(out, `list-${w}.png`), fullPage: true });
      row.steps.list = { status: "pass", screenshot: `list-${w}.png` };
      // The recordings list lives under the "Unmatched recordings" tab (or under an observed endpoint when one is linked).
      const tab = page.getByRole("button", { name: /unmatched recordings/i }).or(page.getByRole("tab", { name: /unmatched recordings/i })).first();
      if (await tab.count()) { await tab.click({ timeout: 10000 }); await page.waitForTimeout(1500); }
      await page.screenshot({ path: path.join(out, `recordings-${w}.png`), fullPage: true });
      const skip = /^(refresh|observed endpoints|unmatched recordings|load more|previous|next)$/i;
      const buttons = await page.getByRole("button").all();
      let rowLoc = null;
      for (const b of buttons) {
        const name = ((await b.innerText().catch(() => "")) || "").trim();
        if (name && !skip.test(name.split("\n")[0].trim())) { rowLoc = b; break; }
      }
      if (rowLoc) {
        await rowLoc.click({ timeout: 10000 });
        await page.waitForTimeout(2000);
        await page.screenshot({ path: path.join(out, `linear-${w}.png`), fullPage: true });
        const linearShown = await page.getByText(/http\.request|frame_enter|frame enter/i).first().count();
        row.steps.linear = linearShown
          ? { status: "pass", screenshot: `linear-${w}.png` }
          : { status: "fail", reason: "a recording was opened but the Linear event window shows no request or frame event", screenshot: `linear-${w}.png` };
      } else {
        row.steps.linear = { status: "fail", reason: "no recording row found in the recordings list" };
      }
      const canvas = page.getByRole("tab", { name: /canvas/i }).or(page.getByRole("button", { name: /canvas/i })).first();
      if (await canvas.count()) {
        await canvas.click({ timeout: 10000 });
        await page.waitForTimeout(1500);
        await page.screenshot({ path: path.join(out, `canvas-${w}.png`), fullPage: true });
        const drawn = await page.getByText(/http\.request/i).first().count();
        row.steps.canvas = drawn ? { status: "pass", screenshot: `canvas-${w}.png` }
          : { status: "fail", reason: "Canvas opened but shows no request or frame node", screenshot: `canvas-${w}.png` };
      } else {
        row.steps.canvas = { status: "not-implemented", reason: "the viewer offers no Canvas control" };
      }
      row.horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
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
