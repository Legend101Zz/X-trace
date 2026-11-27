// Automated Chromium demo video recorder for the v2 Simple viewer (Playwright from web/app/node_modules).
//   node tools/qa/record_demo.mjs --xtrace <bin> --project-dir <dir> --out <dir> [--pause-ms 1500]
// Launches `xtrace open --project-dir <dir> --viewer --no-browser`, records a 1280x800 Chromium video walking
// through Requests -> Steps (stepping through events with Code + Evidence inspector) -> Map (clicking a frame node)
// -> Export endpoints... preview sheet -> clean close, and writes keyframe PNGs + demo-report.json.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => (a.startsWith("--") ? [...acc, [a.slice(2), arr[i + 1]]] : acc), []),
);
for (const k of ["xtrace", "project-dir", "out"]) {
  if (!args[k]) {
    console.error(`missing --${k}`);
    process.exit(2);
  }
}
const pauseMs = Number(args["pause-ms"] || 1500);
const out = path.resolve(args.out);
mkdirSync(out, { recursive: true });
const require = createRequire(path.resolve("web/app/package.json"));
const { chromium } = require("@playwright/test");

function findReady(obj) {
  if (obj && typeof obj === "object") {
    if (typeof obj.url === "string" && typeof obj.origin === "string") return obj;
    for (const v of Object.values(obj)) {
      const r = findReady(v);
      if (r) return r;
    }
  }
  return null;
}

function startViewer() {
  return new Promise((resolve, reject) => {
    const p = spawn(args.xtrace, ["open", "--project-dir", args["project-dir"], "--viewer", "--no-browser"], {
      stdio: ["ignore", "pipe", "ignore"],
      detached: true,
    });
    let buf = "";
    const t = setTimeout(() => {
      stopViewer(p);
      reject(new Error("viewer readiness timeout"));
    }, 60000);
    p.stdout.on("data", (d) => {
      buf += d.toString();
      for (const line of buf.split("\n")) {
        try {
          const r = findReady(JSON.parse(line));
          if (r) {
            clearTimeout(t);
            resolve({ p, ready: r });
            return;
          }
        } catch {
          /* partial line */
        }
      }
    });
    p.on("exit", (c) => {
      clearTimeout(t);
      reject(new Error(`viewer exited ${c}`));
    });
  });
}

// Signals only the process group this script started.
function stopViewer(p) {
  try {
    process.kill(-p.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
}

async function settle(page, ms = pauseMs) {
  await page.waitForTimeout(ms);
}

async function hoverAndClick(page, locator, hoverMs = 500, afterMs = pauseMs) {
  await locator.scrollIntoViewIfNeeded().catch(() => {});
  await locator.hover({ timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(hoverMs);
  await locator.click({ timeout: 10000 });
  await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(afterMs);
}

const report = {
  schemaVersion: 1,
  kind: "demo_video",
  viewport: { width: 1280, height: 800 },
  steps: {},
  screenshots: [],
  videoPath: null,
  videoFile: null,
  pageErrors: [],
  durationMs: 0,
};

const t0 = Date.now();
const browser = await chromium.launch();
let videoPath = null;
try {
  const { p, ready } = await startViewer();
  try {
    const ctx = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      recordVideo: { dir: out, size: { width: 1280, height: 800 } },
    });
    const page = await ctx.newPage();
    const video = page.video();
    page.on("pageerror", (e) => report.pageErrors.push(String(e).slice(0, 160)));

    // 1. Open viewer and browse Requests (Endpoints / Not linked to an endpoint)
    await page.goto(ready.url, { waitUntil: "domcontentloaded", timeout: 30000 });
    await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
    await settle(page, Math.round(pauseMs * 1.1));

    const requestsTab = page.locator("#recordings-tab");
    if ((await page.locator("#recordings-panel").getAttribute("data-active").catch(() => null)) !== "true" && (await requestsTab.isVisible().catch(() => false))) {
      await hoverAndClick(page, requestsTab, 400, 800);
    }

    const endpointCards = page.locator("#recordings-panel button.endpoint-card");
    const cardCount = await endpointCards.count();
    let rowLoc = page.locator("#recordings-panel .recording-list button.recording").first();
    let openedFromEndpoint = false;

    if (cardCount > 0) {
      // Hover first card briefly, then select a rich Petclinic recording (/owners/new or /owners/{ownerId}) if present.
      await endpointCards.first().hover({ timeout: 5000 }).catch(() => {});
      await settle(page, 600);
      const preferred = page
        .locator("#recordings-panel button.endpoint-card")
        .filter({ hasText: /\/owners\/new|\/owners\/\{ownerId\}/i })
        .first();
      const targetCard = (await preferred.count()) ? preferred : endpointCards.first();
      await hoverAndClick(page, targetCard, 600, 1000);
      await rowLoc.waitFor({ state: "visible", timeout: 10000 }).catch(() => {});
      openedFromEndpoint = (await rowLoc.count()) > 0;
    }

    if (!openedFromEndpoint) {
      const unmatchedBtn = page
        .locator("#recordings-panel")
        .getByRole("button", { name: /not linked to an endpoint|unmatched recordings/i })
        .or(page.locator("#recordings-panel").getByRole("tab", { name: /not linked to an endpoint|unmatched recordings/i }))
        .first();
      if (await unmatchedBtn.count()) {
        await hoverAndClick(page, unmatchedBtn, 500, 900);
        await rowLoc.waitFor({ state: "visible", timeout: 10000 }).catch(() => {});
      }
    }

    if (await rowLoc.count()) {
      await hoverAndClick(page, rowLoc, 600, pauseMs);
      report.steps.requests = { status: "pass", openedFromEndpoint };
    } else {
      report.steps.requests = { status: "fail", reason: "no recording row found" };
    }

    // 2. Steps (Linear) view: step through 4-5 events so Code + Evidence inspector (Values, Details) update
    const stepsTab = page.locator("#replay-view-steps-tab");
    if (await stepsTab.count()) {
      const selected = await stepsTab.getAttribute("aria-selected").catch(() => null);
      if (selected !== "true") {
        await hoverAndClick(page, stepsTab, 400, 800);
      }
    }
    await page.locator("#events-panel .event-rail .event").first().waitFor({ state: "visible", timeout: 10000 }).catch(() => {});

    const nextBtn = page.locator("#events-panel .replay-toolbar").getByRole("button", { name: /^Next$/ }).first();
    let stepped = 0;
    for (let i = 0; i < 4; i++) {
      if (await nextBtn.count()) {
        const disabled = await nextBtn.getAttribute("aria-disabled").catch(() => null);
        if (disabled === "true") break;
        await hoverAndClick(page, nextBtn, 400, Math.round(pauseMs * 0.85));
        stepped += 1;
      }
    }
    // Also click a frame_enter event row directly if present to highlight Code source line.
    const frameRows = page.locator('#events-panel .event-rail .event[data-event-kind*="frame_enter"]');
    const frameCount = await frameRows.count();
    if (frameCount > 0) {
      const pickIdx = Math.min(1, frameCount - 1);
      await hoverAndClick(page, frameRows.nth(pickIdx), 400, Math.round(pauseMs * 0.9));
      stepped += 1;
    }

    // Inspect Details and Values tabs in Evidence inspector
    const detailsTab = page.locator("#evidence-panel").getByRole("tab", { name: /^Details$/i }).first();
    const valuesTab = page.locator("#evidence-panel").getByRole("tab", { name: /^Values/i }).first();
    if (await detailsTab.count()) {
      await hoverAndClick(page, detailsTab, 400, Math.round(pauseMs * 0.9));
    }
    if (await valuesTab.count()) {
      await hoverAndClick(page, valuesTab, 400, Math.round(pauseMs * 0.9));
    }
    await page.screenshot({ path: path.join(out, "demo-steps.png") });
    report.screenshots.push("demo-steps.png");
    report.steps.linear = { status: stepped > 0 ? "pass" : "fail", steppedEvents: stepped, screenshot: "demo-steps.png" };

    // 3. Switch to Map (Canvas) view and click a frame node in SVG/tree
    const mapTab = page
      .locator("#replay-view-map-tab")
      .or(page.getByRole("tab", { name: /^(map|canvas)$/i }))
      .first();
    if (await mapTab.count()) {
      await hoverAndClick(page, mapTab, 500, pauseMs);
      await page
        .locator(".canvas-view svg .canvas-node, .canvas-view [role=tree] [role=treeitem]")
        .first()
        .waitFor({ state: "visible", timeout: 10000 })
        .catch(() => {});
      const svgNodes = page.locator(".canvas-view svg .canvas-node");
      const treeItems = page.locator(".canvas-view [role=tree] [role=treeitem]");
      if ((await svgNodes.count()) > 0) {
        const idx = (await svgNodes.count()) > 1 ? 1 : 0;
        await hoverAndClick(page, svgNodes.nth(idx), 500, pauseMs);
        report.steps.map = { status: "pass", clicked: "svg-node", screenshot: "demo-map.png" };
      } else if ((await treeItems.count()) > 0) {
        const idx = (await treeItems.count()) > 1 ? 1 : 0;
        await hoverAndClick(page, treeItems.nth(idx), 500, pauseMs);
        report.steps.map = { status: "pass", clicked: "tree-item", screenshot: "demo-map.png" };
      } else {
        report.steps.map = { status: "fail", reason: "no frame node rendered in Map view", screenshot: "demo-map.png" };
      }
      await page.screenshot({ path: path.join(out, "demo-map.png") });
      report.screenshots.push("demo-map.png");
    } else {
      report.steps.map = { status: "fail", reason: "Map tab not found" };
    }

    // 4. Open `Export endpoints…` preview sheet (showing OpenAPI / Postman / cURL / Bundle choices without sending requests)
    let exportBtn = page.locator("#recordings-panel").getByRole("button", { name: /export endpoints/i }).first();
    if (!(await exportBtn.count())) {
      const backToEndpoints = page.locator("#recordings-panel").getByRole("button", { name: /observed endpoints/i }).first();
      if (await backToEndpoints.count()) {
        await hoverAndClick(page, backToEndpoints, 400, 800);
      }
      exportBtn = page.locator("#recordings-panel").getByRole("button", { name: /export endpoints/i }).first();
    }
    if (await exportBtn.count()) {
      await hoverAndClick(page, exportBtn, 500, Math.round(pauseMs * 0.9));
      const dialog = page.getByRole("dialog");
      await dialog.waitFor({ state: "visible", timeout: 10000 });
      for (const fmt of [/Postman Collection/i, /cURL recipes/i, /Developer bundle/i, /OpenAPI 3\.1/i]) {
        const btn = dialog.getByRole("button", { name: fmt }).first();
        if (await btn.count()) {
          await hoverAndClick(page, btn, 350, 550);
        }
      }
      await settle(page, 800);
      await page.screenshot({ path: path.join(out, "demo-export.png") });
      report.screenshots.push("demo-export.png");
      const closeBtn = dialog.getByRole("button", { name: /^Close$/i }).first();
      if (await closeBtn.count()) {
        await hoverAndClick(page, closeBtn, 400, 900);
      } else {
        await page.keyboard.press("Escape");
        await settle(page, 900);
      }
      report.steps.exportSheet = { status: "pass", screenshot: "demo-export.png" };
    } else {
      report.steps.exportSheet = { status: "fail", reason: "Export endpoints button not found" };
    }

    await ctx.close();
    videoPath = video ? await video.path() : null;
  } finally {
    stopViewer(p);
  }
} finally {
  await browser.close();
}

report.videoPath = videoPath;
report.videoFile = videoPath ? path.basename(videoPath) : null;
report.durationMs = Date.now() - t0;
writeFileSync(path.join(out, "demo-report.json"), JSON.stringify(report, null, 2) + "\n");
console.log(`demo recorded: durationMs=${report.durationMs} video=${report.videoFile} screenshots=${report.screenshots.join(",")}`);
const failed = Object.values(report.steps).some((s) => s.status !== "pass") || !report.videoPath || report.pageErrors.length > 0;
process.exit(failed ? 1 : 0);
