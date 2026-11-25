import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { verifyLoadedReplayTools } from './scripts/replay-tools-journey.mjs';
import { createReplayToolsReport } from './scripts/replay-tools-report.mjs';
import { verifyReplayPlayback } from './scripts/replay-playback-journey.mjs';

const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { pointer, origin, url, recordingId, sequences, shots, result, jumpReceipt, sourceSha, receiptId } = input;
assert.ok(['fine', 'coarse'].includes(pointer));
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
const bootstrap = new URL(url);
assert.equal(bootstrap.origin, origin);
assert.match(bootstrap.hash, /^#token=[a-zA-Z0-9_-]{43}$/);
const token = bootstrap.hash.slice(7);
const viewports = new Map([[320, 640], [736, 900], [1024, 768], [1280, 900], [1440, 900]]);
const existing = new Set(['filter', 'goto', 'jump', 'tools', 'playback', 'speed']);
const seen = new Set();
const jumpReport = createReplayToolsReport({ path: jumpReceipt, sourceSha, receiptId });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ hasTouch: pointer === 'coarse', viewport: { width: 1280, height: 900 } });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || request.url().includes(token)
      || request.headers().referer?.includes(token)) return route.abort();
    return route.continue();
  });
  const page = await context.newPage();
  await page.clock.install();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  let authExchanges = 0;
  let browserErrors = 0;
  let prohibitedRequests = 0;
  page.on('request', (request) => {
    const target = new URL(request.url());
    if (target.origin !== origin || request.url().includes(token) || request.headers().referer?.includes(token)) prohibitedRequests++;
    if (target.pathname === '/api/v1/auth/exchange') authExchanges++;
  });
  page.on('pageerror', () => { browserErrors++; });
  page.on('console', (message) => { if (message.type() === 'error') browserErrors++; });
  const activate = (control) => pointer === 'coarse' ? control.tap() : control.click();
  const openCapture = async () => {
    await expect(page.getByText('Local viewer connected', { exact: true })).toBeVisible();
    const endpoint = page.getByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ });
    await activate(endpoint);
    const [reply] = await Promise.all([
      page.waitForResponse((response) => response.request().method() === 'GET'
        && new URL(response.url()).pathname === `/api/v1/recordings/${recordingId}`),
      activate(page.getByRole('button', { name: new RegExp(recordingId) })),
    ]);
    assert.equal(reply.status(), 200);
    const detail = await reply.json();
    assert.equal(detail.recordingId, recordingId);
    assert.equal(detail.completion, 'complete');
    assert.equal(detail.outcome?.kind, 'responded');
    assert.equal(detail.outcome?.httpStatus, 201);
    assert.equal(detail.nextCursor, null);
    assert.deepEqual(detail.events.map(({ sequence }) => sequence), sequences);
    await expect(page.locator('#events-panel .event[aria-current="true"]')).toBeVisible();
    return detail.events;
  };
  const saveScreenshot = async (name, _label, width, height, target) => {
    const match = /^viewer-replay-(filter|goto|jump|tools|playback|speed)-(fine|coarse)-(320|736|1024|1280|1440)\.png$/.exec(name);
    assert.ok(match && match[2] === pointer && Number(match[3]) === width && viewports.get(width) === height);
    assert.deepEqual(target.viewportSize(), { width, height });
    assert.ok(existing.has(match[1]));
    assert.ok(!seen.has(name));
    seen.add(name);
    const bytes = await target.screenshot();
    await writeFile(join(shots, 'existing', name.replace('.png', '-viewport.png')), bytes, { flag: 'wx', mode: 0o600 });
  };
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    const events = await openCapture();
    await verifyLoadedReplayTools(page, { events, pointer, saveScreenshot, jumpReport });
    await verifyReplayPlayback(page, { events, pointer, openCapture, saveScreenshot });
    assert.equal(authExchanges, 1, 'reload resumes the existing authenticated browser session');
    assert.equal(prohibitedRequests, 0);
    assert.equal(browserErrors, 0);
    assert.equal(seen.size, 30, 'all original frames for this pointer');
    await writeFile(result, JSON.stringify({ schema: 1, pointer, sourceSha, receiptId, existing: 30 }) + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    jumpReport.fail();
    throw error;
  } finally {
    await context.close();
  }
} finally {
  await browser.close();
}
