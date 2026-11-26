import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { verifyLoadedReplayTools } from './scripts/replay-tools-journey.mjs';
import { createReplayToolsReport } from './scripts/replay-tools-report.mjs';
import { verifyReplayPlayback } from './scripts/replay-playback-journey.mjs';

const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { pointer, origin, url, recordingId, sequences, otherRecordingId, otherSequences, shots, result, jumpReceipt, sourceSha, receiptId } = input;
assert.ok(['fine', 'coarse'].includes(pointer));
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
const bootstrap = new URL(url);
assert.equal(bootstrap.origin, origin);
assert.match(bootstrap.hash, /^#token=[a-zA-Z0-9_-]{43}$/);
const token = bootstrap.hash.slice(7);
const viewports = new Map([[320, 640], [736, 900], [1024, 768], [1280, 900], [1440, 900]]);
const existing = new Set(['filter', 'goto', 'jump', 'tools', 'playback', 'speed']);
const seen = new Set();
const refreshedWidths = new Set();
const densityWidths = [];
assert.notEqual(otherRecordingId, recordingId);
const jumpReport = createReplayToolsReport({ path: jumpReceipt, sourceSha, receiptId });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ serviceWorkers: 'block', hasTouch: pointer === 'coarse', viewport: { width: 1280, height: 900 } });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || request.url().includes(token)
      || request.headers().referer?.includes(token)) return route.abort();
    return route.continue();
  });
  const { pathToFileURL } = await import('node:url');
  const { guardViewerWrites } = await import(pathToFileURL(process.env.PROOF_SCRIPTS + '/viewer-traffic.mjs').href);
  await guardViewerWrites(context, origin);
  const page = await context.newPage();
  await page.clock.install();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  let authExchanges = 0;
  let browserErrors = 0;
  let prohibitedRequests = 0;
  let observePhoneKeyboard = false;
  const phoneKeyboardReads = [];
  page.on('request', (request) => {
    const target = new URL(request.url());
    if (target.origin !== origin || request.url().includes(token) || request.headers().referer?.includes(token)) prohibitedRequests++;
    if (target.pathname === '/api/v1/auth/exchange') authExchanges++;
    // The pinned source helper performs the two keyboard switches immediately
    // after the ordinary pointer callback. It separately judges each exact reply.
    if (observePhoneKeyboard && page.viewportSize().width === 320 && request.method() === 'GET'
      && [recordingId, otherRecordingId].some(id => target.pathname === `/api/v1/recordings/${id}`)) {
      phoneKeyboardReads.push(target.pathname);
      if (phoneKeyboardReads.length === 2) observePhoneKeyboard = false;
    }
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
  let tabletSwitches = 0;
  const verifyRecordingSelection = async ({ sequence }) => {
    const tabs = page.getByRole('tablist', { name: 'Open recordings' });
    const otherTab = tabs.getByRole('tab', { name: new RegExp(otherRecordingId) });
    let otherControl = otherTab;
    if (await otherTab.count() === 0) {
      const requests = page.getByRole('tab', { name: 'Requests', exact: true });
      const header = page.locator('#header-requests');
      if (await requests.isVisible()) await activate(requests);
      else if (await header.isVisible() && await header.getAttribute('aria-expanded') === 'false') await activate(header);
      await expect(page.locator('#recordings-panel')).toBeVisible();
      otherControl = page.getByRole('button', { name: new RegExp(otherRecordingId) });
    }
    const [otherReply] = await Promise.all([
      page.waitForResponse(response => response.request().method() === 'GET'
        && new URL(response.url()).pathname === `/api/v1/recordings/${otherRecordingId}`),
      activate(otherControl),
    ]);
    assert.equal(otherReply.status(), 200);
    const otherDetail = await otherReply.json();
    assert.equal(otherDetail.recordingId, otherRecordingId);
    assert.equal(otherDetail.completion, 'complete');
    assert.equal(otherDetail.outcome?.kind, 'responded');
    assert.equal(otherDetail.outcome?.httpStatus, 201);
    assert.equal(otherDetail.nextCursor, null);
    assert.deepEqual(otherDetail.events.map(event => event.sequence), otherSequences);
    await expect(otherTab).toHaveAttribute('aria-selected', 'true');
    const steps = page.locator('#events-panel');
    const selected = steps.locator('.event[aria-current="true"] .event-seq');
    const identity = steps.locator('.center-title h1');
    await expect(identity).toHaveText(otherRecordingId);
    await expect(selected).toHaveText(otherSequences[0]);
    const original = tabs.getByRole('tab', { name: new RegExp(recordingId) });
    const [originalReply] = await Promise.all([
      page.waitForResponse(response => response.request().method() === 'GET'
        && new URL(response.url()).pathname === `/api/v1/recordings/${recordingId}`),
      activate(original),
    ]);
    assert.equal(originalReply.status(), 200);
    const originalDetail = await originalReply.json();
    assert.equal(originalDetail.recordingId, recordingId);
    assert.equal(originalDetail.completion, 'complete');
    assert.equal(originalDetail.outcome?.kind, 'responded');
    assert.equal(originalDetail.outcome?.httpStatus, 201);
    assert.equal(originalDetail.nextCursor, null);
    assert.deepEqual(originalDetail.events.map(event => event.sequence), sequences);
    assert.notDeepEqual(otherDetail.events, originalDetail.events,
      'the two genuine Spring recordings supply distinct exact event projections');
    await expect(original).toHaveAttribute('aria-selected', 'true');
    await expect(identity).toHaveText(recordingId);
    await expect(selected).toHaveText(sequence);
    const refresh = steps.getByRole('button', { name: 'Refresh', exact: true });
    const width = page.viewportSize().width;
    if (width === 736) {
      const modes = steps.getByRole('tablist', { name: 'Replay view' });
      const linear = modes.getByRole('tab', { name: 'Steps', exact: true });
      const map = modes.getByRole('tab', { name: 'Map', exact: true });
      await expect(linear).toHaveAttribute('aria-selected', 'true');
      await linear.press('ArrowRight');
      await expect(map).toBeFocused();
      await expect(map).toHaveAttribute('aria-selected', 'true');
      await expect(steps.getByRole('tabpanel', { name: 'Map', exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: 'Recording summary' })).toContainText(`Event sequence ${sequence}`);
      await map.press('ArrowLeft');
      await expect(linear).toBeFocused();
      await expect(linear).toHaveAttribute('aria-selected', 'true');
      await expect(steps.getByRole('tabpanel', { name: 'Steps', exact: true })).toBeVisible();
      await expect(selected).toHaveText(sequence);
      tabletSwitches++;
    }
    if (width < 700) {
      await original.focus();
      await expect(original).toBeFocused();
      await refresh.scrollIntoViewIfNeeded();
      const before = await refresh.boundingBox();
      await refresh.evaluate((button) => button.focus({ preventScroll: true }));
      await expect(refresh).toBeFocused();
      const after = await refresh.boundingBox();
      assert.ok(before && after && before.x === after.x && before.y === after.y);
      await original.focus();
    }
    let realRequest;
    const [, reply] = await Promise.all([
      page.waitForRequest((request) => {
        if (request.method() !== 'GET' || new URL(request.url()).pathname !== `/api/v1/recordings/${recordingId}`) return false;
        realRequest = request;
        return true;
      }),
      page.waitForResponse((response) => response.request() === realRequest),
      activate(refresh),
    ]);
    assert.deepEqual([...new URL(realRequest.url()).searchParams], [['limit', '200']]);
    assert.equal(reply.status(), 200);
    const detail = await reply.json();
    assert.equal(detail.recordingId, recordingId);
    assert.deepEqual(detail.events.map((event) => event.sequence), sequences);
    assert.deepEqual(detail.events, originalDetail.events, 'Refresh retains the exact original projection');
    await expect(steps.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('region', { name: 'Loaded event window' }).getByText('Loading event window…', { exact: true })).not.toBeVisible();
    await expect(refresh).toBeEnabled();
    await expect(selected).toHaveText(sequence);
    assert.ok(!refreshedWidths.has(width));
    refreshedWidths.add(width);
    if (width === 320) {
      assert.equal(phoneKeyboardReads.length, 0);
      observePhoneKeyboard = true;
    }
  };
  const saveScreenshot = async (name, _label, width, height, target) => {
    const match = /^viewer-replay-(filter|goto|jump|tools|playback|speed|compact-tools-open|desktop-tools-inline)-(fine|coarse)-(320|736|1024|1280|1440)\.png$/.exec(name);
    const phone = /^viewer-phone-more-(fine|coarse)-320\.png$/.exec(name);
    assert.ok(match || phone);
    assert.deepEqual(target.viewportSize(), { width, height });
    assert.equal(viewports.get(width), height);
    if (phone) assert.ok(phone[1] === pointer && width === 320);
    else {
      assert.ok(match[2] === pointer && Number(match[3]) === width);
      const extra = ['compact-tools-open', 'desktop-tools-inline'].includes(match[1]);
      assert.ok(extra ? (match[1] === 'compact-tools-open' ? width < 1280 : width >= 1280) : existing.has(match[1]));
    }
    const extra = Boolean(phone) || ['compact-tools-open', 'desktop-tools-inline'].includes(match?.[1]);
    assert.ok(!seen.has(name));
    seen.add(name);
    // The pinned replay tools reach this frame after checking the selected tail,
    // Back and Alt+ArrowDown. Read the live installed selection at that point.
    if (match?.[1] === 'tools' && pointer === 'coarse' && (width === 1024 || width === 1280)) {
      assert.equal(await target.evaluate(() => matchMedia('(pointer: coarse)').matches), true);
      await expect(target.locator('.event[aria-current="true"] .event-seq')).toHaveText(sequences.at(-1));
      densityWidths.push(width);
    }
    const bytes = await target.screenshot();
    await writeFile(join(shots, extra ? 'compact-open' : 'existing', name.replace('.png', '-viewport.png')), bytes, { flag: 'wx', mode: 0o600 });
  };
  const assertBrowserHealth = () => {
    assert.equal(authExchanges, 1, 'reload resumes the existing authenticated browser session');
    assert.equal(prohibitedRequests, 0);
    assert.equal(browserErrors, 0);
  };
  try {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      const events = await openCapture();
      await verifyLoadedReplayTools(page, { events, pointer, saveScreenshot, jumpReport, verifyRecordingSelection });
      await verifyReplayPlayback(page, { events, pointer, openCapture, saveScreenshot });
      assertBrowserHealth();
      assert.equal(seen.size, 36, '30 original, 3 open compact, 2 inline desktop and 1 phone More frame');
      assert.deepEqual([...refreshedWidths], [...viewports.keys()]);
      assert.deepEqual(densityWidths, pointer === 'coarse' ? [1024, 1280] : []);
      assert.equal(tabletSwitches, 1);
      assert.equal(observePhoneKeyboard, false);
      assert.deepEqual(phoneKeyboardReads, [otherRecordingId, recordingId].map(id => `/api/v1/recordings/${id}`));
    } finally {
      await context.close();
    }
    assertBrowserHealth();
    await writeFile(result, JSON.stringify({ schema: 1, pointer, sourceSha, receiptId, existing: 30, compactOpen: 3, desktopInline: 2, phoneMore: 1, tabletSwitches, densityWidths, phoneKeyboardSwitches: phoneKeyboardReads.length, refreshedWidths: [...refreshedWidths] }) + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    jumpReport.fail();
    throw error;
  }
} finally {
  await browser.close();
}
