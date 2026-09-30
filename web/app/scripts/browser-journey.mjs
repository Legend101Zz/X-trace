import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const [recordingId, encodedSequences] = process.argv.slice(2);
assert.ok(recordingId && encodedSequences, 'recording ID and expected event sequences are required');
const expectedSequences = JSON.parse(encodedSequences);
assert.ok(Array.isArray(expectedSequences) && expectedSequences.length > 0, 'expected events must be a non-empty array');
const input = await new Promise((resolve, reject) => {
  let value = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { value += chunk; });
  process.stdin.on('end', () => resolve(value));
  process.stdin.on('error', reject);
});
const { url: startUrl } = JSON.parse(input);
assert.ok(startUrl, 'viewer URL must be supplied through stdin');

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  const consoleErrors = [];
  const unexpectedRequests = [];
  const bootstrapToken = new URL(startUrl).hash.slice('#token='.length);
  page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', (error) => consoleErrors.push(error.message));
  page.on('request', (request) => {
    assert.ok(!request.url().includes(bootstrapToken), 'bootstrap token appeared in a request URL');
    if (new URL(request.url()).host !== new URL(startUrl).host) unexpectedRequests.push(request.url());
    const headers = request.headers();
    assert.ok(!headers.referer?.includes(bootstrapToken), 'bootstrap token appeared in a referrer');
  });

  try {
    await page.goto(startUrl, { waitUntil: 'domcontentloaded' });
  } catch {
    throw new Error(`viewer page failed to load at ${new URL(startUrl).origin}`);
  }
  const recordingButton = page.getByRole('button', { name: new RegExp(recordingId) });
  try {
    await recordingButton.click({ timeout: 5000 });
  } catch {
    throw new Error(JSON.stringify({ ui: await page.locator('body').innerText(), consoleErrors }));
  }
  await page.locator('.event-seq').first().waitFor();
  const observed = await page.locator('.event-seq').allTextContents();
  assert.deepEqual(observed, expectedSequences, 'browser event order differs from the product query projection');
  const statusMark = page.locator('.status-mark').first();
  assert.equal(await statusMark.evaluate((node) => node.classList.contains('recording')), false);
  assert.deepEqual(await statusMark.evaluate((node) => {
    const style = getComputedStyle(node);
    return { width: style.width, height: style.height };
  }), { width: '6px', height: '6px' });
  assert.deepEqual(await page.locator('.recording').first().locator('.recording-title, .recording-sub, .recording-status').evaluateAll((labels) => labels.map((label) => getComputedStyle(label).display)), ['block', 'block', 'block']);
  await page.getByText('Source unavailable for this capture').waitFor();
  await page.getByText('Values were not projected').waitFor();
  await page.getByText('Completion semantics unavailable').waitFor();
  const screenshotDirectory = process.env.XTRACE_BROWSER_SCREENSHOT_DIR;
  if (screenshotDirectory) {
    await mkdir(screenshotDirectory, { recursive: true });
    await page.screenshot({ path: join(screenshotDirectory, 'viewer-desktop.png'), fullPage: true });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  const tabHeights = await page.getByRole('tab').evaluateAll((tabs) => tabs.map((tab) => tab.getBoundingClientRect().height));
  assert.ok(tabHeights.every((height) => height >= 44), `mobile pane tabs must be at least 44px tall: ${tabHeights}`);
  const wordmarkHeight = await page.locator('.brand > span:nth-child(2)').evaluate((node) => node.getBoundingClientRect().height);
  assert.ok(wordmarkHeight <= 24, `wordmark must remain on one line: ${wordmarkHeight}px`);
  await page.getByRole('tabpanel', { name: 'events' }).waitFor({ state: 'visible' });
  const eventKind = page.locator('.event-kind').first();
  const originalKind = await eventKind.textContent();
  const stressKind = `recording_event_kind:${'long-technical-segment-'.repeat(10)}`;
  await eventKind.evaluate((node, text) => { node.textContent = text; }, stressKind);
  const eventLayout = await page.locator('.event').first().evaluate((row) => {
    const kind = row.querySelector('.event-kind');
    const time = row.querySelector('.event-time');
    if (!kind || !time) throw new Error('event row is missing kind or timestamp');
    const kindBounds = kind.getBoundingClientRect();
    const timeBounds = time.getBoundingClientRect();
    return {
      kindFits: kind.scrollWidth <= kind.clientWidth,
      timeFits: time.scrollWidth <= time.clientWidth,
      overlaps: kindBounds.right > timeBounds.left,
    };
  });
  assert.deepEqual(eventLayout, { kindFits: true, timeFits: true, overlaps: false }, 'mobile event data must wrap without clipping or overlap');
  await eventKind.evaluate((node, text) => { node.textContent = text; }, originalKind);
  if (screenshotDirectory) {
    await page.screenshot({ path: join(screenshotDirectory, 'viewer-mobile.png'), fullPage: true });
  }
  await page.getByRole('tab', { name: 'evidence' }).click();
  await page.getByRole('tabpanel', { name: 'evidence' }).waitFor({ state: 'visible' });
  await page.getByRole('tab', { name: 'recordings' }).click();
  await page.getByRole('tabpanel', { name: 'recordings' }).waitFor({ state: 'visible' });
  await page.getByRole('tab', { name: 'events' }).click();
  await page.getByRole('tabpanel', { name: 'events' }).waitFor({ state: 'visible' });
  const eventTab = page.getByRole('tab', { name: 'events' });
  await eventTab.focus();
  await eventTab.press('ArrowRight');
  assert.equal(await page.getByRole('tab', { name: 'evidence' }).getAttribute('aria-selected'), 'true');
  await page.getByRole('tab', { name: 'evidence' }).press('ArrowLeft');
  assert.equal(await eventTab.getAttribute('aria-selected'), 'true');
  await page.locator('.event').nth(1).click();
  await page.getByRole('tabpanel', { name: 'evidence' }).waitFor({ state: 'visible' });
  await page.getByRole('status').filter({ hasText: /Event .* selected/ }).waitFor();
  const apiPayloads = await page.evaluate(async (id) => {
    const headers = { 'X-XTrace-Client': 'viewer-v1' };
    const listResponse = await fetch('/api/v1/recordings?limit=50', { headers, credentials: 'same-origin' });
    const detailResponse = await fetch(`/api/v1/recordings/${encodeURIComponent(id)}?limit=200`, { headers, credentials: 'same-origin' });
    return {
      listStatus: listResponse.status,
      listBody: await listResponse.text(),
      detailStatus: detailResponse.status,
      detailBody: await detailResponse.text(),
    };
  }, recordingId);
  assert.equal(apiPayloads.listStatus, 200);
  assert.equal(apiPayloads.detailStatus, 200);
  const responseBodies = [apiPayloads.listBody, apiPayloads.detailBody];
  for (const body of responseBodies) {
    assert.ok(!body.includes(bootstrapToken), 'bootstrap token appeared in an API response');
    for (const canary of ['BODY_CANARY_1D4', 'AUTH_CANARY_1D4', 'COOKIE_CANARY_1D4', 'PATH_QUERY_CANARY_1E2']) {
      assert.ok(!body.includes(canary), `API response included privacy canary ${canary}`);
    }
  }
  assert.deepEqual(JSON.parse(apiPayloads.detailBody).events.map((event) => event.sequence), expectedSequences);
  assert.equal(new URL(page.url()).hash, '', 'bootstrap fragment must be removed before exchange');
  const cookies = await context.cookies();
  assert.equal(cookies.length, 1, 'one browser-session cookie should be issued');
  assert.equal(cookies[0].httpOnly, true);
  assert.equal(cookies[0].sameSite, 'Strict');
  assert.equal(cookies[0].secure, false, 'plain loopback HTTP cannot require Secure');
  assert.equal(cookies[0].expires, -1, 'session cookie must not have a persistence expiry');
  assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
  assert.deepEqual(await page.evaluate(() => indexedDB.databases()), []);
  assert.equal(await page.evaluate(() => document.referrer), '');
  assert.deepEqual(unexpectedRequests, [], 'browser made a request outside the loopback origin');
  assert.deepEqual(consoleErrors, [], 'browser console reported an error');
} finally {
  await browser.close();
}

process.stdout.write('browser journey passed: persisted event order and unavailable evidence verified\n');
