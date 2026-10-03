import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const [recordingId, encodedSequences, operationId, legacyV4Id] = process.argv.slice(2);
assert.ok(recordingId && encodedSequences && operationId && legacyV4Id, 'recording, endpoint, and expected event data are required');
const expectedSequences = JSON.parse(encodedSequences);
assert.ok(Array.isArray(expectedSequences) && expectedSequences.length > 0, 'expected events must be a non-empty array');
const input = await new Promise((resolve, reject) => {
  let value = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { value += chunk; });
  process.stdin.on('end', () => resolve(value));
  process.stdin.on('error', reject);
});
const { url: startUrl, expectedUnmatchedIds, expectedLinkedIds, expectedGenuineLinkedIds, syntheticUnmatchedId } = JSON.parse(input);
assert.ok(startUrl, 'viewer URL must be supplied through stdin');
assert.ok(Array.isArray(expectedUnmatchedIds) && expectedUnmatchedIds.includes(legacyV4Id), 'historical unmatched fixture must be present');
assert.ok(Array.isArray(expectedLinkedIds) && expectedLinkedIds.includes(recordingId), 'expected linked page must include the selected capture');
assert.ok(Array.isArray(expectedGenuineLinkedIds) && expectedGenuineLinkedIds.includes(recordingId), 'selected recording must be a genuine pre-enrichment capture');
assert.ok(syntheticUnmatchedId && expectedUnmatchedIds.includes(syntheticUnmatchedId), 'synthetic unmatched fixture must be present');

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  let consoleErrorCount = 0;
  let unexpectedRequestCount = 0;
  const bootstrapToken = new URL(startUrl).hash.slice('#token='.length);
  page.on('console', (message) => { if (message.type() === 'error') consoleErrorCount += 1; });
  page.on('pageerror', () => { consoleErrorCount += 1; });
  page.on('request', (request) => {
    assert.ok(!request.url().includes(bootstrapToken), 'bootstrap token appeared in a request URL');
    if (new URL(request.url()).origin !== new URL(startUrl).origin) unexpectedRequestCount += 1;
    const headers = request.headers();
    assert.ok(!headers.referer?.includes(bootstrapToken), 'bootstrap token appeared in a referrer');
  });

  try {
    await page.goto(startUrl, { waitUntil: 'domcontentloaded' });
  } catch {
    throw new Error(`viewer page failed to load at ${new URL(startUrl).origin}`);
  }
  await page.getByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ }).waitFor();
  await page.getByText('Operator-selected policy').waitFor();
  await page.getByText('spring-orders-v1 does not attest which adapter or application produced the event.').waitFor();
  assert.equal(await page.locator('.endpoint-card').count(), 1, 'the finite fixture policy shows its persisted endpoint');
  const screenshotDirectory = process.env.XTRACE_BROWSER_SCREENSHOT_DIR;
  const screenshotViews = [];
  const saveScreenshot = async (name, view, width, height) => {
    if (!screenshotDirectory) return;
    await page.screenshot({ path: join(screenshotDirectory, name), fullPage: true });
    screenshotViews.push({ file: name, viewport: { width, height }, view });
  };
  if (screenshotDirectory) {
    await mkdir(screenshotDirectory, { recursive: true });
    await saveScreenshot('viewer-desktop-endpoints.png', 'observed-endpoints', 1280, 720);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  const tabHeights = await page.getByRole('tab').evaluateAll((tabs) => tabs.map((tab) => tab.getBoundingClientRect().height));
  assert.ok(tabHeights.every((height) => height >= 44), `mobile pane tabs must be at least 44px tall: ${tabHeights}`);
  const wordmarkHeight = await page.locator('.brand > span:nth-child(2)').evaluate((node) => node.getBoundingClientRect().height);
  assert.ok(wordmarkHeight <= 24, `wordmark must remain on one line: ${wordmarkHeight}px`);
  assert.equal(await page.getByRole('tab', { name: 'recordings' }).getAttribute('aria-selected'), 'true', 'mobile opens on the endpoint catalog');
  await saveScreenshot('viewer-mobile-endpoints.png', 'observed-endpoints', 390, 844);

  await page.locator('.endpoint-card').click();
  const linkedRows = page.locator('.recording-list .recording');
  await linkedRows.first().waitFor();
  const linkedIds = await linkedRows.locator('.recording-title').allTextContents();
  assert.deepEqual([...linkedIds].sort(), [...expectedLinkedIds].sort(), 'browser linked list matches the bounded endpoint query projection');
  assert.ok(linkedIds.includes(recordingId), 'browser links the selected genuine persisted Spring recording');
  for (const id of expectedGenuineLinkedIds) assert.ok(linkedIds.includes(id), `genuine capture ${id} remains linked after fixture enrichment`);
  for (const id of expectedUnmatchedIds) assert.ok(!linkedIds.includes(id), `unmatched recording ${id} is excluded from this endpoint`);
  assert.ok(!linkedIds.includes(syntheticUnmatchedId));
  await page.getByText('POST /orders', { exact: false }).waitFor();
  await page.getByText('Component: spring-fixture · Binding: default').waitFor();
  await saveScreenshot('viewer-mobile-linked-recordings.png', 'linked-recordings', 390, 844);
  const recordingButton = page.getByRole('button', { name: new RegExp(recordingId) });
  try {
    await recordingButton.click({ timeout: 5000 });
  } catch {
    throw new Error('Browser could not select the genuine linked recording in the packaged viewer');
  }
  await page.locator('.event-seq').first().waitFor();
  const observed = await page.locator('.event-seq').allTextContents();
  assert.deepEqual(observed, expectedSequences, 'browser event order differs from the product query projection');
  await page.getByRole('tab', { name: 'evidence' }).click();
  await page.getByRole('tabpanel', { name: 'evidence' }).waitFor({ state: 'visible' });
  const statusMark = page.locator('.status-mark').first();
  assert.equal(await statusMark.evaluate((node) => node.classList.contains('recording')), false);
  assert.deepEqual(await statusMark.evaluate((node) => {
    const style = getComputedStyle(node);
    return { width: style.width, height: style.height };
  }), { width: '6px', height: '6px' });
  assert.deepEqual(await page.locator('.recording').first().locator('.recording-title, .recording-sub, .recording-status').evaluateAll((labels) => labels.map((label) => getComputedStyle(label).display)), ['block', 'block', 'block']);
  await page.getByRole('tab', { name: 'events' }).click();
  await page.locator('.event').filter({ hasText: 'OrderService.place' }).click();
  await page.getByText(/Adapter reported a compile-time source binding; current source matches the recorded identity/).waitFor();
  const sourceExcerpt = await page.locator('.source-excerpt').textContent();
  assert.ok(sourceExcerpt?.includes('repository.save'), 'browser displays the matched bounded Spring source excerpt');
  await page.getByText('Values were not projected').waitFor();
  await page.getByText(/completion semantics unavailable/i).waitFor();
  await page.setViewportSize({ width: 1280, height: 720 });
  await saveScreenshot('viewer-desktop-genuine-detail.png', 'genuine-recording-detail', 1280, 720);
  await page.setViewportSize({ width: 390, height: 844 });
  await saveScreenshot('viewer-mobile-genuine-detail.png', 'genuine-recording-detail', 390, 844);
  await page.getByRole('tab', { name: 'events' }).click();
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
  await saveScreenshot('viewer-mobile-genuine-events.png', 'genuine-event-window', 390, 844);
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
  await page.getByRole('tab', { name: 'recordings' }).click();
  await page.getByRole('tabpanel', { name: 'recordings' }).waitFor({ state: 'visible' });
  await page.getByRole('button', { name: 'Unmatched recordings' }).click();
  const historicalRow = page.getByRole('button', { name: new RegExp(legacyV4Id) });
  await historicalRow.waitFor();
  await historicalRow.getByText('No historical reason recorded').waitFor();
  for (const id of expectedUnmatchedIds) await page.getByRole('button', { name: new RegExp(id) }).waitFor();
  await page.setViewportSize({ width: 1280, height: 720 });
  await saveScreenshot('viewer-desktop-unmatched.png', 'unmatched-recordings', 1280, 720);
  await page.setViewportSize({ width: 390, height: 844 });
  await saveScreenshot('viewer-mobile-unmatched.png', 'unmatched-recordings', 390, 844);
  await historicalRow.click();
  await page.getByRole('heading', { name: legacyV4Id }).waitFor();
  await page.getByText('No projected events').waitFor();
  await page.setViewportSize({ width: 1280, height: 720 });
  await saveScreenshot('viewer-desktop-historical-unmatched.png', 'historical-unmatched-detail', 1280, 720);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('tab', { name: 'events' }).click();
  await page.getByText('No projected events').waitFor();
  await saveScreenshot('viewer-mobile-historical-unmatched.png', 'historical-unmatched-detail', 390, 844);
  const apiPayloads = await page.evaluate(async ({ id, operationId, legacyV4Id, expectedUnmatchedIds }) => {
    const headers = { 'X-XTrace-Client': 'viewer-v1' };
    const listResponse = await fetch('/api/v1/recordings?limit=50', { headers, credentials: 'same-origin' });
    const detailResponse = await fetch(`/api/v1/recordings/${encodeURIComponent(id)}?limit=200`, { headers, credentials: 'same-origin' });
    const endpointResponse = await fetch('/api/v1/endpoints', { headers, credentials: 'same-origin' });
    const linkedResponse = await fetch(`/api/v1/endpoints/${encodeURIComponent(operationId)}/recordings?limit=50`, { headers, credentials: 'same-origin' });
    const unmatchedPages = [];
    let unmatchedCursor = null;
    for (let pageIndex = 0; pageIndex < 20; pageIndex += 1) {
      const suffix = unmatchedCursor ? `&cursor=${encodeURIComponent(unmatchedCursor)}` : '';
      const response = await fetch(`/api/v1/recordings?unmatched=true&limit=1${suffix}`, { headers, credentials: 'same-origin' });
      unmatchedPages.push({ status: response.status, body: await response.text() });
      if (response.status !== 200) break;
      unmatchedCursor = JSON.parse(unmatchedPages.at(-1).body).nextCursor;
      if (!unmatchedCursor) break;
    }
    return {
      listStatus: listResponse.status,
      listBody: await listResponse.text(),
      detailStatus: detailResponse.status,
      detailBody: await detailResponse.text(),
      endpointStatus: endpointResponse.status,
      endpointBody: await endpointResponse.text(),
      linkedStatus: linkedResponse.status,
      linkedBody: await linkedResponse.text(),
      unmatchedPages,
      expectedUnmatchedIds,
      operationId,
      legacyV4Id,
    };
  }, { id: recordingId, operationId, legacyV4Id, expectedUnmatchedIds });
  assert.equal(apiPayloads.listStatus, 200);
  assert.equal(apiPayloads.detailStatus, 200);
  assert.equal(apiPayloads.endpointStatus, 200);
  assert.equal(apiPayloads.linkedStatus, 200);
  const endpointPage = JSON.parse(apiPayloads.endpointBody);
  assert.ok(endpointPage.items.some((item) => item.operationId === operationId));
  const linkedPage = JSON.parse(apiPayloads.linkedBody);
  assert.ok(linkedPage.items.some((item) => item.recordingId === recordingId));
  assert.ok(apiPayloads.unmatchedPages.length < 20, 'unmatched continuation must terminate');
  assert.ok(apiPayloads.unmatchedPages.every((page) => page.status === 200));
  const unmatchedPages = apiPayloads.unmatchedPages.map((page) => JSON.parse(page.body));
  const unmatchedItems = unmatchedPages.flatMap((page) => page.items);
  assert.deepEqual(unmatchedItems.map((item) => item.recordingId), expectedUnmatchedIds);
  assert.equal(new Set(unmatchedItems.map((item) => item.recordingId)).size, unmatchedItems.length);
  const legacyRow = unmatchedItems.find((item) => item.recordingId === legacyV4Id);
  assert.ok(legacyRow, 'historical sidecar-absent v4 recording remains visible after viewer restart');
  assert.equal(legacyRow.operationId, null);
  assert.equal(legacyRow.unmatchedReason, null);
  const responseBodies = [apiPayloads.listBody, apiPayloads.detailBody, apiPayloads.endpointBody, apiPayloads.linkedBody, ...apiPayloads.unmatchedPages.map((page) => page.body)];
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
  assert.equal(unexpectedRequestCount, 0, 'browser made a request outside the loopback origin');
  assert.equal(consoleErrorCount, 0, 'browser console reported an error');
  if (screenshotDirectory) {
    await writeFile(join(screenshotDirectory, 'metadata.json'), `${JSON.stringify({ screenshots: screenshotViews, sanitized: true }, null, 2)}\n`, { mode: 0o600 });
  }
} finally {
  await browser.close();
}

process.stdout.write('browser journey passed: persisted event order, matched source evidence, and unavailable evidence verified\n');
