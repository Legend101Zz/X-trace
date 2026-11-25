import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

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
    const viewportName = name.replace(/\.png$/, '-viewport.png');
    await page.screenshot({ path: join(screenshotDirectory, viewportName) });
    screenshotViews.push({ file: viewportName, viewport: { width, height }, view: `${view}-viewport` });
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
  assert.equal(await page.getByRole('tab', { name: 'Requests' }).getAttribute('aria-selected'), 'true', 'mobile opens on the endpoint catalog');
  await saveScreenshot('viewer-mobile-endpoints.png', 'observed-endpoints', 390, 844);

  const requestSearch = page.getByRole('searchbox', { name: 'Search loaded requests' });
  await requestSearch.fill('no-matching-fixture-request');
  await expect(page.locator('.endpoint-card')).toHaveCount(0);
  await requestSearch.fill('/orders');
  const endpointCard = page.locator('.endpoint-card');
  await expect(endpointCard).toHaveAttribute('aria-expanded', 'false');
  await endpointCard.click();
  await expect(endpointCard).toHaveAttribute('aria-expanded', 'true');
  await requestSearch.fill('');
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
  const assertGroupedCatalog = async (scope) => {
    for (const width of [320, 736, 1024]) {
      await page.setViewportSize({ width, height: 844 });
      await expect(page.locator('.recording-date-heading').first()).toBeVisible();
      const time = page.locator('.recording-list time[datetime]').first();
      await expect(time).toBeVisible();
      const fits = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
      assert.ok(fits, `${scope} catalog should fit at ${width}px`);
    }
    await page.setViewportSize({ width: 390, height: 844 });
  };
  await assertGroupedCatalog('linked');
  const recordingButton = page.getByRole('button', { name: new RegExp(recordingId) });
  try {
    await recordingButton.click({ timeout: 5000 });
  } catch {
    throw new Error('Browser could not select the genuine linked recording in the packaged viewer');
  }
  await page.locator('.event-seq').first().waitFor();
  const firstEvent = page.locator('.event').first();
  await page.keyboard.press('Tab');
  await firstEvent.focus();
  await expect(firstEvent).toBeFocused();
  await expect(firstEvent).toHaveCSS('outline-offset', '-2px');
  await expect(firstEvent).toHaveCSS('outline-style', 'solid');
  const windowControls = page.getByRole('region', { name: 'Loaded event window' });
  await expect(windowControls.getByText('Start of the available recording window.')).toBeVisible();
  await expect(windowControls.getByRole('button', { name: 'Load earlier', exact: true })).toHaveCount(0);
  const observed = await page.locator('.event-seq').allTextContents();
  assert.deepEqual(observed, expectedSequences, 'browser event order differs from the product query projection');
  await page.getByRole('tab', { name: 'Inspector' }).click();
  await page.getByRole('tabpanel', { name: 'Inspector' }).waitFor({ state: 'visible' });
  const statusMark = page.locator('.status-mark').first();
  assert.equal(await statusMark.evaluate((node) => node.classList.contains('recording')), false);
  assert.deepEqual(await statusMark.evaluate((node) => {
    const style = getComputedStyle(node);
    return { width: style.width, height: style.height };
  }), { width: '6px', height: '6px' });
  assert.deepEqual(await page.locator('.recording').first().locator('.recording-title, .recording-sub, .recording-status').evaluateAll((labels) => labels.map((label) => getComputedStyle(label).display)), ['block', 'block', 'block']);
  await page.getByRole('tab', { name: 'Steps' }).click();
  await page.locator('.event').filter({ hasText: 'OrderService.place' }).first().click();
  await page.getByText(/Adapter reported a compile-time source binding; current source matches the recorded identity/).waitFor();
  const sourceExcerpt = await page.locator('.source-excerpt').textContent();
  assert.ok(sourceExcerpt?.includes('repository.save'), 'browser displays the matched bounded Spring source excerpt');
  await page.getByRole('tablist', { name: 'Inspector evidence' }).getByRole('tab', { name: /^Values/ }).click();
  await page.getByText('No value bindings were recorded for this event').waitFor();
  await page.getByText(/response outcome is not event-verified/i).waitFor();
  await page.setViewportSize({ width: 1280, height: 720 });
  await saveScreenshot('viewer-desktop-genuine-detail.png', 'genuine-recording-detail', 1280, 720);
  await page.setViewportSize({ width: 390, height: 844 });
  await saveScreenshot('viewer-mobile-genuine-detail.png', 'genuine-recording-detail', 390, 844);
  await page.getByRole('tab', { name: 'Steps' }).click();
  await page.getByRole('tabpanel', { name: 'Steps' }).waitFor({ state: 'visible' });
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

  // Steps and Map on the real recording at 320, 736, 1024 and 1440 px: no horizontal page scroll,
  // one shared selection, a single roving tab stop in the tree, keyboard stepping, screenshots.
  let renderedStepKinds;
  for (const [width, height] of [[320, 640], [736, 900], [1024, 768], [1440, 900]]) {
    await page.setViewportSize({ width, height });
    const eventsTab = page.getByRole('tab', { name: 'Steps' });
    if (await eventsTab.isVisible()) await eventsTab.click();
    await page.getByRole('tabpanel', { name: 'Steps' }).waitFor({ state: 'visible' });
    const noHorizontalScroll = async (view) => {
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert.ok(overflow <= 0, `${view} view scrolls the page horizontally by ${overflow}px at ${width}px`);
    };
    await page.getByRole('button', { name: 'Steps', exact: true }).click();
    await page.locator('.event').first().waitFor();
    await noHorizontalScroll('steps');
    const observedRows = page.locator('.event');
    const toolbar = page.getByRole('group', { name: 'Replay navigation' });
    const methods = observedRows.locator('.event-kind');
    assert.ok((await methods.allTextContents()).some((text) => /^Called .+/.test(text)), 'the Spring recording displays an observed call sentence');
    const kinds = await observedRows.evaluateAll((rows) => rows.map((row) => row.dataset.eventKind));
    if (renderedStepKinds) assert.deepEqual(kinds, renderedStepKinds, 'Steps retains observed kinds and order across viewport changes');
    renderedStepKinds = kinds;
    const currentRow = page.locator('.event[aria-current="true"]');
    const originalSequence = await currentRow.locator('.event-seq').textContent();
    const next = toolbar.getByRole('button', { name: 'Next', exact: true });
    const forward = await next.getAttribute('aria-disabled') !== 'true';
    await (forward ? next : toolbar.getByRole('button', { name: 'Back', exact: true })).click();
    await expect(currentRow.locator('.event-seq')).not.toHaveText(originalSequence);
    await currentRow.focus();
    await currentRow.press(forward ? 'ArrowUp' : 'ArrowDown');
    await expect(currentRow.locator('.event-seq')).toHaveText(originalSequence);
    await expect(currentRow).toBeFocused();
    await saveScreenshot(`viewer-replay-linear-${width}.png`, 'linear-real-recording', width, height);
    const selectedLinear = async () => page.locator('.event').evaluateAll((rows) => rows.findIndex((row) => row.getAttribute('aria-current') === 'true'));
    const startIndex = await selectedLinear();
    await page.getByRole('button', { name: 'Map', exact: true }).click();
    await page.getByRole('tree').waitFor();
    const items = page.getByRole('treeitem');
    const itemCount = await items.count();
    assert.ok(itemCount >= 1, `canvas tree lists the recording's frames at ${width}px`);
    assert.equal(await page.locator('.canvas-tree [role="treeitem"][tabindex="0"]').count(), 1, 'tree has exactly one tab stop');
    assert.equal(await page.locator('.canvas-svg').getAttribute('aria-hidden'), 'true', 'the drawing is decorative; the tree is the accessible form');
    await noHorizontalScroll('canvas');
    await saveScreenshot(`viewer-replay-canvas-${width}.png`, 'canvas-real-recording', width, height);
    if (itemCount > 1) {
      await page.locator('.canvas-tree [role="treeitem"][tabindex="0"]').focus();
      await page.keyboard.press('ArrowDown');
      await page.getByRole('button', { name: 'Steps', exact: true }).click();
      await page.locator('.event').first().waitFor();
      assert.notEqual(await selectedLinear(), startIndex, `ArrowDown in Canvas moved the selection Linear shows at ${width}px`);
    } else {
      await page.getByRole('button', { name: 'Steps', exact: true }).click();
    }
    assert.equal(await page.locator('.event[aria-current="true"]').count(), 1, 'exactly one selected event in Linear');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('tab', { name: 'Steps' }).click();
  await page.getByRole('tab', { name: 'Inspector' }).click();
  await page.getByRole('tabpanel', { name: 'Inspector' }).waitFor({ state: 'visible' });
  await page.getByRole('tab', { name: 'Requests' }).click();
  await page.getByRole('tabpanel', { name: 'Requests' }).waitFor({ state: 'visible' });
  await page.getByRole('tab', { name: 'Steps' }).click();
  await page.getByRole('tabpanel', { name: 'Steps' }).waitFor({ state: 'visible' });
  const eventTab = page.getByRole('tab', { name: 'Steps' });
  await eventTab.focus();
  await eventTab.press('ArrowRight');
  assert.equal(await page.getByRole('tab', { name: 'Inspector' }).getAttribute('aria-selected'), 'true');
  await page.getByRole('tab', { name: 'Inspector' }).press('ArrowLeft');
  assert.equal(await eventTab.getAttribute('aria-selected'), 'true');
  await page.locator('.event').nth(1).click();
  await page.getByRole('tabpanel', { name: 'Inspector' }).waitFor({ state: 'visible' });
  await page.getByRole('status').filter({ hasText: /Event .* selected/ }).waitFor();
  const backToStep = page.getByRole('button', { name: /Back to event/ });
  assert.ok((await backToStep.boundingBox())?.height >= 44, 'phone Back to event meets its touch target');
  await backToStep.press('Enter');
  const currentEvent = page.locator('.event[aria-current="true"]');
  await expect(currentEvent).toBeFocused();
  const priorSequence = await currentEvent.locator('.event-seq').textContent();
  await page.getByRole('tab', { name: 'Requests' }).click();
  await page.getByRole('tabpanel', { name: 'Requests' }).waitFor({ state: 'visible' });
  await page.getByRole('button', { name: 'Not linked to an endpoint' }).click();
  const historicalRow = page.getByRole('button', { name: new RegExp(legacyV4Id) });
  await historicalRow.waitFor();
  await historicalRow.getByText('No historical reason recorded').waitFor();
  for (const id of expectedUnmatchedIds) await page.getByRole('button', { name: new RegExp(id) }).waitFor();
  await assertGroupedCatalog('unmatched');
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
  await page.getByRole('tab', { name: 'Steps' }).click();
  await page.getByText('No projected events').waitFor();
  await saveScreenshot('viewer-mobile-historical-unmatched.png', 'historical-unmatched-detail', 390, 844);
  const recordingTabs = page.getByRole('tablist', { name: 'Open recordings' });
  const originalRecordingTab = recordingTabs.getByRole('tab', { name: new RegExp(recordingId) });
  const historicalTab = recordingTabs.getByRole('tab', { name: new RegExp(legacyV4Id) });
  await expect(historicalTab).toHaveAttribute('aria-selected', 'true');
  await page.setViewportSize({ width: 320, height: 640 });
  await saveScreenshot('viewer-shell-phone-tabs-320.png', 'two-recording-tabs-on-phone', 320, 640);
  await historicalTab.press('ArrowLeft');
  await expect(originalRecordingTab).toBeFocused();
  await expect(originalRecordingTab).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('.event[aria-current="true"] .event-seq')).toHaveText(priorSequence);
  await originalRecordingTab.press('ArrowRight');
  await expect(historicalTab).toBeFocused();
  await page.getByText('No projected events').waitFor();
  await historicalTab.press('Delete');
  await expect(historicalTab).toHaveCount(0);
  await expect(originalRecordingTab).toBeFocused();
  await expect(page.locator('.event[aria-current="true"] .event-seq')).toHaveText(priorSequence);

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
  const verifiedDetail = JSON.parse(apiPayloads.detailBody);
  const verifiedEvents = verifiedDetail.events;
  assert.deepEqual(verifiedEvents.map((event) => event.sequence), expectedSequences);
  assert.deepEqual(renderedStepKinds, verifiedEvents.map((event) => event.kind), 'Steps only renders kinds returned by the real recording read API');
  const knownKinds = new Set(['unspecified', 'request_update', 'frame_enter', 'frame_exit', 'frame_throw', 'line_cursor',
    'value_snapshot', 'database_start', 'database_end', 'outbound_http_start', 'outbound_http_end',
    'async_link', 'exception', 'response', 'gap']);
  const observedKindReceipt = [...new Set(verifiedEvents.map(({ kind }) => {
    const name = kind.startsWith('recording_event_kind:') ? kind.slice('recording_event_kind:'.length) : '';
    return knownKinds.has(name) ? name : 'other';
  }))].sort();
  process.stdout.write(`packaged Steps observed event kinds: ${observedKindReceipt.join(', ')}\n`);
  const intoIndex = verifiedEvents.findIndex((event) => event.navigation?.into?.state === 'target'
    && verifiedEvents.some(({ frameId }) => frameId === event.navigation.into.frameId));
  if (intoIndex >= 0) {
    const expectedTarget = verifiedEvents.find(({ frameId }) => frameId === verifiedEvents[intoIndex].navigation.into.frameId);
    await page.locator('.event').nth(intoIndex).click();
    const eventsTab = page.getByRole('tab', { name: 'Steps' });
    if (await eventsTab.isVisible()) await eventsTab.click();
    const stepIn = page.getByRole('group', { name: 'Replay navigation' }).getByRole('button', { name: 'Step in', exact: true });
    await expect(stepIn).toHaveAttribute('aria-disabled', 'false');
    await stepIn.click();
    await expect(page.locator('.event[aria-current="true"] .event-seq')).toHaveText(expectedTarget.sequence);
    process.stdout.write('packaged Steps navigation: exercised a server-resolved in-window Step in target\n');
  }

  const methodIndex = verifiedEvents.findIndex(({ kind, source }) => kind === 'recording_event_kind:frame_enter'
    && source?.status === 'matched' && typeof source.excerpt === 'string' && source.excerpt.length > 0);
  assert.ok(methodIndex >= 0, 'the standard Spring fixture returned a hash-matched method extent');
  const methodEvent = verifiedEvents[methodIndex];
  const expectedLines = methodEvent.source.excerpt.split('\n');
  const actualGapCount = verifiedEvents.filter(({ kind, gap }) => kind === 'recording_event_kind:gap' || gap != null).length;
  let observedMissingLabels;
  for (const [width, height] of [[320, 640], [736, 900], [1024, 768], [1440, 900]]) {
    await page.setViewportSize({ width, height });
    const eventsTab = page.getByRole('tab', { name: 'Steps' });
    if (await eventsTab.isVisible()) await eventsTab.click();
    await page.locator('.event').nth(methodIndex).click();
    const code = page.getByRole('region', { name: 'Code', exact: true });
    await expect(code).toBeVisible();
    await expect(code.locator('.source-row')).toHaveCount(expectedLines.length);
    const actualLines = await code.locator('.source-row').evaluateAll((rows) =>
      rows.map((row) => ({ number: Number(row.dataset.sourceLine), text: row.querySelector('.source-text').textContent })));
    assert.ok(actualLines.every(({ number, text }, index) => number === methodEvent.source.startLine + index && text === expectedLines[index]),
      `Code numbers and preserves the real source rows at ${width}px`);
    assert.equal(await code.locator('[aria-current="location"], .source-inline').count(), 0,
      `an observed method extent alone must not highlight a line or place inline bindings at ${width}px`);
    const inspectorTabs = page.getByRole('tablist', { name: 'Inspector evidence' });
    await inspectorTabs.getByRole('tab', { name: /^Values/ }).click();
    const values = page.getByRole('region', { name: 'Values', exact: true });
    await expect(values.getByRole('heading')).toHaveText(`Values (${methodEvent.bindings.length})`);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `Code and Values fit on the page at ${width}px`);
    const detailsTab = inspectorTabs.getByRole('tab', { name: 'Details', exact: true });
    await detailsTab.click();
    const details = page.getByRole('region', { name: 'Event details', exact: true });
    await expect(details.getByText(methodEvent.kind, { exact: true })).toBeVisible();
    if (methodEvent.eventId) await expect(details.locator('[data-event-field="event-id"]')).toHaveText(methodEvent.eventId);
    await expect(details.getByText(`${methodEvent.monotonicNs} ns`, { exact: true })).toBeVisible();
    const recording = page.getByRole('region', { name: 'Recording details', exact: true });
    if (verifiedDetail.capacity) await expect(recording.getByText(`Capacity drops · ${verifiedDetail.capacity.capacityDroppedEvents}`, { exact: true })).toBeVisible();
    else await expect(recording.getByText('Event capacity facts unavailable')).toBeVisible();

    await detailsTab.press('ArrowLeft');
    const missingTab = inspectorTabs.getByRole('tab', { name: /^Missing/ });
    await expect(missingTab).toBeFocused();
    await expect(missingTab).toHaveAttribute('aria-selected', 'true');
    const loaded = page.getByRole('region', { name: 'Loaded window missing evidence', exact: true });
    await expect(loaded.locator('.missing-entry').filter({ has: page.getByText('Recorded gap', { exact: true }) })).toHaveCount(actualGapCount);
    const labels = [...new Set(await loaded.locator('.missing-entry > strong').allTextContents())].sort();
    if (observedMissingLabels) assert.deepEqual(labels, observedMissingLabels, 'loaded Missing categories remain stable across widths');
    observedMissingLabels = labels;
    const target = loaded.getByRole('button', { name: /^Go to event/ }).first();
    if (await target.count()) {
      const sequence = /[0-9]+$/.exec(await target.textContent())?.[0];
      assert.ok(verifiedEvents.some((event) => event.sequence === sequence), 'Missing exposes only a loaded event target');
      await target.click();
      const row = page.locator('.event[aria-current="true"]');
      await expect(row.locator('.event-seq')).toHaveText(sequence);
      await expect(row).toBeFocused();
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('tab', { name: 'Steps' }).click();
  process.stdout.write('packaged Code and Values: hash-matched method extent, source numbering, no active line based on method range, and binding count at 320/736/1024/1440\n');
  process.stdout.write(`packaged Inspector Details and Missing checked at 320/736/1024/1440; observed loaded row categories: ${observedMissingLabels.join(', ') || 'none'}\n`);
  process.stdout.write('focused Code proof: not exercised by the standard fixture browser journey\n');
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
  // Exercise appearance only after verifying that normal replay has not written to browser storage.
  const theme = page.getByRole('combobox', { name: 'Theme' });
  const assertPalette = async (name, background) => {
    await expect(page.locator('html')).toHaveAttribute('data-theme', name);
    await expect(page.locator('body')).toHaveCSS('background-color', background);
  };
  await expect(theme).toHaveValue('system');
  await expect(theme.locator('option')).toHaveText(['System', 'Dark', 'Light', 'High contrast']);
  await page.emulateMedia({ colorScheme: 'light' });
  await assertPalette('light', 'rgb(246, 245, 242)');
  await page.emulateMedia({ colorScheme: 'dark' });
  await assertPalette('dark', 'rgb(17, 20, 22)');

  await theme.selectOption('light');
  await assertPalette('light', 'rgb(246, 245, 242)');
  await page.emulateMedia({ colorScheme: 'light' });
  await theme.selectOption('dark');
  await assertPalette('dark', 'rgb(17, 20, 22)');
  await theme.selectOption('hc');
  await assertPalette('hc', 'rgb(0, 0, 0)');
  await expect(theme).toHaveCSS('border-top-width', '2px');

  for (const width of [320, 736, 1024]) {
    await page.setViewportSize({ width, height: 844 });
    const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
    assert.equal(hasOverflow, false, `the themed viewer must fit at ${width}px`);
    const size = await theme.boundingBox();
    assert.ok(size && size.height >= (width < 1024 ? 44 : 32), `Theme target too short at ${width}px`);
    await theme.focus();
    await page.keyboard.press('Shift+Tab');
    await expect(theme).not.toBeFocused();
    await page.keyboard.press('Tab');
    await expect(theme).toBeFocused();
    await expect(theme).toHaveCSS('outline-color', 'rgb(255, 207, 92)');
    await expect(theme).toHaveCSS('outline-width', '2px');
  }

  await theme.selectOption('system');
  await assertPalette('light', 'rgb(246, 245, 242)');
  await theme.selectOption('hc');
  assert.deepEqual(await page.evaluate(() => ({ preferences: Object.entries(localStorage), session: sessionStorage.length })),
    { preferences: [['xtrace.viewer.theme', 'hc']], session: 0 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const eventAnimation = await page.locator('.event[aria-current="true"]').evaluate((row) => getComputedStyle(row).animationName);
  assert.equal(eventAnimation, 'none', 'reduced motion disables event selection animation');
  await page.setViewportSize({ width: 736, height: 900 });
  const touch = await context.newCDPSession(page);
  await touch.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 1 });
  const inspectorSplitter = page.getByRole('separator', { name: 'Resize Inspector' });
  await expect(inspectorSplitter).toHaveAttribute('aria-orientation', 'horizontal');
  await inspectorSplitter.press('ArrowUp');
  await expect(inspectorSplitter).toHaveAttribute('aria-valuenow', '28');
  await expect(inspectorSplitter).toBeFocused();
  const coarseHitHeight = await inspectorSplitter.evaluate((handle) => {
    if (!matchMedia('(pointer: coarse)').matches) throw new Error('coarse pointer emulation required');
    return parseFloat(getComputedStyle(handle, '::before').height);
  });
  assert.ok(coarseHitHeight >= 44, 'stacked Inspector splitter exposes a 44px coarse-pointer target');
  await saveScreenshot('viewer-shell-tablet-736.png', 'stacked-inspector-and-coarse-splitter', 736, 900);
  await touch.send('Emulation.setTouchEmulationEnabled', { enabled: false });
  await touch.detach();
  await page.setViewportSize({ width: 1440, height: 900 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), 'desktop shell fits at 1440px');
  await page.getByRole('button', { name: 'Reset panels' }).click();
  const requestsSplitter = page.getByRole('separator', { name: 'Resize Requests' });
  const codeSplitter = page.getByRole('separator', { name: 'Resize Code' });
  for (const width of [861, 1024]) {
    await page.setViewportSize({ width, height: 900 });
    await requestsSplitter.press('End');
    await inspectorSplitter.press('End');
    await codeSplitter.press('End');
    await expect(codeSplitter).toBeFocused();
    await expect(codeSplitter).toHaveCSS('outline-style', 'solid');
    const modeFits = await page.locator('.mode-switch').evaluate((mode) => {
      const pane = mode.closest('.pane').getBoundingClientRect();
      return [...mode.querySelectorAll('button')].every((button) => {
        const box = button.getBoundingClientRect();
        return box.left >= pane.left && box.right <= pane.right && box.width >= 44;
      });
    });
    assert.ok(modeFits, `replay mode controls remain within Steps at maximum panel preferences and ${width}px`);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `maximum panel preferences do not overflow the page at ${width}px`);
    await saveScreenshot(`viewer-shell-extreme-${width}.png`, 'splitter-extremes-and-visible-keyboard-focus', width, 900);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: 'Reset panels' }).click();
  await requestsSplitter.press('Home');
  await expect(requestsSplitter).toHaveAttribute('aria-valuenow', '16');
  await expect(requestsSplitter).toBeFocused();
  await codeSplitter.press('ArrowLeft');
  await expect(codeSplitter).toHaveAttribute('aria-valuenow', '52');
  await codeSplitter.press('Enter');
  await expect(codeSplitter).toHaveAttribute('aria-valuenow', '0');
  await expect(page.getByRole('button', { name: 'Code', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Code', exact: true }).click();
  await expect(codeSplitter).toHaveAttribute('aria-valuenow', '52');
  await expect(codeSplitter).toBeFocused();

  const inspectorBounds = await inspectorSplitter.boundingBox();
  assert.ok(inspectorBounds, 'desktop Inspector splitter is visible');
  const handleX = inspectorBounds.x + inspectorBounds.width / 2;
  const handleY = inspectorBounds.y + inspectorBounds.height / 2;
  await page.mouse.move(handleX, handleY);
  await page.mouse.down();
  await page.mouse.move(handleX - 72, handleY, { steps: 4 });
  await page.mouse.up();
  await expect(inspectorSplitter).toHaveAttribute('aria-valuenow', '31');
  await page.getByRole('button', { name: 'Reset panels' }).click();
  await expect(requestsSplitter).toHaveAttribute('aria-valuenow', '22');
  await expect(inspectorSplitter).toHaveAttribute('aria-valuenow', '26');
  await codeSplitter.press('Home');
  await expect(codeSplitter).toHaveAttribute('aria-valuenow', '28');
  await saveScreenshot('viewer-shell-desktop-1440.png', 'active-recording-tab-and-resized-panels', 1440, 900);
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('xtrace.viewer.panels'))),
    { requests: 22, code: 28, inspector: 26, lastOpen: { requests: 22, code: 28, inspector: 26 } });
  await requestsSplitter.press('Enter');
  await expect(requestsSplitter).toHaveAttribute('aria-valuenow', '0');
  await originalRecordingTab.press('Delete');
  await expect(originalRecordingTab).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Requests', exact: true })).toBeFocused();
  // Reloading the spent link exercises startup and persisted appearance without exchanging another token.
  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(theme).toHaveValue('hc');
  await assertPalette('hc', 'rgb(0, 0, 0)');
  await expect(codeSplitter).toHaveAttribute('aria-valuenow', '28');
  assert.equal(unexpectedRequestCount, 0, 'browser made a request outside the loopback origin');
  assert.equal(consoleErrorCount, 0, 'browser console reported an error');
  if (screenshotDirectory) {
    await writeFile(join(screenshotDirectory, 'metadata.json'), `${JSON.stringify({ screenshots: screenshotViews, sanitized: true }, null, 2)}\n`, { mode: 0o600 });
  }
} finally {
  await browser.close();
}

process.stdout.write('browser journey passed: persisted event order, matched source evidence, unavailable evidence, viewer themes, and shell navigation verified\n');
