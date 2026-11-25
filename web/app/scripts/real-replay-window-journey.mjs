import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
import { jumpToLoadedSequence, verifyMountedWindow, verifyReplayWindowNavigation } from './replay-window-journey.mjs';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { url, recordingIds } = JSON.parse(Buffer.concat(chunks).toString());
assert.ok(url && recordingIds?.length === 2 && recordingIds.every(Boolean), 'two linked Spring recordings are required');
const canaries = ['BODY_CANARY_1D4', 'AUTH_CANARY_1D4', 'COOKIE_CANARY_1D4', 'PATH_QUERY_CANARY_1E2'];
const browser = await chromium.launch({ headless: true });
let stage = 'bootstrap';
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(8000);
  const origin = new URL(url).origin;
  let externalRequests = 0;
  let browserErrors = 0;
  page.on('request', (request) => { if (new URL(request.url()).origin !== origin) externalRequests += 1; });
  page.on('pageerror', () => { browserErrors += 1; });
  page.on('console', (message) => { if (message.type() === 'error') browserErrors += 1; });
  await page.goto(url);
  await page.locator('.endpoint-card').first().click();
  const read = async (recordingId, cursor) => {
    const result = await page.evaluate(async ({ recordingId, cursor, canaries }) => {
      const query = new URLSearchParams({ limit: '200' });
      if (cursor != null) query.set('cursor', cursor);
      const response = await fetch(`/api/v1/recordings/${encodeURIComponent(recordingId)}?${query}`, {
        headers: { 'X-XTrace-Client': 'viewer-v1' },
      });
      if (!response.ok) throw new Error('Spring replay read API request failed');
      const body = await response.text();
      if (canaries.some((canary) => body.includes(canary))) throw new Error('Spring replay read API exposed a canary');
      const detail = JSON.parse(body);
      return {
        previous: detail.prevCursor,
        next: detail.nextCursor,
        sequences: detail.events.map(({ sequence }) => String(sequence)),
        hasLine: detail.events.some(({ kind }) => kind === 'recording_event_kind:line_cursor'),
      };
    }, { recordingId, cursor, canaries });
    return result;
  };

  const verifyOrderedPage = ({ sequences }, after = null) => {
    assert.ok(sequences.length > 0, 'read API returned an empty replay page');
    for (const sequence of sequences) {
      assert.ok(after === null || BigInt(sequence) > BigInt(after), 'replay sequences must increase across page boundaries');
      after = sequence;
    }
  };

  stage = 'find three real server pages';
  const initials = await Promise.all(recordingIds.map((id) => read(id)));
  const pagedIndex = initials.findIndex(({ next }) => next != null);
  assert.ok(pagedIndex >= 0, 'bounded Spring workload has a real successor');
  const recordingId = recordingIds[pagedIndex];
  const otherId = recordingIds[1 - pagedIndex];
  const first = initials[pagedIndex];
  verifyOrderedPage(first);
  assert.ok(first.previous == null && initials[1 - pagedIndex].next == null);
  const middle = await read(recordingId, first.next);
  verifyOrderedPage(middle, first.sequences.at(-1));
  assert.ok(middle.previous != null && middle.next != null, 'a real interior page must have both server-issued continuations');
  const earlier = await read(recordingId, middle.previous);
  verifyOrderedPage(earlier);
  assert.ok(BigInt(earlier.sequences.at(-1)) < BigInt(middle.sequences[0]));
  assert.deepEqual(earlier.sequences, first.sequences.slice(-earlier.sequences.length),
    'backward projection returns the budgeted suffix ending at the first forward boundary');
  const later = await read(recordingId, middle.next);
  verifyOrderedPage(later, middle.sequences.at(-1));

  stage = 'verify more than 200 actual persisted events';
  let observed = first.sequences.length + middle.sequences.length + later.sequences.length;
  let hasLine = first.hasLine || middle.hasLine || later.hasLine;
  let tail = later;
  // Count only actual ordered events, even if byte or verified-input limits shorten each page.
  for (let additional = 0; (observed <= 200 || !hasLine) && tail.next != null && additional < 200; additional += 1) {
    const next = await read(recordingId, tail.next);
    verifyOrderedPage(next, tail.sequences.at(-1));
    observed += next.sequences.length;
    hasLine ||= next.hasLine;
    tail = next;
  }
  assert.ok(observed > 200 && hasLine, 'paged Spring recording has more than 200 persisted events including line evidence');
  const selectedIndex = Math.min(5, middle.sequences.length - 1);
  const selected = middle.sequences[selectedIndex];

  const row = (id) => page.locator('.recording-list .recording').filter({ hasText: id });
  const tab = (id) => page.getByRole('tablist', { name: 'Open recordings' }).getByRole('tab', { name: new RegExp(id) });
  const switchPane = async (name) => {
    const pane = page.getByRole('tab', { name, exact: true });
    if (await pane.isVisible()) {
      await pane.click();
    } else if (name === 'Requests') {
      const drawer = page.locator('#header-requests');
      if (await drawer.isVisible() && await drawer.getAttribute('aria-expanded') === 'false') {
        await drawer.click();
        await expect(drawer).toHaveAttribute('aria-expanded', 'true');
      }
    }
  };
  const currentStep = page.locator('#events-panel .event[aria-current="true"]');
  const windows = page.getByRole('region', { name: 'Loaded event window' });
  const laterButton = () => windows.getByRole('button', { name: 'Load later', exact: true });

  await verifyReplayWindowNavigation(page, async () => {
    const { width } = page.viewportSize();
    stage = `open interior Steps at ${width}px`;
    await switchPane('Requests');
    if (!(await tab(otherId).count())) {
      await row(otherId).click();
      await switchPane('Requests');
    }
    if (await tab(recordingId).count()) {
      await tab(recordingId).click();
      await page.getByRole('button', { name: 'Close recording', exact: true }).click();
      await switchPane('Requests');
    }
    await row(recordingId).click();
    await verifyMountedWindow(page, first.sequences);
    await laterButton().click();
    await verifyMountedWindow(page, [...first.sequences, ...middle.sequences]);
    await jumpToLoadedSequence(page, selected);
    if (width < 700) await switchPane('Requests');
    await tab(otherId).click();
    await verifyMountedWindow(page, initials[1 - pagedIndex].sequences);
    if (width < 700) await switchPane('Requests');
    await tab(recordingId).click();
    await expect(currentStep.locator('.event-seq')).toHaveText(selected);
    stage = `navigate and retain selection at ${width}px`;
    return { earlier: earlier.sequences, current: middle.sequences, later: later.sequences, selected };
  });
  stage = 'privacy and browser health';
  const text = await page.locator('body').innerText();
  assert.ok(canaries.every((canary) => !text.includes(canary)), 'Spring replay UI exposed a canary');
  assert.equal(externalRequests, 0);
  assert.equal(browserErrors, 0);
  console.log('real Spring replay windows proof passed at 320, 736, 1024, and 1440px');
} catch (error) {
  // Playwright failures can contain rendered trace text or private locators.
  const frames = String(error.stack).match(/(?:real-)?replay-window-journey\.mjs:\d+:\d+/g) ?? [];
  console.error(`Spring replay window failed during ${stage} (${frames.join(', ')})`);
  if (error.anchorGeometry) console.error(`Steps anchor geometry ${JSON.stringify(error.anchorGeometry)}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
