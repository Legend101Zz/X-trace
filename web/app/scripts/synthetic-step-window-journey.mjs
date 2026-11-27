// Use the running embedded viewer for the retained #94 synthetic store.
// Receive {url, recordingId, verifiedFrameCount} as private JSON on stdin.
import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
import { jumpToLoadedSequence, verifyMountedWindow } from './replay-window-journey.mjs';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { url, recordingId, verifiedFrameCount } = JSON.parse(Buffer.concat(chunks).toString());
const origin = new URL(url);
assert.ok(origin.protocol === 'http:' && origin.hostname === '127.0.0.1' && origin.hash.startsWith('#token='));
assert.ok(typeof recordingId === 'string' && verifiedFrameCount === 10_000);

const browser = await chromium.launch({ headless: true });
let stage = 'bootstrap';
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  stage = 'open synthetic Steps';
  await page.goto(url);
  await page.getByRole('button', { name: 'Not linked to an endpoint', exact: true }).click();
  const button = page.locator('.recording-list .recording').filter({ hasText: recordingId });
  await expect(button).toBeVisible();
  const route = `/api/v1/recordings/${encodeURIComponent(recordingId)}`;
  const detailFromAction = async (action) => {
    const [response] = await Promise.all([
      page.waitForResponse((response) => new URL(response.url()).pathname === route && response.ok()),
      action(),
    ]);
    return response.json();
  };
  const start = performance.now();
  let detail = await detailFromAction(() => button.click());
  const current = page.locator('#events-panel .event[aria-current="true"]');
  await expect(current.locator('.event-seq')).toHaveText(String(detail.events[0].sequence));
  await expect(current).toBeInViewport();
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const openMs = Math.round(performance.now() - start);
  const expected = [];
  const append = () => {
    assert.ok(detail.recordingId === recordingId && detail.events.length > 0, 'synthetic recording identity and nonempty page');
    for (const event of detail.events) {
      const sequence = String(event.sequence);
      assert.ok(!expected.length || BigInt(expected.at(-1)) < BigInt(sequence));
      expected.push(sequence);
    }
  };
  append();
  const later = page.getByRole('button', { name: 'Load later', exact: true });
  for (let pages = 1; expected.length <= 80 && pages < 3; pages += 1) {
    detail = await detailFromAction(() => later.click());
    append();
  }
  assert.ok(expected.length > 80, 'retained synthetic window must exceed the mounted row cap');

  const samples = [];
  for (const [width, height] of [[320, 640], [736, 900], [1024, 768], [1440, 900]]) {
    stage = `synthetic scroll at ${width}px`;
    await page.setViewportSize({ width, height });
    const stepsTab = page.getByRole('tablist', { name: 'Viewer panes' }).getByRole('tab', { name: 'Steps', exact: true });
    if (await stepsTab.isVisible()) await stepsTab.click();
    const scrollStart = performance.now();
    const peakMountedRows = await verifyMountedWindow(page, expected);
    const fullWindowScrollAndAssertionMs = Math.round(performance.now() - scrollStart);
    const scrollToNewRowsMs = await page.getByRole('list', { name: 'Loaded replay steps' }).evaluate(async (list) => {
      const content = list.closest('.steps-content');
      const port = content && getComputedStyle(content).overflowY === 'auto' ? content : list.closest('#events-panel');
      const range = () => Array.from(list.querySelectorAll('[data-step-sequence]'), (row) => row.getAttribute('aria-posinset')).join(',');
      const before = range();
      const start = performance.now();
      port.scrollTop = 0;
      for (let frame = 0; frame < 60; frame += 1) {
        await new Promise(requestAnimationFrame);
        if (range() !== before) {
          await new Promise(requestAnimationFrame);
          return Math.round(performance.now() - start);
        }
      }
      return null;
    });
    assert.ok(scrollToNewRowsMs !== null, 'ordinary scroll mounts a different bounded range');
    samples.push({ width, peakMountedRows, scrollToNewRowsMs, fullWindowScrollAndAssertionMs });
    const midpoint = Math.floor(expected.length / 2);
    await jumpToLoadedSequence(page, expected[midpoint]);
    await current.press('ArrowDown');
    await expect(current).toBeFocused();
    await expect(current.locator('.event-seq')).toHaveText(expected[midpoint + 1]);
  }
  console.log(JSON.stringify({ synthetic: true, fixtureFrames: verifiedFrameCount,
    retainedEvents: expected.length, mountedRowCap: 80, openToVisibleAndSettledMs: openMs, samples }));
} catch {
  console.error(`Synthetic Steps journey failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
