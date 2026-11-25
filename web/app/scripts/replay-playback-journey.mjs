import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

const gap = (event) => event.kind.replace(/^recording_event_kind:/, '') === 'gap' || event.gap != null;
const timestamp = (value) => typeof value === 'string' && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n;

/** Real retained Spring events and trusted controls; the browser clock controls display timers, not trace data. */
export async function verifyReplayPlayback(page, { events, pointer, openCapture, saveScreenshot }) {
  const start = events.findIndex((event, index) => event.frameId && events[index + 1]?.frameId && !gap(event) && !gap(events[index + 1])
    && timestamp(event.monotonicNs) && timestamp(events[index + 1].monotonicNs));
  assert.ok(start >= 0, 'real Spring playback needs an observed adjacent non-gap timed pair');
  const activate = (control) => pointer === 'coarse' ? control.tap() : control.click();
  const selected = page.locator('.event[aria-current="true"]');
  const playback = page.locator('.phone-replay-toolbar, .replay-context .replay-playback');
  const ensureMore = async () => {
    if (page.viewportSize().width >= 700) return;
    const more = playback.getByRole('button', { name: 'More', exact: true });
    if (await more.getAttribute('aria-expanded') !== 'true') await activate(more);
  };
  const replay = () => playback.getByRole('button', { name: 'Replay', exact: true });
  const pause = () => playback.getByRole('button', { name: 'Pause', exact: true });
  const selection = page.locator('#evidence-panel > button');
  const mode = (name) => page.getByRole('tablist', { name: 'Replay view', exact: true }).getByRole('tab', { name, exact: true });
  const submitGo = async (sequence) => {
    await selected.focus();
    await selected.press('Alt+j');
    const input = page.getByRole('dialog', { name: 'Go to step', exact: true }).getByRole('textbox', { name: 'Go to step number' });
    await input.fill(sequence);
    await input.press('Enter');
    await expect(selected.locator('.event-seq')).toHaveText(sequence);
  };
  const go = async (sequence) => {
    await submitGo(sequence);
    // Go restores row focus on the next animation frame. Under the controlled clock,
    // complete that interaction before moving focus to an unrelated playback control.
    await page.clock.runFor(17);
    await expect(selected).toBeFocused();
  };
  const speed = async (value) => {
    await ensureMore();
    const opener = playback.getByRole('button', { name: /^Replay speed,/ });
    await activate(opener);
    await activate(page.getByRole('dialog', { name: 'Replay speed', exact: true }).getByRole('button', { name: `${value}×`, exact: true }));
    await expect(opener).toHaveAccessibleName(`Replay speed, ${value}×`);
    await expect(opener).toBeFocused();
  };
  // Clock emulation is confined to display pacing; no request, recording or projection is replaced.
  await page.clock.pauseAt(await page.evaluate(() => Date.now() + 1000));
  try {
    for (const [width, height] of [[320,640], [736,900], [1024,768], [1280,900], [1440,900]]) {
      await page.setViewportSize({ width, height });
      const tab = page.getByRole('tablist', { name: 'Viewer panes' }).getByRole('tab', { name: 'Steps', exact: true });
      if (await tab.isVisible()) await activate(tab);
      await activate(page.getByRole('tablist', { name: 'Replay view' }).getByRole('tab', { name: 'Steps', exact: true }));
      await go(events[start].sequence);
      if (width === 320) {
        // Both actions occur while the Go focus frame is still queued.
        await submitGo(events[start].sequence);
        await activate(mode('Map'));
        await page.clock.runFor(17);
        await expect(page.locator('.canvas-tree [aria-selected="true"]')).toBeFocused();
        await activate(mode('Steps'));
        await ensureMore();
        await submitGo(events[start + 1].sequence);
        const speedButton = playback.getByRole('button', { name: /^Replay speed,/ });
        await activate(speedButton);
        const speedDialog = page.getByRole('dialog', { name: 'Replay speed', exact: true });
        const selectedSpeed = speedDialog.locator('button[aria-pressed="true"]');
        await expect(selectedSpeed).toBeFocused();
        await page.clock.runFor(17);
        await expect(selectedSpeed).toBeFocused();
        await selectedSpeed.press('Escape');
        await expect(speedButton).toBeFocused();
        await go(events[start].sequence);
      }
      await speed(1);
      await activate(replay());
      await expect(pause()).toHaveAttribute('aria-pressed', 'true');
      await saveScreenshot(`viewer-replay-playback-${pointer}-${width}.png`, `real-Spring-display-playback-clock-controlled-${pointer}`, width, height, page);
      await activate(pause());
      await page.clock.runFor(2001);
      await expect(selected.locator('.event-seq')).toHaveText(events[start].sequence);
      await expect(replay()).toBeFocused();
      const pausedMessage = await playback.locator('.replay-playback-status').textContent();
      await activate(mode('Map'));
      await expect(replay()).toHaveAttribute('aria-pressed', 'false');
      await expect(selection).toHaveText(new RegExp(`^(Back to step · sequence ${events[start].sequence} · |Focus event ${events[start].sequence}$)`));
      await expect(page.locator('.canvas-tree [aria-selected="true"]')).toBeFocused();
      await expect(playback.locator('.replay-playback-status')).toHaveText(pausedMessage);
      await activate(mode('Steps'));
      await expect(selected.locator('.event-seq')).toHaveText(events[start].sequence);
      await expect(selected).toBeFocused();
      await mode('Steps').focus();
      await mode('Steps').press('ArrowRight');
      await expect(mode('Map')).toBeFocused();
      await expect(mode('Map')).toHaveAttribute('aria-selected', 'true');
      await mode('Map').press('ArrowLeft');
      await expect(mode('Steps')).toBeFocused();
      await expect(selected.locator('.event-seq')).toHaveText(events[start].sequence);
      await expect(replay()).toHaveAttribute('aria-pressed', 'false');
      await replay().press('Alt+p');
      await expect(pause()).toBeVisible();
      await pause().press('Escape');
      await page.clock.runFor(2001);
      await expect(selected.locator('.event-seq')).toHaveText(events[start].sequence);
      await selected.focus();
      await selected.press('Alt+p');
      await selected.press('Alt+j');
      const input = page.getByRole('dialog', { name: 'Go to step', exact: true }).getByRole('textbox', { name: 'Go to step number' });
      await input.press('Alt+p');
      await expect(page.locator('.replay-start')).toHaveAttribute('aria-pressed', 'true');
      await input.fill(events[start + 1].sequence);
      await input.press('Enter');
      await expect(replay()).toHaveAttribute('aria-pressed', 'false');
      await page.clock.runFor(2001);
      await expect(selected.locator('.event-seq')).toHaveText(events[start + 1].sequence);
      await go(events[start].sequence);
      await speed(2);
      await selected.focus();
      await selected.press('Alt+q');
      await activate(page.getByRole('dialog', { name: 'Filter steps', exact: true }).getByRole('button', { name: 'Calls and returns', exact: true }));
      const filterMessage = await page.locator('.replay-filter-note').textContent();
      await activate(replay());
      for (const name of ['Map', 'Steps', 'Map']) {
        await activate(mode(name));
        await expect(pause()).toHaveAttribute('aria-pressed', 'true');
        await expect(page.locator('.replay-filter-note')).toHaveText(filterMessage);
        await expect(selection).toHaveText(new RegExp(`^(Back to step · sequence ${events[start].sequence} · |Focus event ${events[start].sequence}$)`));
        await expect(name === 'Map' ? page.locator('.canvas-tree [aria-selected="true"]') : selected).toBeFocused();
        if (width < 700) {
          await ensureMore();
          await expect(playback.getByRole('button', { name: 'Replay speed, 2×' })).toBeVisible();
          await playback.getByRole('button', { name: 'Close', exact: true }).press('Escape');
          await activate(mode(name));
          await expect(name === 'Map' ? page.locator('.canvas-tree [aria-selected="true"]') : selected).toBeFocused();
        } else {
          await expect(playback.getByRole('button', { name: 'Replay speed, 2×' })).toBeVisible();
        }
      }
      await page.evaluate(() => {
        const changes = [];
        let previous = document.querySelector('#evidence-panel > button')?.textContent;
        const observer = new MutationObserver(() => {
          const next = document.querySelector('#evidence-panel > button')?.textContent;
          if (next && next !== previous) { changes.push((next.match(/sequence (\d+)/) ?? next.match(/(\d+)$/))[1]); previous = next; }
        });
        observer.observe(document.querySelector('#evidence-panel'), { subtree: true, characterData: true, childList: true });
        window.__xtracePlaybackModeProof = { changes, observer };
      });
      const modeBefore = BigInt(events[start].monotonicNs), modeAfter = BigInt(events[start + 1].monotonicNs);
      const modeDelay = modeAfter < modeBefore ? 0 : Math.min(2000, Number((modeAfter - modeBefore) / 2n / 1_000_000n));
      await page.clock.runFor(Math.max(1, modeDelay));
      await expect.poll(() => page.evaluate(() => window.__xtracePlaybackModeProof.changes.length)).toBeGreaterThan(0);
      const modeChanges = await page.evaluate(() => {
        window.__xtracePlaybackModeProof.observer.disconnect();
        const changes = window.__xtracePlaybackModeProof.changes;
        delete window.__xtracePlaybackModeProof;
        return changes;
      });
      assert.equal(modeChanges[0], events[start + 1].sequence, 'playback continues in Map at the exact adjacent real event after both mode switches');
      assert.deepEqual(modeChanges, events.slice(start + 1, start + 1 + modeChanges.length).map((event) => event.sequence), 'mode switching never doubles or skips a rendered playback selection');
      await page.clock.runFor(16);
      await expect(page.locator('.canvas-tree [aria-selected="true"]')).toBeFocused();
      if (await pause().count()) await activate(pause());
      const pausedSequence = (await selection.textContent()).match(/^(?:Back to step · sequence |Focus event )(\d+)(?: · |$)/)[1];
      await activate(mode('Steps'));
      await expect(selected.locator('.event-seq')).toHaveText(pausedSequence);
      await expect(replay()).toHaveAttribute('aria-pressed', 'false');
      await activate(page.getByRole('button', { name: 'Show all steps', exact: true }));
      await go(events[start].sequence);
      await page.evaluate(() => {
        const changes = [];
        let previous = document.querySelector('.event[aria-current="true"] .event-seq')?.textContent;
        const observer = new MutationObserver(() => {
          const next = document.querySelector('.event[aria-current="true"] .event-seq')?.textContent;
          if (next && next !== previous) { changes.push(next); previous = next; }
        });
        observer.observe(document.querySelector('#events-panel'), { subtree: true, attributes: true, childList: true });
        window.__xtracePlaybackProof = { changes, observer };
      });
      await activate(replay());
      const before = BigInt(events[start].monotonicNs), after = BigInt(events[start + 1].monotonicNs);
      const delay = after < before ? 0 : Math.min(2000, Number((after - before) / 2n / 1_000_000n));
      await page.clock.runFor(Math.max(1, delay));
      await expect.poll(() => page.evaluate(() => window.__xtracePlaybackProof.changes.length)).toBeGreaterThan(0);
      const changes = await page.evaluate(() => {
        window.__xtracePlaybackProof.observer.disconnect();
        const value = window.__xtracePlaybackProof.changes;
        delete window.__xtracePlaybackProof;
        return value;
      });
      assert.equal(changes[0], events[start + 1].sequence, 'first rendered playback target is the exact adjacent recorded event');
      assert.deepEqual(changes, events.slice(start + 1, start + 1 + changes.length).map((event) => event.sequence), 'rendered replay retains recording order');
      if (await pause().count()) await activate(pause());
      await go(events.at(-1).sequence);
      await expect(replay()).toHaveAttribute('aria-disabled', 'true');
      await expect(playback.locator('.replay-playback-status')).toContainText(/Replay stopped|Playback stopped/);
      const gapIndex = events.findIndex((event, index) => index > 0 && gap(event));
      if (gapIndex > 0) {
        await go(events[gapIndex - 1].sequence);
        await selected.press('Alt+q');
        await activate(page.getByRole('dialog', { name: 'Filter steps', exact: true }).getByRole('button', { name: 'Calls and returns', exact: true }));
        await expect(replay()).toHaveAttribute('aria-disabled', 'true');
        await expect(playback.locator('.replay-playback-status')).toContainText('Playback stopped at a gap');
        await activate(page.getByRole('button', { name: 'Show all steps', exact: true }));
      }
      await go(events[start].sequence);
      await ensureMore();
      await activate(playback.getByRole('button', { name: /^Replay speed,/ }));
      const speedChoices = page.getByRole('dialog', { name: 'Replay speed', exact: true });
      await expect(speedChoices).toContainText('display pacing, not a step duration');
      const chosen = speedChoices.getByRole('button', { name: '2×', exact: true });
      const other = speedChoices.getByRole('button', { name: '4×', exact: true });
      await expect(speedChoices.locator('.replay-speed-options [aria-pressed="true"]')).toHaveCount(1);
      await expect(chosen).toHaveAttribute('aria-pressed', 'true');
      await expect(chosen).toBeFocused();
      await chosen.press('Tab');
      await expect(other).toBeFocused();
      await expect(other).toHaveAttribute('aria-pressed', 'false');
      const appearance = (button) => button.evaluate((node) => {
        const { backgroundColor, color, fontWeight } = getComputedStyle(node);
        return { backgroundColor, color, weight: Number(fontWeight) };
      });
      const [chosenStyle, otherStyle] = await Promise.all([appearance(chosen), appearance(other)]);
      assert.notEqual(chosenStyle.backgroundColor, otherStyle.backgroundColor, 'selected speed stays visibly filled away from focus');
      assert.notEqual(chosenStyle.color, otherStyle.color, 'selected speed uses the accent foreground');
      assert.ok(chosenStyle.weight > otherStyle.weight, 'selected speed has a second visible distinction besides color');
      await saveScreenshot(`viewer-replay-speed-${pointer}-${width}.png`, `real-Spring-replay-speed-${pointer}`, width, height, page);
      await speedChoices.getByRole('button', { name: 'Close', exact: true }).press('Escape');
      if (width === 1280) {
        await activate(page.getByRole('button', { name: 'Settings', exact: true }));
        await page.getByRole('combobox', { name: 'Default speed', exact: true }).selectOption('0.5');
        await page.getByRole('dialog', { name: 'Settings', exact: true }).getByRole('button', { name: 'Close', exact: true }).press('Escape');
        await expect(playback.getByRole('button', { name: 'Replay speed, 2×' })).toBeVisible();
        await page.reload({ waitUntil: 'domcontentloaded' });
        await openCapture();
        await expect(playback.getByRole('button', { name: 'Replay speed, 0.5×' })).toBeVisible();
      }
      const sizes = await playback.locator('button').evaluateAll((buttons) => buttons.filter((button) => button.getClientRects().length).map((button) => {
        const box = button.getBoundingClientRect(); return [box.width,box.height];
      }));
      assert.ok(sizes.every(([w,h]) => w >= 44 && h >= 44), 'playback controls have 44px targets in both dimensions');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), 'playback fits the requested viewport');
    }
    await speed(1);
    await go(events[0].sequence);
  } finally {
    await page.clock.resume();
  }
  process.stdout.write(`Replay controls: real Spring events at five widths, ${pointer}; display timers clock-controlled, no runtime timing measurement; gap matching only when observed\n`);
}
