import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

const kindOf = ({ kind }) => kind.replace(/^recording_event_kind:/, '');
const categories = [
  ['Calls and returns', ['frame_enter', 'frame_exit', 'frame_throw', 'exception']],
  ['Lines', ['line_cursor']],
  ['Requests, responses and database', ['request_update', 'response', 'database_start', 'database_end', 'outbound_http_start', 'outbound_http_end', 'async_link']],
  ['Not recorded', ['gap']],
];
const jumps = [
  ['not-recorded stretch', 'gap', (event) => kindOf(event) === 'gap'],
  ['thrown exception', 'exception', (event) => ['frame_throw', 'exception'].includes(kindOf(event)) || event.exception != null],
  ['database call', 'database', (event) => kindOf(event) === 'database_start'],
  ['HTTP call', 'http', (event) => kindOf(event) === 'outbound_http_start'],
];

// Validate every loaded position even when the Steps list mounts only its visible window.
async function verifyRows(page, expected, timing) {
  const list = page.getByRole('list', { name: 'Loaded replay steps' });
  if (expected.length <= 80) {
    assert.deepEqual(await list.locator('.event-seq').allTextContents(), expected, 'filter keeps observed order and exact selection');
    if (timing) assert.deepEqual(await list.locator('.event-time').allTextContents(), expected.map((sequence) => timing.get(sequence)),
      'timing is an exact delta from first loaded event, not a duration');
  }
  const covered = new Set();
  for (let sweep = 0; sweep <= expected.length && covered.size < expected.length; sweep += 1) {
    const mounted = await list.evaluate(async (element, reset) => {
      const body = element.closest('.steps-content');
      const owner = body && getComputedStyle(body).overflowY === 'auto' ? body : element.closest('#events-panel');
      if (reset) owner.scrollTop = 0;
      else owner.scrollTop += Math.max(1, Math.floor(owner.clientHeight * 0.75));
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      return [...element.querySelectorAll('[data-step-sequence]')].map((row) => {
        const event = row.querySelector('.event');
        const copy = event.querySelector('.event-copy');
        const time = event.querySelector('.event-time');
        const a = copy.getBoundingClientRect();
        const b = time.getBoundingClientRect();
        return {
          sequence: row.dataset.stepSequence,
          position: Number(row.getAttribute('aria-posinset')),
          count: Number(row.getAttribute('aria-setsize')),
          timing: time.textContent,
          copyFits: copy.scrollWidth <= copy.clientWidth,
          timingFits: time.scrollWidth <= time.clientWidth,
          overlaps: a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top,
        };
      });
    }, sweep === 0);
    assert.ok(mounted.length > 0 && mounted.length <= 80, 'filter keeps the mounted Steps bound');
    for (const row of mounted) {
      assert.equal(row.count, expected.length, 'filtered row count matches the full loaded projection');
      assert.equal(row.sequence, expected[row.position - 1], 'filtered mounted position preserves exact observed order');
      covered.add(row.position);
      if (timing) {
        assert.equal(row.timing, timing.get(row.sequence), 'mounted timing matches the exact loaded timestamp delta');
        assert.ok(row.copyFits && row.timingFits && !row.overlaps, 'enabled recorded timing wraps without clipping or overlapping step text');
      }
    }
  }
  assert.equal(covered.size, expected.length, 'scrolling exposes every expected filtered step');
}

/** Real Spring read projection; the caller identifies whether the viewer was source-built or installed. */
export async function verifyLoadedReplayTools(page, { events, pointer, saveScreenshot, verifyRecordingSelection, jumpReport }) {
  assert.ok(events.length > 1, 'real Spring tools journey needs multiple recorded events');
  const selected = page.locator('.event[aria-current="true"]');
  const panel = (name) => page.getByRole('dialog', { name, exact: true });
  const activate = (control) => pointer === 'coarse' ? control.tap() : control.click();
  const touchTargets = async (scope) => {
    if (pointer !== 'coarse' && page.viewportSize().width > 1023) return;
    const sizes = await scope.locator('button, input').evaluateAll((controls) => controls
      .filter((control) => control.getClientRects().length > 0)
      .map((control) => {
        const box = control.getBoundingClientRect();
        return { label: control.getAttribute('aria-label') || control.textContent, width: box.width, height: box.height };
      }));
    assert.ok(sizes.length > 0 && sizes.every(({ width, height }) => width >= 44 && height >= 44),
      `tools and opened-panel targets remain 44px in both dimensions at ${page.viewportSize().width}px ${pointer}: ${JSON.stringify(sizes)}`);
  };
  const ensureMore = async () => {
    if (page.viewportSize().width >= 700) return;
    const more = page.getByRole('group', { name: 'Replay navigation' }).getByRole('button', { name: 'More', exact: true });
    if (await more.getAttribute('aria-expanded') !== 'true') await activate(more);
  };
  const openPanel = async (name) => {
    await ensureMore();
    const tools = page.locator('.replay-tools');
    if (page.viewportSize().width < 1280) {
      await activate(tools.getByRole('button', { name: /^Tools(?: · 1)?$/ }));
      await touchTargets(panel('Tools'));
      await activate(panel('Tools').getByRole('button', { name: { filter: /^Filter steps(?: · 1)?$/, goto: 'Go to step', jump: 'Jump to…' }[name], exact: true }));
    } else {
      await activate(tools.getByRole('button', { name: { filter: /^Filter(?: · 1)?$/, goto: 'Go to step', jump: 'Jump' }[name], exact: true }));
    }
    await touchTargets(panel({ filter: 'Filter steps', goto: 'Go to step', jump: 'Jump to' }[name]));
  };
  const showSteps = async () => {
    const tab = page.getByRole('tablist', { name: 'Viewer panes' }).getByRole('tab', { name: 'Steps', exact: true });
    if (await tab.isVisible()) await activate(tab);
    await activate(page.getByRole('tablist', { name: 'Replay view' }).getByRole('tab', { name: 'Steps', exact: true }));
    await expect(selected).toBeVisible();
  };
  const goto = async (sequence) => {
    await selected.focus();
    await page.keyboard.press('Alt+j');
    const input = panel('Go to step').getByRole('textbox', { name: 'Go to step number' });
    await expect(input).toBeFocused();
    await input.fill(sequence);
    await input.press('Enter');
    await expect(selected.locator('.event-seq')).toHaveText(sequence);
    await expect(selected).toBeFocused();
  };
  const verifyCompactJumpClose = async () => {
    const opener = page.locator('.replay-tools').getByRole('button', { name: 'Tools', exact: true });
    await openPanel('jump');
    const dialog = panel('Jump to');
    const close = dialog.getByRole('button', { name: 'Close', exact: true });
    const hitTest = () => close.evaluate((button) => {
      const box = button.getBoundingClientRect();
      const dialogBox = button.closest('[role="dialog"]').getBoundingClientRect();
      const inside = box.width >= 44 && box.height >= 44
        && box.left >= Math.max(0, dialogBox.left) && box.top >= Math.max(0, dialogBox.top)
        && box.right <= Math.min(innerWidth, dialogBox.right) && box.bottom <= Math.min(innerHeight, dialogBox.bottom);
      return inside && [[box.left + 4, box.top + 4], [box.right - 4, box.bottom - 4],
        [(box.left + box.right) / 2, (box.top + box.bottom) / 2]]
        .every(([x, y]) => button.contains(document.elementFromPoint(x, y)));
    });
    // Inspect before an automation action can scroll Close into view.
    assert.ok(await hitTest(), 'compact Jump Close starts fully within the dialog and hit-testable');
    await dialog.getByRole('button', { name: 'Next http call', exact: true }).press('Tab');
    await expect(close).toBeFocused();
    assert.ok(await hitTest(), 'compact Jump Close stays fully hit-testable with keyboard focus');
    await activate(close);
    await expect(dialog).toHaveCount(0);
    await expect(opener).toBeFocused();
  };

  for (const [width, height] of [[320, 640], [736, 900], [1024, 768], [1280, 900], [1440, 900]]) {
    jumpReport.beginViewport(width, height, pointer);
    await page.setViewportSize({ width, height });
    await showSteps();
    assert.equal(await page.evaluate((coarse) => matchMedia('(pointer: coarse)').matches === coarse, pointer === 'coarse'), true,
      `browser must use the requested ${pointer} pointer`);
    const tools = page.locator('.replay-tools');
    await ensureMore();
    if (width === 320) {
      const more = page.getByRole('group', { name: 'More replay controls', exact: true });
      const summary = page.getByRole('region', { name: 'Recording summary' });
      for (const line of ['.replay-context-request', '.replay-context-event']) {
        await expect(summary.locator(line)).toBeInViewport({ ratio: 1 });
      }
      const first = await summary.locator('.replay-context-request').boundingBox();
      const second = await summary.locator('.replay-context-event').boundingBox();
      assert.ok(first && second && first.y >= 0 && first.y + first.height <= second.y + 1,
        'phone header places the request above the selected event');
      await expect(page.locator('.topbar')).toBeHidden();
      await expect(more.getByRole('button', { name: 'Step in', exact: true })).toBeFocused();
      for (const label of ['Step in', 'Step over', 'Step out', 'Tools', /^Replay speed,/, 'Close']) {
        const action = more.getByRole('button', { name: label, exact: true });
        await expect(action).toBeInViewport({ ratio: 1 });
        assert.ok(await action.evaluate((button) => {
          const box = button.getBoundingClientRect();
          return box.width >= 44 && box.height >= 44 &&
            button.contains(document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2));
        }), 'each phone More action is fully visible and hittable');
      }
      await saveScreenshot(`viewer-phone-more-${pointer}-320.png`, `open-phone-more-real-Spring-${pointer}`, width, height, page);
    }
    if (width < 1280) {
      await expect(tools.getByRole('button', { name: 'Tools', exact: true })).toBeVisible();
      await expect(tools.getByRole('button', { name: 'Filter', exact: true })).toHaveCount(0);
    } else {
      for (const name of ['Filter', 'Go to step', 'Show timing', 'Jump']) await expect(tools.getByRole('button', { name, exact: true })).toBeVisible();
      await expect(tools.getByRole('button', { name: 'Tools', exact: true })).toHaveCount(0);
    }
    await touchTargets(tools);
    await goto(events[1].sequence);
    // Open and submit through the rendered controls as well as through the keyboard path.
    await openPanel('goto');
    await panel('Go to step').getByRole('textbox', { name: 'Go to step number' }).fill(events[1].sequence);
    await activate(panel('Go to step').getByRole('button', { name: 'Go', exact: true }));
    await expect(selected.locator('.event-seq')).toHaveText(events[1].sequence);
    await expect(selected).toBeFocused();
    if (width === 320) await verifyCompactJumpClose();
    for (const [label, kinds] of categories) {
      const sequence = await selected.locator('.event-seq').textContent();
      if (pointer === 'coarse') await openPanel('filter');
      else {
        await selected.focus();
        await page.keyboard.press('Alt+q');
      }
      await touchTargets(panel('Filter steps'));
      await expect(panel('Filter steps').getByRole('button', { name: 'All steps', exact: true })).toBeFocused();
      if (label === 'Calls and returns') await saveScreenshot(`viewer-replay-filter-${pointer}-${width}.png`, `loaded-filter-real-Spring-${pointer}`, width, height, page);
      await activate(panel('Filter steps').getByRole('button', { name: label, exact: true }));
      const expected = events.filter((event) => kinds.includes(kindOf(event)) || event.sequence === sequence).map(({ sequence }) => sequence);
      await verifyRows(page, expected);
      await expect(selected.locator('.event-seq')).toHaveText(sequence);
      await expect(page.locator('.replay-filter-note')).toContainText(`showing ${expected.length} of ${events.length} loaded steps`);
      assert.ok(await page.locator('.step-row').count() <= 80, 'filter keeps the mounted Steps bound');
      // Navigation respects the filter, while Go can still select any retained event.
      const index = expected.indexOf(sequence);
      const direction = index + 1 < expected.length ? 1 : index > 0 ? -1 : 0;
      if (direction) {
        const target = expected[index + direction];
        await activate(page.getByRole('group', { name: 'Replay navigation' }).getByRole('button', { name: direction === 1 ? 'Next' : 'Back', exact: true }));
        await expect(selected.locator('.event-seq')).toHaveText(target);
        await goto(sequence);
        await selected.press(direction === 1 ? 'ArrowDown' : 'ArrowUp');
        await expect(selected.locator('.event-seq')).toHaveText(target);
        await goto(sequence);
      }
      if (label === 'Calls and returns' && verifyRecordingSelection) {
        await verifyRecordingSelection({ sequence, activate });
        await expect(selected.locator('.event-seq')).toHaveText(sequence);
        await expect(page.locator('.replay-filter-note')).toContainText(`showing ${expected.length} of ${events.length} loaded steps`);
      }
      await activate(page.getByRole('tablist', { name: 'Replay view' }).getByRole('tab', { name: 'Map', exact: true }));
      await expect(page.getByRole('region', { name: 'Recording summary' })).toContainText(`Event sequence ${sequence}`);
      await activate(page.getByRole('tablist', { name: 'Replay view' }).getByRole('tab', { name: 'Steps', exact: true }));
      await expect(selected.locator('.event-seq')).toHaveText(sequence);
      await touchTargets(page.locator('.replay-filter-note'));
      await activate(page.getByRole('button', { name: 'Show all steps', exact: true }));
      await expect(width < 700 ? page.getByRole('button', { name: 'More', exact: true }) : tools.getByRole('button', { name: width < 1280 ? 'Tools' : 'Go to step', exact: true })).toBeFocused();
      await expect(selected.locator('.event-seq')).toHaveText(sequence);
    }

    // Native text editing keeps its focus and cannot invoke viewer-wide tools.
    await selected.focus();
    await page.keyboard.press('Alt+j');
    const sequenceInput = panel('Go to step').getByRole('textbox', { name: 'Go to step number' });
    await sequenceInput.press('Alt+q');
    await expect(sequenceInput).toBeFocused();
    await expect(panel('Filter steps')).toHaveCount(0);
    await sequenceInput.fill('999999999999999999999999');
    await sequenceInput.press('Enter');
    await expect(panel('Go to step')).toContainText('Event sequence is not in the loaded window.');
    await expect(panel('Go to step')).toContainText('No match here does not mean no match in the recording.');
    await saveScreenshot(`viewer-replay-goto-${pointer}-${width}.png`, `loaded-goto-real-Spring-${pointer}`, width, height, page);
    await sequenceInput.press('Escape');
    await expect(selected).toBeFocused();

    for (const [label, kind, matches] of jumps) {
      const matchesInWindow = events.filter(matches);
      jumpReport.observeJump(kind, matchesInWindow.length, events.slice(1).some(matches), events.slice(0, -1).some(matches));
      for (const [direction, start] of [['Next', 0], ['Previous', events.length - 1]]) {
        await goto(events[start].sequence);
        if (pointer === 'coarse') await openPanel('jump');
        else await selected.press('Alt+g');
        const dialog = panel('Jump to');
        const target = direction === 'Next' ? events.slice(1).find(matches) : events.slice(0, -1).findLast(matches);
        const button = dialog.getByRole('button', { name: `${direction} ${label.toLowerCase()}`, exact: true });
        await expect(button).toHaveAttribute('aria-disabled', String(!target));
        if (label === 'not-recorded stretch' && direction === 'Next') await saveScreenshot(`viewer-replay-jump-${pointer}-${width}.png`, `loaded-jump-real-Spring-${pointer}`, width, height, page);
        await touchTargets(dialog);
        if (target) {
          await activate(button);
          await expect(selected.locator('.event-seq')).toHaveText(target.sequence);
          await expect(selected).toBeFocused();
          jumpReport.checkedJump(kind, direction.toLowerCase(), 'activated');
        } else {
          const before = await selected.locator('.event-seq').textContent();
          await button.focus();
          await expect(button).toBeFocused();
          await expect(button).toHaveAccessibleDescription(`No ${direction === 'Next' ? 'later' : 'earlier'} ${label.toLowerCase()} in the loaded steps.`);
          await expect(dialog).toContainText(`No ${direction === 'Next' ? 'later' : 'earlier'} ${label.toLowerCase()} in the loaded steps.`);
          await button.press('Enter');
          await expect(selected.locator('.event-seq')).toHaveText(before);
          await expect(button).toBeFocused();
          await expect(dialog).toContainText(`No ${direction === 'Next' ? 'later' : 'earlier'} ${label.toLowerCase()} in the loaded steps.`);
          await activate(dialog.getByRole('button', { name: 'Close', exact: true }));
          await expect(selected.locator('.event-seq')).toHaveText(before);
          jumpReport.checkedJump(kind, direction.toLowerCase(), 'absence-reason-checked');
        }
      }
      if (width === 320) process.stdout.write(`Spring fixture loaded Jump (${pointer}): ${label}: ${matchesInWindow.length} observed; ${matchesInWindow.length ? 'matching targets checked when present' : 'absent kind, unavailable reason checked; matching journey not exercised'}\n`);
    }

    const openTiming = async () => {
      await ensureMore();
      if (width < 1280) await activate(tools.getByRole('button', { name: 'Tools', exact: true }));
      return (width < 1280 ? panel('Tools') : tools).getByRole('button', { name: 'Show timing', exact: true });
    };
    const timing = await openTiming();
    await expect(timing).toHaveAttribute('aria-pressed', 'false');
    await touchTargets(width < 1280 ? panel('Tools') : tools);
    await activate(timing);
    const baseline = BigInt(events[0].monotonicNs);
    let previous = baseline;
    const expectedTiming = events.map((event) => {
      const ns = BigInt(event.monotonicNs);
      const text = ns < baseline || ns < previous ? 'Non-monotonic timestamp' : `+${ns - baseline} ns`;
      previous = ns;
      return text;
    });
    const timingBySequence = new Map(events.map((event, index) => [event.sequence, expectedTiming[index]]));
    await verifyRows(page, events.map(({ sequence }) => sequence), timingBySequence);
    if (width === 1280) {
      await activate(page.getByRole('button', { name: 'Settings', exact: true }));
      const settings = page.getByRole('dialog', { name: 'Settings', exact: true });
      await expect(settings.getByRole('combobox', { name: 'Show timing', exact: true })).toHaveValue('on');
      await settings.getByRole('combobox', { name: 'Show timing', exact: true }).selectOption('off');
      await settings.getByRole('button', { name: 'Close', exact: true }).press('Escape');
      await expect(tools.getByRole('button', { name: 'Show timing', exact: true })).toHaveAttribute('aria-pressed', 'false');
      await activate(page.getByRole('button', { name: 'Settings', exact: true }));
      await settings.getByRole('combobox', { name: 'Show timing', exact: true }).selectOption('on');
      await settings.getByRole('button', { name: 'Close', exact: true }).press('Escape');
      await expect(tools.getByRole('button', { name: 'Show timing', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await verifyRows(page, events.map(({ sequence }) => sequence), timingBySequence);
    }
    await saveScreenshot(`viewer-replay-tools-${pointer}-${width}.png`, `loaded-tools-real-Spring-${pointer}`, width, height, page);
    await ensureMore();
    if (width < 1280) {
      await activate(tools.getByRole('button', { name: 'Tools', exact: true }));
      const menu = panel('Tools');
      for (const name of ['Filter steps', 'Go to step', 'Jump to…', 'Show timing', 'Close']) {
        await expect(menu.getByRole('button', { name, exact: true })).toBeVisible();
      }
      await expect(menu.getByRole('button', { name: 'Filter steps', exact: true })).toBeFocused();
      await touchTargets(menu);
      assert.ok(await menu.locator('button').evaluateAll((buttons) => buttons.length === 5 && buttons.every((button) => {
        const box = button.getBoundingClientRect();
        const panel = button.closest('[role="dialog"]').getBoundingClientRect();
        return box.left >= Math.max(0, panel.left) && box.right <= Math.min(innerWidth, panel.right)
          && box.top >= Math.max(0, panel.top) && box.bottom <= Math.min(innerHeight, panel.bottom)
          && button.contains(document.elementFromPoint((box.left + box.right) / 2, (box.top + box.bottom) / 2));
      })), 'compact Tools displays every action fully inside the open panel and viewport');
      await saveScreenshot(`viewer-replay-compact-tools-open-${pointer}-${width}.png`, `open-compact-tools-real-Spring-${pointer}`, width, height, page);
    } else {
      // Desktop has inline controls, not a Tools dialog. Capture the real equivalent.
      for (const name of ['Filter', 'Go to step', 'Show timing', 'Jump']) {
        const button = tools.getByRole('button', { name, exact: true });
        await expect(button).toBeVisible();
        assert.ok(await button.evaluate((element) => {
          const box = element.getBoundingClientRect();
          return box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight
            && element.contains(document.elementFromPoint((box.left + box.right) / 2, (box.top + box.bottom) / 2));
        }), 'desktop inline tool must be fully visible and hittable');
      }
      await saveScreenshot(`viewer-replay-desktop-tools-inline-${pointer}-${width}.png`, `inline-desktop-tools-real-Spring-${pointer}`, width, height, page);
    }
    await activate((width < 1280 ? panel('Tools') : tools).getByRole('button', { name: 'Show timing', exact: true }));
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), `tools fit at ${width}px ${pointer}`);
    await ensureMore();
    await touchTargets(tools);
    jumpReport.finishViewport();
  }
  await goto(events[0].sequence);
  process.stdout.write(`Replay Tools scope: real Spring fixture, ${events.length} loaded events; scale/performance and installed-package provenance require their separate host receipts.\n`);
  process.stdout.write(`Spring fixture replay tools checked at 320/736/1024/1280/1440 ${pointer}; native Alt+Q/J/G, input exclusion, Escape focus return, exact selected sequence, loaded kinds, timing, DOM bound; enabled coarse controls used touch taps; opened-panel width/height targets checked\n`);
}
