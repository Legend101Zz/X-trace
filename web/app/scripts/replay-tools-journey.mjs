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
    if (await more.getAttribute('aria-expanded') === 'true') return;
    try {
      await activate(more);
      await expect(more).toHaveAttribute('aria-expanded', 'true');
    } catch (error) {
      // Classify the rendered hit target without logging DOM text, selectors or captured values.
      const hit = await page.evaluate(() => {
        const button = document.querySelector('.phone-actions button[aria-expanded]');
        if (!button) return 'missing';
        const box = button.getBoundingClientRect();
        const x = box.left + box.width / 2;
        const y = box.top + box.height / 2;
        if (!box.width || !box.height || x < 0 || x >= innerWidth || y < 0 || y >= innerHeight) return 'outside';
        const target = document.elementFromPoint(x, y);
        if (button.contains(target)) return 'more';
        if (target?.closest('.replay-tool-panel--jump')) return 'jump';
        if (target?.closest('[role="dialog"]')) return 'dialog';
        if (target?.closest('.viewer-preferences, .tabs')) return 'footer';
        if (target?.closest('#events-panel')) return 'steps';
        return 'other';
      }).catch(() => 'unavailable');
      process.stderr.write(`Replay More hit after failure: ${hit}\n`);
      throw error;
    }
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
  const assertLabelUncovered = async (locator) => {
    await expect(locator).toBeInViewport({ ratio: 1 });
    assert.ok(await locator.evaluate((element) => {
      const text = document.createRange();
      text.selectNodeContents(element);
      const lines = [...text.getClientRects()].filter((rect) => rect.width && rect.height);
      return lines.length > 0 && lines.every(({ left, top, width, height }) => {
        const y = top + height / 2;
        return [left + 1, left + width / 2, left + width - 1].every((x) =>
          element.contains(document.elementFromPoint(x, y)));
      });
    }), 'the rendered label is inside the viewport and unobscured by neighboring panes or controls');
  };
  const verifyRecordingBar = async (detail, width) => {
    const summary = page.getByRole('region', { name: 'Recording summary' });
    const ns = detail.durationNs === null ? null : BigInt(detail.durationNs);
    const duration = ns === null ? 'Duration unavailable' : ns < 1_000_000n ? `${ns} ns` :
      `${ns / 1_000_000n}.${(ns / 100_000n) % 10n} ms`;
    const standard = detail.limitations.includes('capture_policy_not_armed');
    const capture = summary.locator('.recording-capture');
    const info = width < 700 ? summary.locator('.replay-context-why') : capture;
    const opener = info.locator('summary');
    if (width < 700) {
      await expect(capture).toBeHidden();
    } else {
      const value = summary.locator('.recording-duration-value');
      await expect(value).toHaveText(duration);
      await assertLabelUncovered(value);
      await expect(opener).toHaveText(standard ? 'Standard' : 'Capture');
    }
    await assertLabelUncovered(opener);
    if (pointer === 'coarse' || width < 1024) {
      const box = await opener.boundingBox();
      assert.ok(box && box.width >= 44 && box.height >= 44, 'recording evidence has a touch-sized control');
    }
    await opener.press('Enter');
    await expect(info).toHaveJSProperty('open', true);
    const explanation = info.locator('.replay-context-explanation');
    await expect(explanation).toBeInViewport({ ratio: 1 });
    const modeEvidence = explanation.getByText(standard ?
      'Focused capture was not armed; relaunch with focused capture to record this.' :
      'Capture mode unavailable for this recording.', { exact: true });
    try {
      await assertLabelUncovered(modeEvidence);
    } catch (failure) {
      // Diagnose the original hit-test without publishing text, selectors or DOM content.
      try {
        const surfaces = await modeEvidence.evaluate((element) => {
          const range = document.createRange();
          range.selectNodeContents(element);
          const labels = new Set();
          for (const rect of [...range.getClientRects()].filter(rect => rect.width && rect.height).slice(0, 32)) {
            const y = rect.top + rect.height / 2;
            for (const x of [rect.left + 1, rect.left + rect.width / 2, rect.right - 1]) {
              if (x < 0 || x >= innerWidth || y < 0 || y >= innerHeight) {
                labels.add('outside-viewport');
                continue;
              }
              const hit = document.elementFromPoint(x, y);
              if (element.contains(hit)) continue;
              const known = [
                ['.replay-toolbar', 'replay-toolbar'],
                ['.panel-splitter', 'panel-splitter'],
                ['.replay-speed-panel', 'speed-panel'],
                ['.replay-tool-panel', 'tool-panel'],
                ['.recording-more-options', 'recording-more'],
                ['.replay-context-explanation', 'recording-explanation'],
                ['.replay-context', 'recording-context'],
                ['.viewer-workspace', 'workspace'],
              ];
              labels.add(hit ? known.find(([selector]) => hit.closest(selector))?.[1] ?? 'other' : 'no-hit');
            }
          }
          return [...labels].sort();
        });
        for (const surface of surfaces) console.error(`Recording disclosure hit after failure: ${surface}`);
      } catch { /* Preserve the first assertion when the page is unavailable. */ }
      throw failure;
    }
    assert.deepEqual(await explanation.locator('[aria-label="Recorded capture limitations"] li').allTextContents(), detail.limitations);
    if (width < 700) await expect(explanation).toContainText(ns === null ?
      'Duration unavailable for this capture' : `Adapter-observed duration ${duration} (measured by the adapter, not verified by X-trace)`);
    await opener.press('Escape');
    await expect(info).toHaveJSProperty('open', false);
    await expect(opener).toBeFocused();
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
    const scope = dialog.getByText(/Only the .* loaded steps .* are searched/);
    await assertLabelUncovered(scope);
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
      const route = summary.locator('.replay-context-route');
      await expect(route).toHaveText('POST /orders');
      assert.ok(await route.evaluate((node) => node.scrollWidth <= node.clientWidth + 1),
        'the complete short request identity fits the phone recording summary');
      const first = await summary.locator('.replay-context-request').boundingBox();
      const second = await summary.locator('.replay-context-event').boundingBox();
      assert.ok(first && second && first.y >= 0 && first.y + first.height <= second.y + 1,
        'phone header places the request above the selected event');
      await expect(page.locator('.topbar')).toBeHidden();
      await expect(more.getByRole('button', { name: 'Step in', exact: true })).toBeFocused();
      const refresh = page.locator('#events-panel').getByRole('button', { name: 'Refresh', exact: true });
      await assertLabelUncovered(refresh);
      assert.ok(await refresh.evaluate(button => {
        const box = button.getBoundingClientRect();
        return box.width >= 44 && box.height >= 44 &&
          [[box.left + 3, box.top + 3], [box.right - 3, box.bottom - 3]].every(
            ([x, y]) => button.contains(document.elementFromPoint(x, y)));
      }), 'Refresh is fully available when phone More opens, before an action can scroll it into view');
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
        // Remember the ordinary guarded reads made by the existing switch proof.
        // The source caller opens a legacy fixture; the installed caller opens a real second capture.
        const knownDetails = new Map();
        const observedReads = [];
        const observedReadErrors = [];
        const observeDetail = response => {
          if (response.request().method() !== 'GET' || !/^\/api\/v1\/recordings\/[^/]+$/.test(new URL(response.url()).pathname)) return;
          observedReads.push((async () => {
            assert.equal(response.status(), 200, 'the existing recording switch receives a guarded detail response');
            const detail = await response.json();
            knownDetails.set(detail.recordingId, detail);
          })().catch(problem => { observedReadErrors.push(problem); }));
        };
        page.on('response', observeDetail);
        try {
          await verifyRecordingSelection({ sequence, activate });
          await Promise.all(observedReads);
          if (observedReadErrors.length) throw observedReadErrors[0];
        } finally {
          page.off('response', observeDetail);
        }
        const activeRecording = await page.locator('#events-panel .center-title h1').textContent();
        const detail = knownDetails.get(activeRecording);
        assert.ok(detail && detail.recordingId === activeRecording, 'the recording bar uses the selected recording read by the existing switch');
        await verifyRecordingBar(detail, width);
        if (width === 320) {
          const tabs = page.getByRole('tablist', { name: 'Open recordings' }).getByRole('tab');
          await expect(tabs).toHaveCount(2);
          const identities = [];
          for (const tab of await tabs.all()) {
            const suffix = tab.locator('.open-recording-id');
            const name = await tab.getAttribute('aria-label');
            await expect(suffix).toHaveText(name.slice(-8));
            await assertLabelUncovered(suffix);
            const route = tab.locator('.open-recording-route');
            await assertLabelUncovered(route);
            assert.ok(await route.evaluate((element) => element.scrollWidth <= element.clientWidth),
              'both open recording choices show their complete route labels at 320px');
            assert.ok(await tab.evaluate((element) => {
              const box = element.getBoundingClientRect();
              return box.width >= 44 && box.height >= 44 &&
                element.contains(document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2));
            }), 'both open recording choices retain full-sized hittable targets');
            identities.push(name.slice(-8));
          }
          assert.equal(new Set(identities).size, 2, 'both open recordings show distinct observed identities');
          const tablist = page.getByRole('tablist', { name: 'Open recordings' });
          const current = tablist.getByRole('tab', { selected: true });
          const currentId = await current.getAttribute('id');
          const original = page.locator(`[id="${currentId}"]`);
          await original.focus();
          async function switchAndVerify(tab, key, recording) {
            const known = knownDetails.get(recording);
            assert.ok(known, 'the original switch proof supplied this recording projection');
            const [reply] = await Promise.all([
              page.waitForResponse(response => response.request().method() === 'GET' &&
                new URL(response.url()).pathname === `/api/v1/recordings/${encodeURIComponent(recording)}`),
              tab.press(key),
            ]);
            assert.equal(reply.status(), 200, 'keyboard selection receives a successful guarded viewer read');
            const detail = await reply.json();
            assert.equal(detail.recordingId, recording, 'keyboard detail belongs to the selected recording');
            assert.deepEqual(detail.events, known.events, 'keyboard selection reads the previously verified recording projection');
            await expect(page.locator('#events-panel').getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
            await expect(page.getByRole('region', { name: 'Loaded event window' }).getByText('Loading event window…', { exact: true })).not.toBeVisible();
            if (detail.events.length === 0) await expect(page.getByText('No projected events', { exact: true })).toBeVisible();
            else await expect(page.getByRole('region', { name: 'Loaded event window' })).toContainText(`${detail.events.length} loaded ${detail.events.length === 1 ? 'event' : 'events'}`);
          }
          const otherRecording = await tablist.getByRole('tab', { selected: false }).getAttribute('id');
          await switchAndVerify(original, 'ArrowRight', otherRecording.replace(/^open-recording-/, ''));
          const other = tablist.getByRole('tab', { selected: true });
          const otherId = await other.getAttribute('id');
          assert.notEqual(otherId, currentId, 'ArrowRight selects the other open recording');
          await expect(other).toBeFocused();
          await expect(page.locator('#events-panel .center-title h1')).toHaveText(otherId.replace(/^open-recording-/, ''));
          await switchAndVerify(other, 'ArrowLeft', currentId.replace(/^open-recording-/, ''));
          await expect(original).toHaveAttribute('aria-selected', 'true');
          await expect(original).toBeFocused();
          await expect(page.locator('#events-panel .center-title h1')).toHaveText(currentId.replace(/^open-recording-/, ''));
          const close = page.locator('.recording-tabs').getByRole('button', { name: 'Close recording', exact: true });
          await expect(close).toBeVisible();
          assert.ok(await close.evaluate((element) => {
            const box = element.getBoundingClientRect();
            return box.width === 44 && box.height === 44 &&
              element.contains(document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2));
          }), 'phone close remains a fixed 44px target beside both recording choices');
          assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
            'two recording choices and close do not widen the phone viewport');
        }
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
          await expect(dialog).toHaveCount(0);
          const opener = pointer === 'fine' ? selected : tools.getByRole('button', {
            name: width < 1280 ? 'Tools' : 'Jump', exact: true,
          });
          await expect(opener).toBeFocused();
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
    const checkDenseReader = pointer === 'coarse' && (width === 1024 || width === 1280);
    if (checkDenseReader) await goto(events.at(-1).sequence);
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
    const verifySelectedReading = async (sequence) => {
      await expect(selected.locator('.event-seq')).toHaveText(sequence);
      await expect(selected.locator('.event-time')).toHaveText(timingBySequence.get(sequence));
      await expect(page.locator('.workspace-inspector')).toHaveAttribute('data-collapsed', 'false');
      await expect(page.locator('.evidence-pane .inspector-tabs')).toBeInViewport();
      const summary = page.locator('.replay-context-event');
      await expect(summary.locator('.mono')).toHaveText(`Event sequence ${sequence}`);
      await expect(summary.locator('span').last()).toHaveText(await selected.locator('.event-kind').textContent());
      await expect(selected).toBeInViewport({ ratio: 1 });
      for (const part of ['.event-seq', '.event-kind', '.event-time']) {
        await assertLabelUncovered(selected.locator(part));
      }
      assert.ok(await selected.evaluate((button) => {
        const b = button.getBoundingClientRect();
        const pane = button.closest('.steps-content').getBoundingClientRect();
        return b.width >= 44 && b.height >= 44 && b.top >= pane.top - 1 && b.bottom <= pane.bottom + 1
          && [b.left + 3, b.right - 3].every(x => [b.top + 3, b.bottom - 3].every(y =>
            button.contains(document.elementFromPoint(x, y))));
      }), 'the selected 44px row is fully reachable inside the Steps reader with Inspector open');
    };
    if (checkDenseReader) await verifySelectedReading(events.at(-1).sequence);
    await verifyRows(page, events.map(({ sequence }) => sequence), timingBySequence);
    if (width === 320) {
      const navigation = page.getByRole('group', { name: 'Replay navigation' });
      const more = navigation.getByRole('button', { name: 'More', exact: true });
      const back = navigation.getByRole('button', { name: 'Back', exact: true });
      const next = navigation.getByRole('button', { name: 'Next', exact: true });
      await goto(events.at(-1).sequence);
      await expect(back).toHaveAttribute('aria-disabled', 'false');
      await expect(next).toHaveAttribute('aria-disabled', 'true');
      const before = await more.boundingBox();
      assert.ok(before);
      for (const action of [back, next]) {
        await action.focus();
        await expect(action).toBeFocused();
        assert.deepEqual(await more.boundingBox(), before, 'changing the focused reason keeps the phone actions stationary');
      }
      if (pointer === 'fine') {
        await selected.focus();
        for (const action of [back, next]) {
          await action.hover();
          assert.deepEqual(await more.boundingBox(), before, 'changing the hovered reason keeps the phone actions stationary');
        }
      }
    }
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
    if (width >= 1280) {
      const views = page.getByRole('tablist', { name: 'Replay view' });
      for (const name of ['Steps', 'Map']) {
        const tab = views.getByRole('tab', { name, exact: true });
        await assertLabelUncovered(tab);
        if (pointer === 'coarse') {
          assert.ok(await tab.evaluate((button) => {
            const box = button.getBoundingClientRect();
            const y = box.top + box.height / 2;
            return box.width >= 44 && box.height >= 44 &&
              [box.left + 1, box.left + box.width / 2, box.right - 1].every((x) =>
                button.contains(document.elementFromPoint(x, y)));
          }), 'the coarse mode tab has a 44px target clear of both neighboring dividers');
        }
      }
    }
    if (checkDenseReader) {
      // The inventory sweep browsed away. Return through real navigation and
      // check the row before any action on it could scroll it into view.
      const back = page.getByRole('group', { name: 'Replay navigation' }).getByRole('button', { name: 'Back', exact: true });
      await activate(back);
      await verifySelectedReading(events.at(-2).sequence);
      await page.keyboard.press('Alt+ArrowDown');
      await verifySelectedReading(events.at(-1).sequence);
    }
    if (width === 736) {
      await expect(page.locator('#events-panel .recording-why')).toHaveJSProperty('open', true);
      const tail = events.at(-1).sequence;
      await goto(tail);
      await verifyMapReturn(page, tail, activate);
      const readableRow = await page.locator('.steps-list .event').evaluateAll((rows) => rows.some((row) => {
        const box = row.getBoundingClientRect();
        const x = box.left + box.width / 2;
        return box.width > 0 && box.height > 0 && [box.top + 1, box.top + box.height / 2, box.bottom - 1]
          .every((y) => row.contains(document.elementFromPoint(x, y)));
      }));
      assert.ok(readableRow, `at least one complete recorded event is exposed with Why expanded at 736px ${pointer}`);
    }
    await saveScreenshot(`viewer-replay-tools-${pointer}-${width}.png`, `loaded-tools-real-Spring-${pointer}`, width, height, page);
    await ensureMore();
    if (width < 1280) {
      await activate(tools.getByRole('button', { name: 'Tools', exact: true }));
      const menu = panel('Tools');
      const actions = ['Filter steps', 'Go to step', 'Jump to…', 'Show timing', 'Close'];
      if (width < 1024) actions.push('Send again…');
      for (const name of actions) {
        await expect(menu.getByRole('button', { name, exact: true })).toBeVisible();
      }
      await expect(menu.getByRole('button', { name: 'Filter steps', exact: true })).toBeFocused();
      await touchTargets(menu);
      assert.ok(await menu.locator('button').evaluateAll((buttons, expected) => buttons.length === expected && buttons.every((button) => {
        const box = button.getBoundingClientRect();
        const panel = button.closest('[role="dialog"]').getBoundingClientRect();
        return box.left >= Math.max(0, panel.left) && box.right <= Math.min(innerWidth, panel.right)
          && box.top >= Math.max(0, panel.top) && box.bottom <= Math.min(innerHeight, panel.bottom)
          && button.contains(document.elementFromPoint((box.left + box.right) / 2, (box.top + box.bottom) / 2));
      }), actions.length), 'compact Tools displays every action fully inside the open panel and viewport');
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
    const compact = width < 1024;
    const inMore = width >= 1024 && width < 1280;
    const toolsOpener = tools.getByRole('button', { name: 'Tools', exact: true });
    const recordingMore = page.locator('.recording-more summary');
    if (inMore) {
      await activate(panel('Tools').getByRole('button', { name: 'Close', exact: true }));
      await activate(recordingMore);
    }
    const planOpener = (compact ? panel('Tools') : page.locator('.replay-context')).getByRole('button', { name: 'Send again…', exact: true });
    await activate(planOpener);
    const planDialog = panel('Send again');
    const planClose = planDialog.getByRole('button', { name: 'Close', exact: true });
    await expect(planClose).toBeFocused();
    const restoreSummary = planDialog.locator('summary').filter({ hasText: 'Open an existing plan' });
    await page.keyboard.press('Shift+Tab');
    await expect(restoreSummary).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(planClose).toBeFocused();
    const revisionField = planDialog.getByLabel('Catalog revision ID', { exact: true });
    await activate(revisionField);
    await expect(revisionField).toBeFocused();
    if (pointer === 'coarse') await activate(planClose);
    else await page.keyboard.press('Escape');
    await expect(planDialog).toHaveCount(0);
    await expect(compact ? toolsOpener : planOpener).toBeFocused();
    if (inMore) await activate(recordingMore);
    if (width < 1280) await activate(toolsOpener);
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

export async function assertReadableTourStep(page) {
  await expect(page.locator('#events-panel .recording-why')).toHaveJSProperty('open', true);
  await assertReadableSelection(page, 'the recorded step sentence remains readable alongside the open disclosure and tour');
}

export async function verifyMapReturn(page, sequence, activate) {
  const views = page.getByRole('tablist', { name: 'Replay view' });
  const map = views.getByRole('tab', { name: 'Map', exact: true });
  const steps = views.getByRole('tab', { name: 'Steps', exact: true });
  const selected = page.locator('#events-panel .event[aria-current="true"]');
  await expect(selected.locator('.event-seq')).toHaveText(sequence);
  await activate(map);
  await expect(map).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('.steps-list')).toHaveCount(0);
  await activate(steps);
  await expect(steps).toHaveAttribute('aria-selected', 'true');
  await expect(selected).toBeFocused();
  // Sample the settled remount, after Chromium delivered the row measurements.
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(selected.locator('.event-seq')).toHaveText(sequence);
  await assertReadableSelection(page, 'the same recorded step sentence is readable after returning from Map');
}

async function assertReadableSelection(page, message) {
  const row = page.locator('#events-panel .event[aria-current="true"]');
  await expect(row).toBeInViewport({ ratio: 1 });
  const readable = await row.locator('.event-kind').evaluate((sentence) => {
    const text = document.createRange();
    text.selectNodeContents(sentence);
    const lines = [...text.getClientRects()].filter((line) => line.width && line.height);
    return lines.length > 0 && lines.every((line) => {
      const y = line.top + line.height / 2;
      return [line.left + 1, line.right - 1].every((x) => sentence.contains(document.elementFromPoint(x, y)));
    });
  });
  assert.ok(readable, message);
}
