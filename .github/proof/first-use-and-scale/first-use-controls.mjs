import assert from 'node:assert/strict';

// Standalone wrapper modules do not resolve dependencies from the product checkout.
// The browser entry point supplies Playwright's existing expect.
export async function readable(locator, expect) {
  await expect(locator).toBeInViewport({ ratio: 1 });
  assert.ok(await locator.evaluate(element => {
    const range = document.createRange();
    range.selectNodeContents(element);
    const lines = [...range.getClientRects()].filter(line => line.width && line.height);
    return lines.length > 0 && lines.every(line => [line.left + 1, line.right - 1].every(x =>
      element.contains(document.elementFromPoint(x, line.top + line.height / 2))));
  }));
}

export async function assertPrivateTextAbsent(page) {
  const text = await page.locator('body').textContent();
  assert.ok(!text.includes('INSTALLED_TOUR_PRIVATE_BODY') && !text.includes('INSTALLED_TOUR_PRIVATE_QUERY'));
}

export async function manualChoice(page, width, guide, current, events, expect) {
  const tabs = page.getByRole('tablist', { name: 'Inspector evidence' });
  const missing = tabs.getByRole('tab', { name: /^Missing/ });
  const details = tabs.getByRole('tab', { name: 'Details', exact: true });
  await missing.press('End');
  await expect(details).toBeFocused();
  const panes = page.getByRole('tablist', { name: 'Viewer panes' });
  const showPane = async name => {
    if (await panes.isVisible()) await panes.getByRole('tab', { name, exact: true }).press('Enter');
  };
  const inspect = async event => {
    await showPane('Inspector');
    await expect(details).toHaveAttribute('aria-selected', 'true');
    const identity = page.getByRole('region', {name: 'Event details'}).locator('[data-event-field="event-id"]');
    await expect(identity).toBeVisible();
    await expect(identity).toHaveText(event.eventId);
    await assertPrivateTextAbsent(page);
  };
  await inspect(events[0]);
  await showPane('Steps');
  const controls = page.getByRole('group', { name: 'Replay navigation' });
  const next = controls.getByRole('button', { name: 'Next', exact: true });
  const back = controls.getByRole('button', { name: 'Back', exact: true });
  await expect(current).toHaveText(events[0].sequence);
  await expect(next).toBeEnabled();
  await next.press('Enter');
  await expect(current).toHaveText(events[1].sequence);
  await inspect(events[1]);
  await showPane('Steps');
  await expect(back).toBeEnabled();
  await back.press('Enter');
  await expect(current).toHaveText(events[0].sequence);
  await inspect(events[0]);
  await page.setViewportSize({ width: width >= 861 ? 320 : 1440, height: 844 });
  await inspect(events[0]);
  await page.setViewportSize({ width, height: 844 });
  await inspect(events[0]);
  await guide.getByRole('button', { name: 'Previous', exact: true }).press('Enter');
  await guide.getByRole('button', { name: 'Next', exact: true }).press('Enter');
  await expect(missing).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('region', { name: 'Loaded window missing evidence' })).toBeVisible();
  await assertPrivateTextAbsent(page);
  await expect(guide.getByRole('heading', { name: 'Check what was recorded' })).toBeFocused();
}

export async function nativeDrag(page, width, expect) {
  await page.setViewportSize({ width, height: 844 });
  const inspector = page.getByRole('separator', { name: 'Resize Inspector' });
  const initial = await inspector.getAttribute('aria-valuenow');
  assert.ok(Number(initial) > 0);
  await inspector.press('Enter');
  await expect(inspector).toHaveAttribute('aria-valuenow', '0');
  const stored = () => page.evaluate(() => {
    const key = 'xtrace.viewer.panels';
    assertOnlyLayout();
    return localStorage.getItem(key);
    function assertOnlyLayout() {
      if (localStorage.length !== 1 || !localStorage.getItem(key) || sessionStorage.length !== 0) {
        throw new Error('unexpected persisted preferences');
      }
    }
  });
  const collapsed = await stored();
  assert.equal(JSON.parse(collapsed).inspector, 0);
  const help = page.getByRole('button', { name: 'Help', exact: true });
  await help.press('Enter');
  await page.getByRole('dialog', { name: 'Help' }).getByRole('button', { name: 'Take the 3-step tour' }).press('Enter');
  const guide = page.locator('.viewer-tour');
  await guide.getByRole('button', { name: 'Next', exact: true }).press('Enter');
  await guide.getByRole('button', { name: 'Next', exact: true }).press('Enter');
  await expect(inspector).toHaveAttribute('aria-valuenow', initial);
  await inspector.evaluate(element => {
    const seen = {pointerId: null, got: 0, lost: 0, cancel: 0};
    element.__nativeDragProof = seen;
    for (const [event, key] of [['gotpointercapture', 'got'], ['lostpointercapture', 'lost'], ['pointercancel', 'cancel']]) {
      element.addEventListener(event, input => {
        if (input.isTrusted) { seen.pointerId = input.pointerId; seen[key]++; }
      });
    }
  });
  const input = await page.context().newCDPSession(page);
  try {
    for (const kind of ['capture-loss', 'touch-cancel']) {
      const observed = () => inspector.evaluate(element => ({...element.__nativeDragProof}));
      const base = await observed();
      const box = await inspector.boundingBox();
      assert.ok(box && box.width > 1 && box.height > 1);
      const point = { x: Math.floor(box.x + box.width / 2), y: Math.floor(box.y + box.height / 2) };
      // Actual browser hit-testing picks the splitter; no synthetic DOM event is dispatched.
      assert.ok(await inspector.evaluate((e, p) => e.contains(document.elementFromPoint(p.x, p.y)), point));
      if (kind === 'capture-loss') {
        await page.mouse.move(point.x, point.y);
        await page.mouse.down();
        try {
          await page.mouse.move(point.x, point.y - 32);
          await expect(inspector).not.toHaveAttribute('aria-valuenow', initial);
          await expect.poll(async () => (await observed()).got).toBe(base.got + 1);
          await inspector.evaluate(el => el.releasePointerCapture(el.__nativeDragProof.pointerId));
          await page.mouse.move(point.x, point.y - 35);
          await expect.poll(async () => (await observed()).lost).toBe(base.lost + 1);
        } finally { await page.mouse.up(); }
      } else {
        await input.send('Emulation.setTouchEmulationEnabled', {enabled: true, maxTouchPoints: 1});
        try {
          await input.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [{...point, id: 1}]});
          await input.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: [{x: point.x, y: point.y - 32, id: 1}]});
          await expect(inspector).not.toHaveAttribute('aria-valuenow', initial);
          await expect.poll(async () => (await observed()).got).toBe(base.got + 1);
          await input.send('Input.dispatchTouchEvent', {type: 'touchCancel', touchPoints: []});
          await expect.poll(async () => (await observed()).cancel).toBe(base.cancel + 1);
          await expect.poll(async () => (await observed()).lost).toBe(base.lost + 1);
        } finally { await input.send('Emulation.setTouchEmulationEnabled', {enabled: false}); }
      }
      await expect(inspector).toHaveAttribute('aria-valuenow', initial);
      assert.equal(await stored(), collapsed);
    }
  } finally { await input.detach(); }
  await guide.getByRole('button', { name: 'Finish', exact: true }).press('Enter');
  await expect(inspector).toHaveAttribute('aria-valuenow', '0');
  assert.equal(await stored(), collapsed);
  // The next width uses the restored panel. This also verifies the saved open size.
  await inspector.press('Enter');
  await expect(inspector).toHaveAttribute('aria-valuenow', initial);
  assert.equal(JSON.parse(await stored()).inspector, Number(initial));
}
