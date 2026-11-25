import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

const viewports = [[320, 640], [736, 900], [1024, 768], [1440, 900]];

/**
 * The supplied opener uses a real persisted recording, opens a noninitial
 * window with both server continuations, and returns independently read API
 * sequences for its predecessor, the starting page and its successor.
 */
export async function verifyReplayWindowNavigation(page, openInterior) {
  for (const [width, height] of viewports) {
    await page.setViewportSize({ width, height });
    const { earlier, current, later, selected } = await openInterior(page);
    assert.ok(earlier.length && current.includes(selected) && later.length, 'fixture must have both real adjacent pages and a selected event');
    const controls = page.getByRole('region', { name: 'Loaded event window' });
    const order = () => page.locator('#events-panel .event-seq').allTextContents();
    const selection = () => page.locator('#events-panel .event[aria-current="true"] .event-seq').textContent();
    const matches = async (expected) => JSON.stringify(await order()) === JSON.stringify(expected);
    assert.ok(await matches(current), 'the visible starting window matches the read API');
    const previous = controls.getByRole('button', { name: 'Load earlier', exact: true });
    await previous.press('Enter');
    await expect.poll(() => matches([...earlier, ...current])).toBe(true);
    assert.ok(await selection() === selected, 'earlier paging preserves the selected event');
    await controls.getByRole('button', { name: 'Load later', exact: true }).press('Enter');
    await expect.poll(() => matches([...earlier, ...current, ...later])).toBe(true);
    assert.ok(await selection() === selected, 'later paging preserves the selected event');
    const form = controls.getByRole('textbox', { name: 'Loaded event sequence', exact: true });
    await form.fill(earlier[0]);
    await controls.getByRole('button', { name: 'Go to event', exact: true }).press('Enter');
    await expect(page.locator('#events-panel .event[aria-current="true"]')).toBeFocused();
    assert.ok(await selection() === earlier[0], 'a loaded predecessor event is keyboard-selectable');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `replay window controls fit at ${width}px`);
  }
}
