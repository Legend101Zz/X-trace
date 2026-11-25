import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

const viewports = [[320, 640], [736, 900], [1024, 768], [1440, 900]];

export async function jumpToLoadedSequence(page, sequence) {
  const controls = page.getByRole('region', { name: 'Loaded event window' });
  await controls.getByRole('textbox', { name: 'Loaded event sequence', exact: true }).fill(sequence);
  await controls.getByRole('button', { name: 'Go to event', exact: true }).press('Enter');
  const current = page.locator('#events-panel .event[aria-current="true"]');
  await expect(current).toBeFocused();
  await expect(current.locator('.event-seq')).toHaveText(sequence);
}

/** Sweep the full loaded list, comparing every mounted position against independent API order. */
export async function verifyMountedWindow(page, expected) {
  const list = page.getByRole('list', { name: 'Loaded replay steps' });
  await expect(page.getByText(`${expected.length} ordered events`, { exact: true })).toBeVisible();
  const covered = new Set();
  let peakMountedRows = 0;
  for (let sweep = 0; sweep <= expected.length && covered.size < expected.length; sweep += 1) {
    const mounted = await list.evaluate(async (element, reset) => {
      const body = element.closest('.steps-content');
      const owner = body && getComputedStyle(body).overflowY === 'auto' ? body : element.closest('#events-panel');
      if (reset) owner.scrollTop = 0;
      else owner.scrollTop += Math.max(1, Math.floor(owner.clientHeight * 0.75));
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      return Array.from(element.querySelectorAll('[data-step-sequence]'), (row) => ({
        sequence: row.dataset.stepSequence,
        position: Number(row.getAttribute('aria-posinset')),
        count: Number(row.getAttribute('aria-setsize')),
      }));
    }, sweep === 0);
    assert.ok(mounted.length > 0 && mounted.length <= 80, 'Steps obeys the mounted row cap');
    peakMountedRows = Math.max(peakMountedRows, mounted.length);
    for (const { sequence, position, count } of mounted) {
      assert.ok(count === expected.length && expected[position - 1] === sequence, 'mounted position and sequence match the read API');
      covered.add(position);
    }
  }
  assert.equal(covered.size, expected.length, 'scrolling exposes every API event in the loaded window');
  return peakMountedRows;
}

async function pageWithoutMovingAnchor(page, button, expectedCount) {
  const current = page.locator('#events-panel .event[aria-current="true"]');
  await current.scrollIntoViewIfNeeded();
  const list = page.getByRole('list', { name: 'Loaded replay steps' });
  const anchor = (originalSequence = null) => list.evaluate((element, originalSequence) => {
    const body = element.closest('.steps-content');
    const owner = body && getComputedStyle(body).overflowY === 'auto' ? body : element.closest('#events-panel');
    const viewport = owner.getBoundingClientRect();
    const rows = [...element.querySelectorAll('[data-step-sequence]')];
    const intersectsViewport = (node) => {
      const box = node.getBoundingClientRect();
      return box.height > 0 && box.bottom > viewport.top && box.top < viewport.bottom;
    };
    const first = rows.find(intersectsViewport);
    const placeholderVisible = [...element.querySelectorAll('.steps-spacer')].some(intersectsViewport);
    const original = originalSequence === null ? first : rows.find((row) => row.dataset.stepSequence === originalSequence);
    const offset = (row) => row ? Math.round((row.getBoundingClientRect().top - viewport.top) * 10) / 10 : null;
    return {
      sequence: first?.dataset.stepSequence ?? null,
      exactOffset: first ? first.getBoundingClientRect().top - viewport.top : null,
      geometry: {
        sameFirst: first != null && first === original,
        originalMounted: original != null,
        sameSelection: original?.querySelector('.event[aria-current="true"]') != null,
        firstOffset: offset(first),
        originalOffset: offset(original),
        ownerTop: Math.round(viewport.top),
        ownerHeight: owner.clientHeight,
        ownerBorderTop: owner.clientTop,
        scrollTop: Math.round(owner.scrollTop),
        scrollHeight: owner.scrollHeight,
        pageScrollTop: Math.round(window.scrollY),
        listTop: Math.round(element.getBoundingClientRect().top - viewport.top),
        mountedRows: rows.length,
        placeholderVisible,
        desktopScrollOwner: owner === body,
      },
    };
  }, originalSequence);
  const samples = {};
  try {
    // A scroll can reveal an overscan placeholder before React mounts the actual rows.
    // Sample only once the viewport intersects a real row and no virtual spacer.
    let original;
    await expect.poll(async () => {
      original = await anchor();
      samples.lastReadiness = original.geometry;
      return original.sequence !== null && !original.geometry.placeholderVisible;
    }).toBe(true);
    samples.beforeFocus = original.geometry;
    await button.evaluate((node) => node.focus({ preventScroll: true }));
    samples.afterFocus = (await anchor(original.sequence)).geometry;
    await page.keyboard.press('Enter');
    samples.afterPagingKey = (await anchor(original.sequence)).geometry;
    await expect(page.getByText(`${expectedCount} ordered events`, { exact: true })).toBeVisible();
    await expect.poll(async () => {
      const now = await anchor(original.sequence);
      samples.final = now.geometry;
      return !now.geometry.placeholderVisible && now.sequence === original.sequence
        && Math.abs(now.exactOffset - original.exactOffset) <= 2;
    }).toBe(true);
  } catch (error) {
    error.anchorGeometry = samples;
    throw error;
  }
}

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
    const selection = () => page.locator('#events-panel .event[aria-current="true"] .event-seq').textContent();
    await verifyMountedWindow(page, current);
    const previous = controls.getByRole('button', { name: 'Load earlier', exact: true });
    await pageWithoutMovingAnchor(page, previous, earlier.length + current.length);
    await verifyMountedWindow(page, [...earlier, ...current]);
    assert.ok(await selection() === selected, 'earlier paging preserves the selected event');
    const next = controls.getByRole('button', { name: 'Load later', exact: true });
    await pageWithoutMovingAnchor(page, next, earlier.length + current.length + later.length);
    await verifyMountedWindow(page, [...earlier, ...current, ...later]);
    assert.ok(await selection() === selected, 'later paging preserves the selected event');
    await jumpToLoadedSequence(page, earlier[0]);
    assert.ok(await selection() === earlier[0], 'a loaded predecessor event is keyboard-selectable');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `replay window controls fit at ${width}px`);
  }
}
