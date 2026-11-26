import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

export async function assertTextIsReadable(locator, message) {
  assert.ok(await locator.evaluate((element) => {
    const range = document.createRange();
    range.selectNodeContents(element);
    const lines = [...range.getClientRects()].filter((line) => line.width && line.height);
    return lines.length > 0 && lines.every((line) => [line.left + 1, line.right - 1].every((x) =>
      element.contains(document.elementFromPoint(x, line.top + line.height / 2))));
  }), message);
}

function controls(page, width) {
  const panel = page.locator('#recordings-panel');
  const button = (name) => panel.getByRole('button', { name, exact: true });
  const refresh = button('Refresh');
  const copy = button('Copy example command');
  const tour = button('Take the 3-step tour');
  const actions = [copy, tour, button('Export endpoints…')];
  const sidebar = [panel.getByRole('searchbox'), button('Observed endpoints'), button('Not linked to an endpoint')];
  return { copy, tour, order: width >= 1200 ? [...sidebar, refresh, ...actions] : [refresh, ...actions, ...sidebar] };
}

async function assertExposed(locator, target = false) {
  await expect(locator).toBeInViewport({ ratio: 1 });
  const result = await locator.evaluate((element) => {
    const r = element.getBoundingClientRect();
    const points = [
      [r.left + r.width / 2, r.top + r.height / 2],
      [r.left + 4, r.top + 4], [r.right - 4, r.top + 4],
      [r.left + 4, r.bottom - 4], [r.right - 4, r.bottom - 4],
    ];
    return {
      fits: r.width > 0 && r.height > 0 && r.left >= 0 && r.top >= 0 && r.right <= innerWidth && r.bottom <= innerHeight,
      exposed: points.every(([x, y]) => element.contains(document.elementFromPoint(x, y))),
      sized: r.width >= 44 && r.height >= 44,
    };
  });
  assert.ok(result.fits && result.exposed, 'the full bounds fit the viewport and all five hit points reach the element');
  if (target) assert.ok(result.sized, 'the control has a 44 × 44 pixel or larger hit target');
}

async function assertVisibleFocus(locator) {
  await expect(locator).toBeFocused();
  assert.ok(await locator.evaluate((element) => {
    const css = getComputedStyle(element);
    return element.matches(':focus-visible') && !['none', 'hidden'].includes(css.outlineStyle)
      && Number.parseFloat(css.outlineWidth) >= 1 && css.outlineColor !== 'transparent';
  }), 'keyboard focus has a visible outline');
  await assertExposed(locator, true);
}

async function checkTabOrder(page, width) {
  const { copy, order } = controls(page, width);
  const start = order.indexOf(copy);
  await assertVisibleFocus(copy);
  // Walk from the real keyboard Copy action to both ends and back. Do not set focus for a passing result.
  for (let i = start - 1; i >= 0; i--) {
    await page.keyboard.press('Shift+Tab');
    await assertVisibleFocus(order[i]);
  }
  for (let i = 1; i < order.length; i++) {
    await page.keyboard.press('Tab');
    await assertVisibleFocus(order[i]);
  }
  for (let i = order.length - 2; i >= start; i--) {
    await page.keyboard.press('Shift+Tab');
    await assertVisibleFocus(order[i]);
  }
}

// Call after genuine Copy on an empty project. First inspect the untouched viewport.
// At shorter heights content may scroll; require readable blocks and reachable controls individually.
export async function assertEmptyProjectLayout(page, width) {
  if (![320, 1024, 1440].includes(width)) return;
  const tall = await page.evaluate(() => innerHeight >= 844);
  const panel = page.locator('#recordings-panel');
  const card = panel.getByRole('region', { name: 'No recordings yet' });
  const blocks = card.locator('h2, p, code');
  if (tall) await assertExposed(card);
  for (const block of await blocks.all()) {
    if (!tall) await block.scrollIntoViewIfNeeded();
    await assertTextIsReadable(block, 'every line of the visible first-use instructions and feedback is readable');
  }
  if (tall) {
    for (const control of controls(page, width).order) await assertExposed(control, true);
  }
  if (width === 320) {
    const choices = panel.locator('.catalog-switch button');
    await expect(choices).toHaveCount(2);
    const footer = await page.locator('.viewer-preferences').boundingBox();
    assert.ok(footer);
    for (const choice of await choices.all()) {
      if (!tall) await choice.scrollIntoViewIfNeeded();
      const bounds = await choice.boundingBox();
      assert.ok(bounds && bounds.width >= 44 && bounds.height >= 44 && bounds.y + bounds.height <= footer.y,
        'each reachable empty catalog choice fits above the phone status bar after Copy');
      await assertExposed(choice, true);
      await assertTextIsReadable(choice, 'the phone catalog choice text is exposed');
    }
  }
  if (width === 1440) {
    const sidebar = await page.getByRole('separator', { name: 'Resize Requests' }).boundingBox();
    const workspace = await page.locator('.viewer-workspace').boundingBox();
    const bounds = await card.boundingBox();
    assert.ok(sidebar && workspace && bounds);
    const mainLeft = sidebar.x + sidebar.width;
    const mainRight = workspace.x + workspace.width;
    assert.ok(bounds.x >= mainLeft && bounds.x + bounds.width <= mainRight
      && Math.abs(bounds.x + bounds.width / 2 - (mainLeft + mainRight) / 2) <= 2,
      'the first-use command is centered in the main area next to Requests');
  }
  if (width === 1024) {
    const note = panel.locator('aside.context-note');
    if (!tall) await note.scrollIntoViewIfNeeded();
    await assertExposed(note);
    await assertTextIsReadable(note, 'every line of the evidence disclaimer fits in the open Requests drawer');
  }
  if (!tall) await controls(page, width).copy.scrollIntoViewIfNeeded();
  await checkTabOrder(page, width);
}

export async function assertDesktopTourFocusRestored(page) {
  const { copy, tour } = controls(page, 1440);
  await expect(page.locator('.viewer-workspace')).not.toHaveAttribute('data-tour-pane', /.+/);
  await assertVisibleFocus(tour);
  await page.keyboard.press('Shift+Tab');
  await assertVisibleFocus(copy);
  await page.keyboard.press('Tab');
  await assertVisibleFocus(tour);
}

// Standalone three-width qualification can check the transition without replaying all tour steps.
export async function assertEmptyDesktopTourReturn(page) {
  const { copy, tour } = controls(page, 1440);
  await expect(copy).toBeFocused();
  await page.keyboard.press('Tab');
  await assertVisibleFocus(tour);
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog', { name: 'Find a recording' }).getByRole('heading')).toBeFocused();
  await expect(page.locator('.viewer-workspace')).toHaveAttribute('data-tour-pane', 'recordings');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await assertDesktopTourFocusRestored(page);
}
