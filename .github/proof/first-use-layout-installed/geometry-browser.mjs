import assert from 'node:assert/strict';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium, expect } from '@playwright/test';
import { assertEmptyProjectLayout, assertEmptyDesktopTourReturn, assertTextIsReadable } from './scripts/first-recording-layout.mjs';

const { guardViewerWrites } = await import(pathToFileURL(join(process.env.PROOF_SCRIPTS, 'viewer-traffic.mjs')));
const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { url, result, width, receipt, source, shots } = input;
assert.ok([320, 1024, 1440].includes(width));
assert.match(receipt, /^[0-9a-f]{64}$/);
assert.match(source, /^[0-9a-f]{40}$/);
const height = 844;
const bootstrap = new URL(url);
const { origin, hash } = bootstrap;
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
assert.match(hash, /^#token=[a-zA-Z0-9_-]{43}$/);
const token = hash.slice(7);
const state = { width, receipt, source, phase: 'bootstrap' };

async function checkpoint(phase) {
  state.phase = phase;
  await writeFile(result + '.next', JSON.stringify(state), { flag: 'wx', mode: 0o600 });
  await rename(result + '.next', result);
}

await checkpoint('bootstrap');
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 1,
    hasTouch: width === 320,
    serviceWorkers: 'block',
    permissions: ['clipboard-read', 'clipboard-write'],
  });
  let unsafe = 0;
  let errors = 0;
  let exchanges = 0;
  await context.route('**/*', async route => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || request.url().includes(token)
      || request.headers().referer?.includes(token)) {
      unsafe++;
      return route.abort();
    }
    return route.continue();
  });
  await guardViewerWrites(context, origin);
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  page.on('pageerror', () => { errors++; });
  page.on('console', event => { if (event.type() === 'error') errors++; });
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/v1/auth/exchange') exchanges++;
  });

  try {
    await page.goto(url);
    const empty = page.getByRole('region', { name: 'No recordings yet' });
    const panel = page.locator('#recordings-panel');
    await expect(empty).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
    assert.equal(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), width === 320);
    const refresh = panel.getByRole('button', { name: 'Refresh', exact: true });
    const copy = empty.getByRole('button', { name: 'Copy example command', exact: true });
    await checkpoint('copy');
    const command = 'xtrace run --project-dir ./your-project --java-agent ./xtrace-java-agent.jar -- java -jar ./your-app.jar';
    await expect(empty.locator('code')).toHaveText(command);
    await assertTextIsReadable(empty.locator('code'), 'recording command is exposed');
    await expect(empty.locator('code')).toBeInViewport({ ratio: 1 });
    await page.evaluate(value => navigator.clipboard.writeText(value), 'xtrace-first-use-before-copy');
    await copy.evaluate(el => {
      el.__firstUseTrustedCopy = 0;
      el.addEventListener('click', event => { if (event.isTrusted) el.__firstUseTrustedCopy++; });
    });
    await refresh.focus();
    await page.keyboard.press('Tab');
    await expect(copy).toBeFocused();
    await page.keyboard.press('Enter');
    assert.equal(await copy.evaluate(el => el.__firstUseTrustedCopy), 1);
    const feedback = empty.getByText('Example command copied.', { exact: true });
    await expect(feedback).toBeVisible();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), command);
    state.copy = true;

    await checkpoint('frame');
    assert.deepEqual(await page.evaluate(() => [innerWidth, innerHeight, devicePixelRatio]), [width, height, 1]);
    // Files enter private scratch only after a complete native buffer has arrived.
    await writeFile(join(shots, `empty-${width}.png.next`), await page.screenshot({ fullPage: false }),
      { flag: 'wx', mode: 0o600 });
    await rename(join(shots, `empty-${width}.png.next`), join(shots, `empty-${width}.png`));
    state.frame = true;

    await checkpoint('layout');
    await assertEmptyProjectLayout(page, width);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    state.layout = true;

    await checkpoint('tour-return');
    if (width === 1440) {
      await assertEmptyDesktopTourReturn(page);
      await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
      state.tourReturn = true;
    }
    await checkpoint('traffic');
  } finally {
    await context.close();
  }
  assert.deepEqual([unsafe, errors, exchanges], [0, 0, 1]);
  state.traffic = true;
} finally {
  await browser.close();
}
await checkpoint('complete');
