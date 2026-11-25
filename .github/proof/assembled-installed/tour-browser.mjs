import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { url, widths, recordingId, result, sourceSha, receiptId } = input;
assert.match(sourceSha, /^[0-9a-f]{40}$/);
assert.match(receiptId, /^[0-9a-f]{64}$/);
assert.deepEqual(widths, [320, 736, 1024, 1440]);
assert.ok(widths.length > 0 && widths.every((width) => [320, 736, 1024, 1440].includes(width)));
const bootstrap = new URL(url);
const origin = bootstrap.origin;
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
assert.match(bootstrap.hash, /^#token=[a-zA-Z0-9_-]{43}$/);
const token = bootstrap.hash.slice(7);
const screenshotRoot = process.env.XTRACE_BROWSER_SCREENSHOT_DIR;
const screenshotDirectory = screenshotRoot && join(screenshotRoot, recordingId ? 'spring-tour' : 'first-recording');
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const browser = await chromium.launch({ headless: true });
let stage = 'bootstrap';
try {
  const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || request.url().includes(token)
      || request.headers().referer?.includes(token)) return route.abort();
    return route.continue();
  });
  const page = await context.newPage();
  await page.clock.install();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  let external = 0;
  let browserErrors = 0;
  let exchanges = 0;
  page.on('pageerror', () => { browserErrors++; });
  page.on('console', (message) => { if (message.type() === 'error') browserErrors++; });
  page.on('request', (request) => {
    if (request.url().includes(token) || request.headers().referer?.includes(token)) external++;
    if (new URL(request.url()).pathname === '/api/v1/auth/exchange') exchanges++;
  });
  page.on('request', (request) => { if (new URL(request.url()).origin !== origin) external += 1; });
  const openRequests = async () => {
    const panel = page.locator('#recordings-panel');
    if (!await panel.isVisible()) {
      const requests = page.getByRole('tab', { name: 'Requests', exact: true });
      if (await requests.isVisible()) await requests.click();
      else await page.locator('#header-requests').click();
    }
    await expect(panel).toBeVisible();
  };
  const showSteps = async () => {
    const tab = page.getByRole('tablist', { name: 'Viewer panes' }).getByRole('tab', { name: 'Steps', exact: true });
    if (await tab.isVisible()) await tab.click();
    else {
      const drawer = page.locator('#header-requests');
      if (await drawer.isVisible() && await drawer.getAttribute('aria-expanded') === 'true') await drawer.click();
    }
  };
  let activeStops = 0;
  let tourHandoffs = 0;
  await page.goto(url);
  for (const width of widths) {
    stage = `verified empty project and tour at ${width}px`;
    await page.setViewportSize({ width, height: 844 });
    if (recordingId) {
      stage = `recorded Spring tour at ${width}px`;
      await openRequests();
      const endpoint = page.locator('.endpoint-card').filter({ hasText: '/orders' });
      if (await endpoint.getAttribute('aria-expanded') === 'false') await endpoint.click();
      await page.locator('.recording-list .recording').filter({ hasText: recordingId }).click();
      await expect(page.getByRole('region', { name: 'No recordings yet' })).toHaveCount(0);
      const current = page.locator('#events-panel .event[aria-current="true"] .event-seq');
      await expect(current).toBeVisible();
      const sequence = await current.textContent();
      const help = page.getByRole('button', { name: 'Help', exact: true });
      await help.press('Enter');
      await page.getByRole('dialog', { name: 'Help' }).getByRole('button', { name: 'Take the 3-step tour' }).press('Enter');
      const guide = page.locator('.viewer-tour');
      for (const title of ['Find a recording', 'Read Steps in order', 'Check what was recorded']) {
        await expect(guide.getByRole('heading', { name: title })).toBeFocused();
        if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `tour-${width}-${title.split(' ')[0]}.png`) });
        const next = guide.getByRole('button', { name: 'Next', exact: true });
        if (await next.isVisible()) await next.press('Enter');
      }
      await guide.getByRole('button', { name: 'Finish', exact: true }).press('Enter');
      await expect(help).toBeFocused();
      await expect(current).toHaveText(sequence);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      const text = await page.locator('body').textContent();
      assert.ok(!text.includes('INSTALLED_TOUR_PRIVATE_BODY') && !text.includes('INSTALLED_TOUR_PRIVATE_QUERY'));
      stage = `installed playback tour Export handoff at ${width}px`;
      await showSteps();
      const replay = page.getByRole('button', { name: 'Replay', exact: true });
      const nextStep = page.getByRole('group', { name: 'Replay navigation' }).getByRole('button', { name: 'Next', exact: true });
      const seen = new Set();
      while (await replay.isDisabled()) {
        const old = await current.innerText();
        assert.ok(!seen.has(old) && await nextStep.isEnabled());
        seen.add(old);
        await nextStep.click();
        await expect(current).not.toHaveText(old);
      }
      const retained = await current.innerText();
      await page.clock.pauseAt(await page.evaluate(() => Date.now() + 1000));
      const exportOpener = page.getByRole('button', { name: 'Export this endpoint…', exact: true });
      const sheet = page.getByRole('dialog', { name: 'Export', exact: true });
      const enterAndCloseExport = async () => {
        await exportOpener.click();
        await expect(sheet).toBeVisible();
        await expect(page.locator('.viewer-tour')).toHaveCount(0);
        await expect(sheet.getByRole('button', { name: 'Close', exact: true })).toBeFocused();
        assert.equal(await sheet.evaluate((dialog) => dialog instanceof HTMLDialogElement && dialog.matches(':modal')), true);
        await expect(page.locator('.replay-start[aria-pressed="true"]')).toHaveCount(0);
        await page.clock.runFor(2001);
        await expect(current).toHaveText(retained);
        await page.keyboard.press('Escape');
        await expect(page.getByRole('dialog')).toHaveCount(0);
        await expect(exportOpener).toBeFocused();
        await page.clock.runFor(2001);
        await expect(current).toHaveText(retained);
        await showSteps();
        await expect(replay).toBeVisible();
        await expect(replay).toHaveAttribute('aria-pressed', 'false');
      };
      await replay.click();
      await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await openRequests();
      // A compact viewport can hide the playing control while Requests is open.
      assert.ok(await page.locator('.replay-start[aria-pressed="true"]').count() > 0);
      await enterAndCloseExport();
      activeStops++;
      await replay.click();
      await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await help.click();
      await page.getByRole('dialog', { name: 'Help' }).getByRole('button', { name: 'Take the 3-step tour' }).click();
      await expect(page.getByRole('dialog', { name: 'Find a recording' }).getByRole('heading')).toBeFocused();
      await enterAndCloseExport();
      tourHandoffs++;
      await page.clock.resume();
      continue;
    }
    const empty = page.getByRole('region', { name: 'No recordings yet' });
    await expect(empty).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
    const copy = empty.getByRole('button', { name: 'Copy example command' });
    assert.ok((await copy.boundingBox())?.height >= 44, 'copy has a full touch target');
    await copy.press('Enter');
    await expect(empty.getByText('Example command copied.')).toBeVisible();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'xtrace run --project-dir ./your-project --java-agent ./xtrace-java-agent.jar -- java -jar ./your-app.jar');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `empty-${width}.png`) });

    const start = empty.getByRole('button', { name: 'Take the 3-step tour' });
    await start.press('Enter');
    const tour = page.getByRole('dialog', { name: 'Find a recording' });
    await expect(tour.getByRole('heading')).toBeFocused();
    await expect(tour.getByText('Step 1 of 3')).toBeVisible();
    for (const [step, title] of [[2, 'Read Steps in order'], [3, 'Check what was recorded']]) {
      await page.getByRole('dialog').getByRole('button', { name: 'Next', exact: true }).press('Enter');
      const coach = page.getByRole('dialog', { name: title });
      await expect(coach.getByRole('heading')).toBeFocused();
      await expect(coach.getByText(`Step ${step} of 3`)).toBeVisible();
      await expect(coach.getByText('Select a recording to see its events and evidence.')).toBeVisible();
      await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
      if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `tour-${width}-step-${step}.png`) });
    }
    const final = page.getByRole('dialog', { name: 'Check what was recorded' });
    await final.getByRole('button', { name: 'Previous' }).press('Enter');
    await expect(page.getByRole('dialog', { name: 'Read Steps in order' }).getByRole('heading')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(start).toBeFocused();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    const help = page.getByRole('button', { name: 'Help', exact: true });
    await help.press('Enter');
    await page.getByRole('dialog', { name: 'Help' }).getByRole('button', { name: 'Take the 3-step tour' }).press('Enter');
    await expect(page.getByRole('dialog', { name: 'Find a recording' }).getByRole('heading')).toBeFocused();
    await page.getByRole('dialog').getByRole('button', { name: 'Next', exact: true }).press('Enter');
    await page.getByRole('dialog').getByRole('button', { name: 'Next', exact: true }).press('Enter');
    await page.getByRole('dialog').getByRole('button', { name: 'Finish', exact: true }).press('Enter');
    await expect(help).toBeFocused();
    await expect(empty).toBeVisible();
  }
  assert.equal(external, 0);
  assert.equal(browserErrors, 0);
  assert.equal(exchanges, 1);
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  await writeFile(result, JSON.stringify({ schema: 1, sourceSha, receiptId, widths,
    scenario: recordingId ? 'selected' : 'empty', frames: 12, handoffs: tourHandoffs, activeStops }) + '\n', { flag: 'wx', mode: 0o600 });
  await context.close();
  console.log(recordingId ? 'recorded Spring Help tour passed' : 'first recording and Help tour passed');
} catch {
  console.error(`First recording browser journey failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
