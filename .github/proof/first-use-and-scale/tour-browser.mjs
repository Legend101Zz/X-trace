import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { assertReadableTourStep } from './scripts/replay-tools-journey.mjs';

const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { url, widths, recordingId, result, sourceSha, receiptId } = input;
const events = input.eventGroups.flat().map(([sequence, eventId]) => ({ sequence, eventId }));
assert.ok(recordingId ? events.length > 1 && events.length <= 200 : events.length === 0);
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
  const context = await browser.newContext({ serviceWorkers: 'block', permissions: ['clipboard-read', 'clipboard-write'] });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || request.url().includes(token)
      || request.headers().referer?.includes(token)) return route.abort();
    return route.continue();
  });
  const { pathToFileURL } = await import('node:url');
  const { assertPrivateTextAbsent, manualChoice, nativeDrag, readable } = await import(pathToFileURL(process.env.PROOF_SCRIPTS + '/first-use-controls.mjs').href);
  const { guardViewerWrites } = await import(pathToFileURL(process.env.PROOF_SCRIPTS + '/viewer-traffic.mjs').href);
  await guardViewerWrites(context, origin);
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
  let selectedTabletReads = 0;
  const checked = [];
  async function record(kind, width) {
    assert.ok(!checked.some(row => row.kind === kind && row.width === width));
    checked.push({kind, width});
    await writeFile(result + '.' + kind + '-' + width, JSON.stringify({receiptId, sourceSha, width, kind}), {flag:'wx',mode:0o600});
  }
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
      const sequence = events[0].sequence;
      await expect(current).toHaveText(sequence);
      await expect(page.locator('#events-panel .center-title h1')).toHaveText(recordingId);
      const views = page.getByRole('tablist', {name:'Replay view'});
      const map = views.getByRole('tab', {name:'Map',exact:true});
      await map.press('Enter');
      await expect(map).toHaveAttribute('aria-selected','true');
      const help = page.getByRole('button', { name: 'Help', exact: true });
      await help.press('Enter');
      await page.getByRole('dialog', { name: 'Help' }).getByRole('button', { name: 'Take the 3-step tour' }).press('Enter');
      const guide = page.locator('.viewer-tour');
      for (const title of ['Find a recording', 'Read Steps in order', 'Check what was recorded']) {
        await expect(guide.getByRole('heading', { name: title })).toBeFocused();
        if (title === 'Read Steps in order') {
          await expect(views.getByRole('tab',{name:'Steps',exact:true})).toHaveAttribute('aria-selected','true');
          await expect(current).toHaveText(sequence);
        }
        if (title === 'Check what was recorded') {
          const missing = page.getByRole('tablist', {name:'Inspector evidence'}).getByRole('tab',{name:/^Missing/});
          await expect(missing).toHaveAttribute('aria-selected','true');
          const heading = page.getByRole('region',{name:'Loaded window missing evidence'}).getByRole('heading');
          await readable(heading, expect);
        }
        if (width === 736 && title === 'Read Steps in order') {
          await expect(page.locator('#events-panel .center-title h1')).toHaveText(recordingId);
          await expect(current).toHaveText(sequence);
          await assertReadableTourStep(page);
          selectedTabletReads++;
        }
        await assertPrivateTextAbsent(page);
        if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `tour-${width}-${title.split(' ')[0]}.png`) });
        if (title === 'Check what was recorded') {
          await manualChoice(page, width, guide, current, events, expect);
          await record('manual', width);
        }
        const next = guide.getByRole('button', { name: 'Next', exact: true });
        if (await next.isVisible()) await next.press('Enter');
      }
      await guide.getByRole('button', { name: 'Finish', exact: true }).press('Enter');
      await expect(help).toBeFocused();
      await expect(current).toHaveText(sequence);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await assertPrivateTextAbsent(page);
      await record('selected', width);
      continue;
    }
    const empty = page.getByRole('region', { name: 'No recordings yet' });
    await expect(empty).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
    const copy = empty.getByRole('button', { name: 'Copy example command' });
    const panel = page.locator('#recordings-panel');
    const guideBounds = await empty.boundingBox();
    const exportBounds = await panel.getByRole('button',{name:'Export endpoints…'}).boundingBox();
    assert.ok(guideBounds && exportBounds && guideBounds.y + guideBounds.height <= exportBounds.y);
    if (width >= 1024) assert.ok(guideBounds.width >= width * 0.30);
    await readable(empty.locator('code'), expect);
    await panel.getByRole('button',{name:'Refresh'}).focus();
    await page.keyboard.press('Tab');
    await expect(copy).toBeFocused();
    assert.ok((await copy.boundingBox())?.height >= 44, 'copy has a full touch target');
    await copy.press('Enter');
    const feedback = empty.getByText('Example command copied.');
    await expect(feedback).toBeVisible();
    if (width === 1024) {
      assert.ok(await feedback.evaluate((label) => {
        const range = document.createRange();
        range.selectNodeContents(label);
        const pane = label.closest('#recordings-panel').getBoundingClientRect();
        const lines = [...range.getClientRects()].filter((line) => line.width && line.height);
        return lines.length > 0 && lines.every((line) => {
          const y = line.top + line.height / 2;
          return line.left >= pane.left && line.right <= pane.right && line.top >= pane.top && line.bottom <= pane.bottom
            && [line.left + 1, line.right - 1].every((x) => label.contains(document.elementFromPoint(x, y)));
        });
      }), 'the Requests drawer contains every line of the copy confirmation');
      const steps = page.locator('#events-panel');
      const divider = await page.getByRole('separator', { name: 'Resize Requests' }).boundingBox();
      const panel = await steps.boundingBox();
      assert.ok(divider && panel && panel.x >= divider.x + divider.width,
        'the first-use Requests drawer leaves the Steps pane unobstructed');
      for (const text of ['No recording selected', 'Choose a linked or unmatched recording in Requests.']) {
        const label = steps.getByText(text, { exact: true });
        await expect(label).toBeVisible();
        assert.ok(await label.evaluate(element => {
          const range = document.createRange();
          range.selectNodeContents(element);
          const lines = [...range.getClientRects()].filter(rect => rect.width && rect.height);
          return lines.length > 0 && lines.every(rect => [rect.left + 1, rect.right - 1].every(x =>
            element.contains(document.elementFromPoint(x, rect.top + rect.height / 2))));
        }), 'every line of the empty Steps instruction is readable next to Requests');
      }
    }
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
    await record('empty',width);
  }
  assert.equal(selectedTabletReads, recordingId ? 1 : 0);
  const assertBrowserHealth = () => {
    assert.equal(external, 0);
    assert.equal(browserErrors, 0);
    assert.equal(exchanges, 1);
  };
  assertBrowserHealth();
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  if (recordingId) {
    for (const width of [1024,1440]) {
      stage = `native interrupted panel size at ${width}px`;
      await nativeDrag(page, width, expect);
      await record('drag',width);
    }
  }
  await context.close();
  assertBrowserHealth();
  await writeFile(result, JSON.stringify({ schema: 1, sourceSha, receiptId, widths,
    scenario: recordingId ? 'selected' : 'empty', frames: 12, checked, selectedTabletReads }) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(recordingId ? 'recorded Spring Help tour passed' : 'first recording and Help tour passed');
} catch {
  console.error(`First recording browser journey failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
