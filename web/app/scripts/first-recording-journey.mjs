import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { assertReadableTourStep } from './replay-tools-journey.mjs';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { url, widths = [320, 736, 1024, 1440], recordingId } = JSON.parse(Buffer.concat(chunks).toString());
assert.ok(widths.length > 0 && widths.every((width) => [320, 736, 1024, 1440].includes(width)));
const origin = new URL(url).origin;
const screenshotRoot = process.env.XTRACE_BROWSER_SCREENSHOT_DIR;
const screenshotDirectory = screenshotRoot && join(screenshotRoot, recordingId ? 'spring-tour' : 'first-recording');
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const browser = await chromium.launch({ headless: true });
let stage = 'bootstrap';
try {
  const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  let external = 0;
  page.on('request', (request) => { if (new URL(request.url()).origin !== origin) external += 1; });
  await page.goto(url);
  for (const width of widths) {
    stage = `verified empty project and tour at ${width}px`;
    await page.setViewportSize({ width, height: 844 });
    if (recordingId) {
      stage = `recorded Spring tour at ${width}px`;
      const requests = page.getByRole('tab', { name: 'Requests', exact: true });
      if (await requests.isVisible()) await requests.click();
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
        if (width === 736 && title === 'Read Steps in order') await assertReadableTourStep(page);
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
      continue;
    }
    const empty = page.getByRole('region', { name: 'No recordings yet' });
    await expect(empty).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Open recordings' })).toHaveCount(0);
    const copy = empty.getByRole('button', { name: 'Copy example command' });
    assert.ok((await copy.boundingBox())?.height >= 44, 'copy has a full touch target');
    await copy.press('Enter');
    const feedback = empty.getByText('Example command copied.');
    await expect(feedback).toBeVisible();
    if (width === 1024) {
      const feedbackPosition = await feedback.evaluate((label) => {
        const range = document.createRange();
        range.selectNodeContents(label);
        const pane = label.closest('#recordings-panel').getBoundingClientRect();
        const lines = [...range.getClientRects()].filter((line) => line.width && line.height);
        if (!lines.length) return 'no-lines';
        for (const line of lines) {
          if (line.left < pane.left || line.right > pane.right) return 'outside-inline';
          if (line.top < pane.top || line.bottom > pane.bottom) return 'outside-block';
          const y = line.top + line.height / 2;
          if (![line.left + 1, line.right - 1].every((x) => label.contains(document.elementFromPoint(x, y)))) {
            return 'covered';
          }
        }
        return 'inside';
      });
      if (feedbackPosition !== 'inside') console.error(`First recording drawer feedback: ${feedbackPosition}`);
      assert.equal(feedbackPosition, 'inside', 'the Requests drawer contains every line of the copy confirmation');
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
  }
  assert.equal(external, 0);
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  console.log(recordingId ? 'recorded Spring Help tour passed' : 'first recording and Help tour passed');
} catch (error) {
  const location = error?.stack?.match(/first-recording-journey\.mjs:(\d{1,5}):(\d{1,5})/);
  if (location) console.error(`First recording source location: ${location[1]}:${location[2]}`);
  console.error(`First recording browser journey failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
