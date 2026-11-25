import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { url } = JSON.parse(Buffer.concat(chunks).toString());
const origin = new URL(url).origin;
const screenshotRoot = process.env.XTRACE_BROWSER_SCREENSHOT_DIR;
const screenshotDirectory = screenshotRoot && join(screenshotRoot, 'first-recording');
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const browser = await chromium.launch({ headless: true });
let stage = 'bootstrap';
try {
  const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  let external = 0;
  page.on('request', (request) => { if (new URL(request.url()).origin !== origin) external += 1; });
  await page.goto(url);
  for (const width of [320, 736, 1024, 1440]) {
    stage = `verified empty project and tour at ${width}px`;
    await page.setViewportSize({ width, height: 844 });
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
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  console.log('first recording and Help tour passed at 320, 736, 1024 and 1440px');
} catch {
  console.error(`First recording browser journey failed during ${stage}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
