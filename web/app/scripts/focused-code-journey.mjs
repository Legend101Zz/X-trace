import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { url, recordingId } = JSON.parse(Buffer.concat(chunks).toString());
assert.ok(url && recordingId, 'focused viewer context is required');
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const screenshotDirectory = process.env.XTRACE_FOCUSED_SCREENSHOT_DIR;
  if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
  page.setDefaultTimeout(8000);
  const origin = new URL(url).origin;
  let externalRequests = 0;
  let browserErrors = 0;
  page.on('request', (request) => { if (new URL(request.url()).origin !== origin) externalRequests += 1; });
  page.on('pageerror', () => { browserErrors += 1; });
  page.on('console', (message) => { if (message.type() === 'error') browserErrors += 1; });
  await page.goto(url);
  await page.locator('.endpoint-card').first().waitFor();
  const detail = await page.evaluate(async (id) => {
    const response = await fetch(`/api/v1/recordings/${encodeURIComponent(id)}?limit=200`, { headers: { 'X-XTrace-Client': 'viewer-v1' } });
    if (!response.ok) throw new Error('focused recording read API failed');
    return response.json();
  }, recordingId);
  const allText = JSON.stringify(detail);
  const canaries = ['BODY_CANARY_1D4', 'AUTH_CANARY_1D4', 'COOKIE_CANARY_1D4', 'PATH_QUERY_CANARY_1E2'];
  assert.ok(canaries.every((canary) => !allText.includes(canary)), 'private limits hold on the focused read API');
  const index = detail.events.findIndex((event) => event.kind === 'recording_event_kind:line_cursor'
    && event.line > 0 && event.source?.status === 'matched'
    && event.bindings.some((binding) => binding.role === 'local' && binding.name === 'descriptionPresent' && binding.value.state === 'captured'));
  if (index < 0) {
    const declaredGap = detail.events.some((event) => event.gap?.reason === 'class_not_transformed');
    throw new Error(`focused Spring recording lacks a matched positive line with its captured descriptionPresent local (declared transform gap: ${declaredGap})`);
  }
  const event = detail.events[index];
  const local = event.bindings.find(({ name, role }) => name === 'descriptionPresent' && role === 'local');
  const text = event.source.excerpt?.split('\n')[event.line - event.source.startLine];
  assert.ok(typeof text === 'string', 'the captured cursor has a retained source row');
  await page.locator('.endpoint-card').first().click();
  await page.getByRole('button', { name: new RegExp(recordingId) }).click();

  for (const [width, height] of [[320, 640], [736, 900], [1024, 768], [1440, 900]]) {
    await page.setViewportSize({ width, height });
    const steps = page.getByRole('tab', { name: 'events' });
    if (await steps.isVisible()) await steps.click();
    const outcome = page.locator('#events-panel .recording-why');
    await expect(outcome).toHaveJSProperty('open', true);
    const step = page.locator('#events-panel .event').nth(index);
    await step.scrollIntoViewIfNeeded();
    const hitIsStep = await step.evaluate((row) => {
      const { left, right, top, bottom } = row.getBoundingClientRect();
      const hit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
      return hit != null && row.contains(hit);
    });
    assert.ok(hitIsStep, `an actual pointer can reach the focused event with Why expanded at ${width}px`);
    await step.click();
    await expect(step).toHaveAttribute('aria-current', 'true');
    const code = page.getByRole('region', { name: 'Code', exact: true });
    const active = code.locator('[aria-current="location"]');
    await expect(active).toHaveCount(1);
    await expect(active).toHaveAttribute('data-source-line', String(event.line));
    await expect(active.locator('.source-inline')).toBeVisible();
    assert.ok(await active.locator('.source-text').textContent() === text,
      `highlighted source row matches the focused read API at ${width}px`);
    const shownLocal = active.locator('.value-binding').filter({ hasText: 'descriptionPresent' });
    assert.ok(await shownLocal.locator('.value-preview').textContent() === local.value.preview,
      `selected real local preview matches the read API inline at ${width}px`);
    assert.ok((await page.getByRole('region', { name: 'Values', exact: true }).textContent()).includes('descriptionPresent'),
      `selected real local is in Values at ${width}px`);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `focused source and values fit at ${width}px`);
    const rendered = await page.locator('body').textContent();
    assert.ok(canaries.every((canary) => !rendered.includes(canary)), 'private limits hold in the focused rendered UI');
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `focused-code-${width}.png`), fullPage: true });
  }
  assert.equal(externalRequests, 0, 'focused viewer made a request outside loopback');
  assert.equal(browserErrors, 0, 'focused browser reported an error');
  process.stdout.write('focused Code and Values proof passed: matched line_cursor and captured local at 320/736/1024/1440; neutral probe timing copy\n');
} finally {
  await browser.close();
}
