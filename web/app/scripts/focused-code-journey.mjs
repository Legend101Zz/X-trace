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
  const page = await browser.newPage({ colorScheme: 'dark' });
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
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
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
    const steps = page.getByRole('tab', { name: 'Steps' });
    if (await steps.isVisible()) await steps.click();
    const step = page.locator('#events-panel .event').nth(index);
    const measureTextColumn = () => step.locator('.event-copy').evaluate((copy) => copy.getBoundingClientRect().width);
    if (width === 1024) {
      for (const name of ['Resize Requests', 'Resize Inspector', 'Resize Code']) {
        await page.getByRole('separator', { name }).press('End');
      }
      assert.ok(await measureTextColumn() >= 80, 'maximum saved panel preferences still leave a readable Steps column at 1024px');
      await page.getByRole('button', { name: 'Reset panels' }).click();
    }
    await expect(page.locator('#events-panel .recording-why')).toHaveJSProperty('open', true);
    await step.scrollIntoViewIfNeeded();
    assert.ok(await step.evaluate((row) => {
      const { left, right, top, bottom } = row.getBoundingClientRect();
      const hit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
      return hit != null && row.contains(hit);
    }), `the real event receives pointer input with Why expanded at ${width}px`);
    const copyWidth = await measureTextColumn();
    assert.ok(copyWidth >= 80, `focused Steps preserve a readable text column at ${width}px`);
    assert.ok(!(await step.locator('.event-copy').textContent()).includes('#m1:'), 'Java identity digest stays out of short step text');
    await step.click();
    await expect(step).toHaveAttribute('aria-current', 'true');
    const code = page.getByRole('region', { name: 'Code', exact: true });
    const active = code.locator('[aria-current="location"]');
    await expect(active).toHaveCount(1);
    await expect(active).toHaveAttribute('data-source-line', String(event.line));
    await expect(active.locator('.source-inline')).toBeVisible();
    // Read layout before any click or scroll can move the source into view.
    const firstViewport = await active.evaluate((row) => {
      const source = row.querySelector('.source-text').getBoundingClientRect();
      const context = document.querySelector('.replay-context').getBoundingClientRect();
      const controls = document.querySelector('.viewer-preferences').getBoundingClientRect();
      return source.top >= context.bottom && source.bottom <= controls.top
        && controls.bottom <= window.innerHeight;
    });
    assert.ok(firstViewport, `the selected source and bottom controls fit in the first viewport at ${width}px`);
    const context = page.getByRole('region', { name: 'Recording summary' });
    await expect(context.getByText('POST /orders', { exact: true })).toBeInViewport();
    await expect(context.getByText(`Event sequence ${event.sequence}`, { exact: true })).toBeInViewport();
    if (detail.outcome?.httpStatus != null) {
      const badge = context.locator('.replay-context-http');
      await expect(badge).toContainText(String(detail.outcome.httpStatus));
      await expect(badge).toBeInViewport();
    }
    const tabs = page.getByRole('tablist', { name: 'Inspector evidence' });
    if (width < 861) {
      const codeTab = tabs.getByRole('tab', { name: 'Code', exact: true });
      await expect(codeTab).toHaveAttribute('aria-selected', 'true');
      await expect(page.getByRole('region', { name: 'Event details', exact: true })).toHaveCount(0);
      const targets = await tabs.getByRole('tab').evaluateAll((buttons) => buttons.map((button) => button.getBoundingClientRect().height));
      assert.ok(targets.length === 4 && targets.every((height) => height >= 44), 'all four reading tabs are touch-size');
    }
    if (screenshotDirectory) {
      await page.screenshot({ path: join(screenshotDirectory, `focused-code-${width}-viewport.png`) });
      await page.screenshot({ path: join(screenshotDirectory, `focused-code-${width}.png`), fullPage: true });
    }
    assert.ok(await active.locator('.source-text').textContent() === text,
      `highlighted source row matches the focused read API at ${width}px`);
    const shownLocal = active.locator('.value-binding').filter({ hasText: 'descriptionPresent' });
    assert.ok(await shownLocal.locator('.value-preview').textContent() === local.value.preview,
      `selected real local preview matches the read API inline at ${width}px`);
    const valuesTab = tabs.getByRole('tab', { name: /^Values/ });
    if (width < 861) {
      await tabs.getByRole('tab', { name: 'Code', exact: true }).press('ArrowRight');
      await expect(valuesTab).toBeFocused();
    } else await valuesTab.click();
    assert.ok((await page.getByRole('region', { name: 'Values', exact: true }).textContent()).includes('descriptionPresent'),
      `selected real local is in Values at ${width}px`);
    await expect(context.getByText(`Event sequence ${event.sequence}`, { exact: true })).toBeInViewport();
    if (screenshotDirectory) {
      await page.screenshot({ path: join(screenshotDirectory, `focused-values-${width}-viewport.png`) });
      await page.screenshot({ path: join(screenshotDirectory, `focused-values-${width}.png`), fullPage: true });
    }
    const details = tabs.getByRole('tab', { name: 'Details', exact: true });
    await details.click();
    await expect(page.locator('[data-event-field="symbol"]')).toHaveText(event.symbol);
    const back = page.getByRole('button', { name: width < 861 ? `Back to event ${event.sequence}` : `Focus event ${event.sequence}`, exact: true });
    await expect(back).toBeInViewport();
    await back.press('Enter');
    await expect(step).toBeFocused();
    await expect(step).toHaveAttribute('aria-current', 'true');
    if (width >= 861) await valuesTab.click();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      `focused source and values fit at ${width}px`);
    const rendered = await page.locator('body').textContent();
    assert.ok(canaries.every((canary) => !rendered.includes(canary)), 'private limits hold in the focused rendered UI');
  }
  assert.equal(externalRequests, 0, 'focused viewer made a request outside loopback');
  assert.equal(browserErrors, 0, 'focused browser reported an error');
  process.stdout.write('focused Code and Values proof passed: matched line_cursor and captured local at 320/736/1024/1440; neutral probe timing copy\n');
} finally {
  await browser.close();
}
