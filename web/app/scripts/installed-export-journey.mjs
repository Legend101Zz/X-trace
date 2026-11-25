// Hosted-only proof against the embedded viewer; all input and output are private.
// stdin: {xtrace, projectDir, out, operationId, catalogOperationId, recordingId}; stdout is fixed counts only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { open, mkdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const config = JSON.parse(input);
for (const key of ['xtrace', 'projectDir', 'out', 'operationId', 'catalogOperationId', 'recordingId']) assert.equal(typeof config[key], 'string');
const formats = [
  ['openapi', true, 'OpenAPI 3.1'], ['openapi', false, 'OpenAPI 3.1'],
  ['postman', false, 'Postman Collection 2.1'], ['curl', false, 'cURL recipes'], ['bundle', false, 'Developer bundle'],
];
const report = { schemaVersion: 1, rows: [], cases: [], status: 'fail' };
const browser = await chromium.launch({ headless: true });
const activeViewers = new Set();
process.once('SIGTERM', () => {
  for (const child of activeViewers) child.kill('SIGTERM');
  void browser.close().finally(() => process.exit(1));
});

async function viewer(out) {
  const stdout = await open(join(out, 'viewer.stdout'), 'wx', 0o600);
  const stderr = await open(join(out, 'viewer.stderr'), 'wx', 0o600);
  const child = spawn(config.xtrace, ['open', '--project-dir', config.projectDir, '--viewer', '--no-browser'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  activeViewers.add(child);
  child.once('exit', () => activeViewers.delete(child));
  const state = { limited: false, writes: [] };
  const record = (pipe, target) => {
    let bytes = 0;
    pipe.on('data', (chunk) => {
      const remaining = 1024 * 1024 - bytes;
      state.writes.push(target.write(chunk.subarray(0, remaining)).catch(() => { state.limited = true; }));
      bytes += Math.min(chunk.length, remaining);
      if (chunk.length > remaining) { state.limited = true; child.kill('SIGTERM'); }
    });
  };
  record(child.stdout, stdout);
  record(child.stderr, stderr);
  let text = '';
  try {
    const ready = await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error('viewer-readiness')), 60_000);
      child.once('error', (error) => { clearTimeout(deadline); reject(error); });
      child.once('exit', () => { clearTimeout(deadline); reject(new Error('viewer-exited')); });
      child.stdout.on('data', (chunk) => {
        if (text.length + chunk.length > 65536) { reject(new Error('viewer-output-limit')); return; }
        text += chunk;
        for (const line of text.split('\n')) {
          try {
            const doc = JSON.parse(line);
            if (typeof doc.url === 'string') { clearTimeout(deadline); resolve(doc); break; }
          } catch { /* The readiness line may be split across pipe reads. */ }
        }
      });
    });
    return { child, ready, stdout, stderr, state };
  } catch (error) {
    await stop({ child, stdout, stderr, state });
    throw error;
  }
}

async function stop({ child, stdout, stderr, state }) {
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM'); // Only this directly spawned foreground viewer PID.
    let deadline;
    try { await Promise.race([exited, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('viewer-cleanup')), 10_000); })]); }
    finally { clearTimeout(deadline); }
  }
  await Promise.all(state.writes);
  await stdout.close();
  await stderr.close();
  assert.equal(state.limited, false, 'viewer-output-limit');
  assert.equal(child.exitCode, 0, 'viewer-exit-status');
}

async function geometry(page, dialog) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'document-overflow');
  assert.ok(await dialog.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    return rect.left >= 0 && rect.right <= innerWidth + 1 && rect.top >= 0 && rect.bottom <= innerHeight + 1 && node.scrollWidth <= node.clientWidth + 1;
  }), 'dialog-overflow');
  const controls = dialog.locator('button:visible:not(:disabled), select:visible:not(:disabled), input:visible:not(:disabled), a[href]:visible');
  for (const control of await controls.all()) {
    await control.scrollIntoViewIfNeeded();
    const box = await control.boundingBox();
    assert.ok(box && box.width >= 44 && box.height >= 44 && box.y >= 0 && box.y + box.height <= 901, 'reachable-touch-target');
  }
}

async function nativeModal(page, dialog, opener) {
  assert.ok(await dialog.evaluate((node) => node instanceof HTMLDialogElement && node.open && node.matches(':modal')), 'native-modal');
  await opener.evaluate((node) => node.focus());
  assert.ok(await dialog.evaluate((node) => node.contains(document.activeElement)), 'background-inert');
}

async function snapshot(page, out, name) {
  await writeFile(join(out, `${name}.dom.txt`), await page.locator('body').innerText(), { flag: 'wx', mode: 0o600 });
}

async function keyboard(page, dialog, opener) {
  await nativeModal(page, dialog, opener);
  await expect(dialog.getByRole('button', { name: 'Close', exact: true })).toBeFocused();
  await trap(page, dialog);
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeVisible();
}

async function trap(page, dialog) {
  const controls = dialog.locator('button:visible:not(:disabled), select:visible:not(:disabled), input:visible:not(:disabled), a[href]:visible');
  await controls.first().focus();
  for (const control of await controls.all()) {
    await expect(control).toBeFocused();
    await page.keyboard.press('Tab');
  }
  await expect(controls.first()).toBeFocused();
  const count = await controls.count();
  for (let index = 0; index < count; index += 1) await page.keyboard.press('Tab');
  await expect(controls.first()).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(controls.last()).toBeFocused();
}

try {
  for (const coarse of [false, true]) for (const width of [320, 736, 1024, 1280, 1440]) {
    const id = `${width}-${coarse ? 'coarse' : 'fine'}`;
    const out = join(config.out, id);
    await mkdir(out, { mode: 0o700 });
    const row = { width, coarse, cases: 0, status: 'fail', pageErrors: 0, consoleErrors: 0, externalRequests: 0 };
    report.rows.push(row);
    let running, context;
    const apiWrites = [];
    let apiWriteFailed = false;
    try {
      running = await viewer(out);
      const viewerUrl = new URL(running.ready.url);
      assert.ok(viewerUrl.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(viewerUrl.hostname), 'loopback-viewer');
      const origin = viewerUrl.origin;
      context = await browser.newContext({ viewport: { width, height: 900 }, hasTouch: coarse, isMobile: coarse, acceptDownloads: true, reducedMotion: 'reduce', serviceWorkers: 'block' });
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      page.on('pageerror', () => { row.pageErrors += 1; });
      page.on('console', (message) => { if (message.type() === 'error') row.consoleErrors += 1; });
      let apiIndex = 0;
      page.on('response', (response) => {
        if (new URL(response.url()).origin === origin && new URL(response.url()).pathname.startsWith('/api/v1/') && response.headers()['content-type']?.includes('application/json')) {
          const name = `api-${apiIndex++}.json`;
          apiWrites.push((async () => {
            assert.ok(Number(response.headers()['content-length'] ?? 0) <= 32 * 1024 * 1024, 'api-body-limit');
            const body = await response.body();
            assert.ok(body.length <= 32 * 1024 * 1024, 'api-body-limit');
            await writeFile(join(out, name), body, { flag: 'wx', mode: 0o600 });
          })().catch(() => { apiWriteFailed = true; }));
        }
      });
      await context.route('**/*', async (route) => {
        if (new URL(route.request().url()).origin !== origin) { row.externalRequests += 1; await route.abort(); }
        else await route.continue();
      });
      context.on('request', (request) => { if (new URL(request.url()).origin !== origin) row.externalRequests += 1; });
      const requestsTab = page.getByRole('tab', { name: 'Requests', exact: true });
      const showRequests = async () => {
        if (await requestsTab.isVisible()) await requestsTab.click();
        await expect(page.locator('#recordings-panel')).toBeVisible();
      };
      const endpoint = page.locator('.endpoint-card').filter({ hasText: '/orders' });
      const dialog = page.getByRole('dialog', { name: 'Export', exact: true });
      await page.goto(running.ready.url, { waitUntil: 'domcontentloaded' });
      await showRequests();
      await expect(endpoint).toHaveCount(1);
      await snapshot(page, out, 'requests');
      assert.equal(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), coarse, 'pointer-mode');
      for (const scope of ['all', 'one']) for (const [format, yaml, label] of formats) {
        await showRequests();
        const expanded = await endpoint.getAttribute('aria-expanded') === 'true';
        if (expanded !== (scope === 'one')) await endpoint.click();
        const opener = page.getByRole('button', { name: scope === 'all' ? 'Export endpoints…' : 'Export this endpoint…', exact: true });
        await opener.click();
        await keyboard(page, dialog, opener);
        await dialog.getByRole('button', { name: label, exact: false }).click();
        if (format === 'openapi') await dialog.getByLabel('File type').selectOption(yaml ? 'yaml' : 'json');
        await expect(dialog.getByRole('button', { name: scope === 'all' ? 'All eligible endpoints' : 'This endpoint', exact: true })).toHaveAttribute('aria-pressed', 'true');
        await geometry(page, dialog);
        await snapshot(page, out, `${scope}-${format}-${yaml ? 'yaml' : 'json'}-choose`);
        if (scope === 'all' && format === 'openapi' && yaml) await page.screenshot({ path: join(out, 'choose.png') });
        const previewResponse = page.waitForResponse((response) => response.url() === `${origin}/api/v1/exports/preview`);
        await dialog.getByRole('button', { name: 'Preview', exact: true }).click();
        const response = await previewResponse;
        assert.equal(response.status(), 200, 'preview-status');
        const preview = await response.json();
        assert.deepEqual(preview.request, { format, yaml, revision: 'latest', scope: scope === 'all' ? 'all' : `observed:${config.operationId}` });
        assert.equal(preview.catalogOperationId, scope === 'all' ? null : config.catalogOperationId, 'catalog-scope-resolution');
        await expect(dialog.getByRole('region', { name: 'Preview export' })).toBeFocused();
        await expect(dialog.getByText(preview.contentHash, { exact: true })).toBeVisible();
        await expect(dialog.getByText('Captured request and response bodies, cookies and credentials stay out of the export.', { exact: true })).toBeVisible();
        await geometry(page, dialog);
        await trap(page, dialog);
        const caseId = `${scope}-${format}-${yaml ? 'yaml' : 'json'}`;
        await writeFile(join(out, `${caseId}.preview.json`), JSON.stringify(preview), { flag: 'wx', mode: 0o600 });
        await writeFile(join(out, `${caseId}.dom.txt`), await page.locator('body').innerText(), { flag: 'wx', mode: 0o600 });
        await page.screenshot({ path: join(out, `${caseId}.png`) });
        const saveResponse = page.waitForResponse((result) => result.url() === `${origin}/api/v1/exports/save`);
        const downloadEvent = page.waitForEvent('download');
        await dialog.getByRole('button', { name: 'Save file', exact: true }).click();
        const saved = await saveResponse;
        assert.equal(saved.status(), 200, 'save-status');
        assert.deepEqual(saved.request().postDataJSON(), { ...preview.request, approval: preview.approval });
        assert.equal(saved.headers()['content-type']?.split(';')[0], preview.download.mediaType, 'download-media');
        assert.equal(saved.headers()['content-disposition'], `attachment; filename="${preview.download.filename}"`, 'download-disposition');
        assert.ok(Number(saved.headers()['content-length'] ?? 0) <= 20 * 1024 * 1024, 'download-size-limit');
        const download = await downloadEvent;
        assert.equal(download.suggestedFilename(), preview.download.filename, 'download-name');
        await download.saveAs(join(out, `${caseId}.download`));
        assert.ok((await stat(join(out, `${caseId}.download`))).size <= 20 * 1024 * 1024, 'download-size-limit');
        assert.equal(await download.failure(), null, 'download-failed');
        await expect(dialog.getByRole('heading', { name: 'Download started', exact: true })).toBeVisible();
        await snapshot(page, out, `${caseId}-save`);
        await geometry(page, dialog);
        await trap(page, dialog);
        if (scope === 'all' && format === 'openapi' && yaml) await page.screenshot({ path: join(out, 'save.png') });
        await dialog.getByRole('button', { name: 'Done', exact: true }).click();
        await expect(opener).toBeFocused();
        report.cases.push({ id, caseId, scope, format, yaml });
        row.cases += 1;
      }
      await showRequests();
      if (await endpoint.getAttribute('aria-expanded') !== 'true') await endpoint.click();
      await page.getByRole('button', { name: new RegExp(config.recordingId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click();
      await page.locator('.event-seq').first().waitFor();
      await snapshot(page, out, 'recording');
      await page.getByLabel('More recording actions', { exact: true }).click();
      const recordingExport = page.getByRole('button', { name: 'Export…', exact: true });
      await recordingExport.click();
      await keyboard(page, dialog, recordingExport);
      await snapshot(page, out, 'recording-export-choose');
      await expect(dialog.getByRole('button', { name: 'This endpoint', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await page.keyboard.press('Escape');
      assert.equal(row.pageErrors, 0, 'page-errors');
      assert.equal(row.consoleErrors, 0, 'console-errors');
      assert.equal(row.externalRequests, 0, 'external-requests');
      row.status = 'pass';
    } catch (error) {
      row.reason = 'browser-assertion-or-prerequisite';
      await writeFile(join(out, 'failure.private.txt'), String(error?.stack ?? error), { mode: 0o600 });
    } finally {
      try { await Promise.all(apiWrites); assert.equal(apiWriteFailed, false, 'api-evidence-write'); }
      catch { row.status = 'fail'; row.reason = 'api-evidence-write'; }
      try { if (context) await context.close(); }
      catch { row.status = 'fail'; row.reason = 'browser-cleanup'; }
      try { if (running) await stop(running); }
      catch { row.status = 'fail'; row.reason = 'browser-cleanup'; }
    }
  }
  if (report.rows.length === 10 && report.rows.every((row) => row.status === 'pass' && row.cases === 10)) report.status = 'pass';
} finally {
  try { await browser.close(); }
  catch { report.status = 'fail'; }
  await writeFile(join(config.out, 'browser.private.json'), JSON.stringify(report), { mode: 0o600 });
}
console.log(JSON.stringify({ status: report.status, viewports: report.rows.length, downloads: report.cases.length }));
process.exitCode = report.status === 'pass' ? 0 : 1;
