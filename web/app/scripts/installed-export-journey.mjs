// Hosted-only proof against the embedded viewer; all input and output are private.
// stdin: {xtrace, projectDir, out, operationId, catalogOperationId, recordingId}; stdout is fixed counts only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { closeSync, fsyncSync, openSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
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
assert.match(config.identity?.sourceSha ?? '', /^[0-9a-f]{40}$/);
assert.match(config.identity?.packageSha256 ?? '', /^[0-9a-f]{64}$/);
const report = { schemaVersion: 2, identity: config.identity, rows: [], cases: [], status: 'in-progress',
  failureSubstage: null, browserCleanup: 'not-reached', checkpointSequence: 0,
  current: { rowId: null, caseId: null, stage: 'browser-launch' } };
let browser, activeRow = null, activeCase = null;
let interrupted = false, workPassed = false;
const activeViewers = new Set();

// A killed process must leave one complete, private, bounded receipt, including the
// await it was entering. Never publish a row as passed before all its cleanup.
function checkpoint() {
  report.checkpointSequence += 1;
  const bytes = Buffer.from(JSON.stringify(report));
  assert.ok(bytes.length <= 128 * 1024, 'checkpoint-limit');
  const path = join(config.out, 'browser.private.json');
  const temporary = path + '.tmp';
  let fd;
  try {
    fd = openSync(temporary, 'wx', 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(temporary, path);
    const directory = openSync(config.out, 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } finally {
    if (fd !== undefined) { closeSync(fd); unlinkSync(temporary); }
  }
}

function stage(name) {
  report.current = { rowId: activeRow ? `${activeRow.width}-${activeRow.coarse ? 'coarse' : 'fine'}` : null,
    caseId: activeCase, stage: name };
  checkpoint();
}

async function bounded(operation, milliseconds, code) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(code)), milliseconds); })]); }
  finally { clearTimeout(timer); }
}

process.once('SIGTERM', () => {
  interrupted = true;
  report.status = 'interrupted';
  if (activeRow?.status === 'in-progress') activeRow.status = 'interrupted';
  checkpoint();
  for (const child of activeViewers) child.kill('SIGTERM');
  // Closing Chromium interrupts pending protocol/body reads so normal finally
  // blocks can record each cleanup outcome. The enclosing runner allows 10 s.
  void browser?.close().catch(() => {});
  setTimeout(() => process.exit(1), 8_000).unref();
});
checkpoint();

async function viewer(out, row) {
  const stdout = await open(join(out, 'viewer.stdout'), 'wx', 0o600);
  const stderr = await open(join(out, 'viewer.stderr'), 'wx', 0o600);
  const child = spawn(config.xtrace, ['open', '--project-dir', config.projectDir, '--viewer', '--no-browser'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  activeViewers.add(child);
  child.once('exit', () => activeViewers.delete(child));
  const state = { limited: false, writes: [], closed: false };
  child.once('close', () => { state.closed = true; });
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
    try { await stop({ child, stdout, stderr, state }); }
    catch (cleanupError) {
      row.cleanupFailures.push('viewer-stop');
      await writeFile(join(out, 'viewer-stop.failure.private.txt'), String(cleanupError?.stack ?? cleanupError), { mode: 0o600 });
    }
    throw error;
  }
}

async function stop({ child, stdout, stderr, state }) {
  try {
    const closed = state.closed ? Promise.resolve() : new Promise((resolve) => child.once('close', resolve));
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    // close follows the process exit and its final pipe reads; snapshotting the
    // writes on exit could otherwise miss buffered output still arriving.
    await bounded(closed, 10_000, 'viewer-cleanup');
    await bounded(Promise.all(state.writes), 10_000, 'viewer-output-drain');
  } finally {
    await stdout.close();
    await stderr.close();
  }
  assert.equal(state.limited, false, 'viewer-output-limit');
  assert.equal(child.exitCode, 0, 'viewer-exit-status');
}

async function geometry(page, dialog) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'document-overflow');
  assert.ok(await dialog.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    return rect.left >= 0 && rect.right <= innerWidth + 1 && rect.top >= 0 && rect.bottom <= innerHeight + 1 && node.scrollWidth <= node.clientWidth + 1;
  }), 'dialog-overflow');
  // Measure every actionable control, including inactive arrow-accessed tabs and
  // omission summaries. One synchronous pass avoids per-control animation waits.
  assert.ok(await dialog.evaluate((node) => [...node.querySelectorAll(
    'button, select, input:not([type="hidden"]), textarea, a[href], summary',
  )].filter((control) => !control.matches(':disabled') && control.getClientRects().length && getComputedStyle(control).visibility === 'visible')
    .every((control) => {
      control.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      const box = control.getBoundingClientRect();
      return box.width >= 44 && box.height >= 44 && box.x >= 0 && box.right <= innerWidth + 1 && box.y >= 0 && box.bottom <= innerHeight + 1;
    })), 'reachable-touch-target');
}

async function nativeModal(page, dialog, opener) {
  assert.ok(await dialog.evaluate((node) => node instanceof HTMLDialogElement && node.open && node.matches(':modal')), 'native-modal');
  await opener.evaluate((node) => node.focus());
  assert.ok(await dialog.evaluate((node) => node.contains(document.activeElement)), 'background-inert');
}

async function snapshot(page, out, name) {
  await writeFile(join(out, `${name}.dom.txt`), await page.locator('body').innerText(), { flag: 'wx', mode: 0o600 });
}

async function terminalCommand(page, dialog, preview, phase) {
  const expected = { '--revision': preview.revisionId, '--format': preview.request.format };
  if (phase === 'Preview') expected['--preview'] = true;
  else expected['--output'] = './xtrace-export';
  if (preview.catalogOperationId) expected['--operations'] = preview.catalogOperationId;
  if (preview.request.yaml) expected['--yaml'] = true;
  const command = dialog.getByLabel('Terminal command', { exact: true });
  const visible = await command.innerText();
  // The displayed values are single CLI tokens; bind each value to its option.
  const tokens = visible.trim().split(/\s+/);
  assert.deepEqual(tokens.slice(0, 2), ['xtrace', 'export'], 'terminal-command-binary');
  const actual = {};
  for (let index = 2; index < tokens.length; index += 1) {
    const option = tokens[index];
    assert.ok(Object.hasOwn(expected, option) && !Object.hasOwn(actual, option), 'terminal-command-option');
    actual[option] = expected[option] === true ? true : tokens[++index];
  }
  assert.deepEqual(actual, expected, 'terminal-command-options');
  await page.evaluate(() => navigator.clipboard.writeText(''));
  const copy = dialog.getByRole('button', { name: 'Copy terminal command', exact: true });
  await copy.focus();
  await expect(copy).toBeFocused();
  await page.keyboard.press('Enter');
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(visible);
}

async function activate(page, button, key) {
  await button.focus();
  await expect(button).toBeFocused();
  await page.keyboard.press(key);
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
  // Native tab order includes disclosure summaries and the metadata panel, and
  // excludes roving tabs with tabindex=-1. Positive tab indices precede zero.
  const handles = await dialog.locator('button, select, input:not([type="hidden"]), textarea, a[href], summary, [tabindex]').elementHandles();
  const controls = [];
  for (const handle of handles) {
    const index = await handle.evaluate((node) => !node.matches(':disabled') && node.tabIndex >= 0 &&
      node.getClientRects().length > 0 && getComputedStyle(node).visibility === 'visible' ? node.tabIndex : -1);
    if (index >= 0) controls.push({ handle, index });
  }
  controls.sort((left, right) => (left.index || Infinity) - (right.index || Infinity));
  assert.ok(controls.length > 0, 'focus-stops');
  const focused = async (control) => assert.ok(await control.handle.evaluate((node) => node === document.activeElement), 'sequential-focus-order');
  await controls[0].handle.focus();
  for (const control of controls) {
    await focused(control);
    await page.keyboard.press('Tab');
  }
  await focused(controls[0]); // Forward end wraps to the first stop.
  for (const control of [...controls].reverse()) {
    await page.keyboard.press('Shift+Tab');
    await focused(control);
  }
  await page.keyboard.press('Shift+Tab');
  await focused(controls.at(-1)); // Reverse end wraps to the last stop.
  await controls[0].handle.focus();
  await Promise.all(handles.map((handle) => handle.dispose()));
}

async function inventoryKeyboard(page, dialog, preview) {
  assert.ok(preview.files.length > 0, 'file-inventory-empty');
  if (['curl', 'bundle'].includes(preview.request.format)) assert.ok(preview.files.length > 1, 'multi-file-inventory-not-exercised');
  const list = dialog.getByRole('tablist', { name: 'Export files', exact: true });
  const tabs = list.getByRole('tab');
  const size = 16;
  let offset = 0;
  do {
    const count = Math.min(size, preview.files.length - offset);
    await expect(tabs).toHaveCount(count);
    await tabs.first().focus();
    for (let index = 0; index < count; index += 1) {
      const tab = tabs.nth(index);
      const file = preview.files[offset + index];
      await expect(tab).toBeFocused();
      await expect(tab).toHaveText(file.name ?? `Recipe ${file.recipeOrdinal} (filename withheld)`);
      await expect(tab).toHaveAttribute('aria-selected', 'true');
      const panel = dialog.getByRole('tabpanel');
      await expect(panel).toHaveAttribute('aria-labelledby', await tab.getAttribute('id'));
      await expect(panel).toContainText(`${file.bytes.toLocaleString('en-US')} bytes`);
      await expect(panel).toContainText(file.mode.toString(8).padStart(4, '0'));
      await expect(panel.getByLabel('File BLAKE3', { exact: true })).toHaveText(file.blake3);
      await page.keyboard.press('ArrowDown');
    }
    await expect(tabs.first()).toBeFocused();
    await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('ArrowUp');
    await expect(tabs.last()).toBeFocused();
    await expect(tabs.last()).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Home');
    await expect(tabs.first()).toBeFocused();
    await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('End');
    await expect(tabs.last()).toBeFocused();
    await expect(tabs.last()).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Home');
    offset += count;
    if (offset < preview.files.length) await dialog.getByRole('button', { name: 'Next files', exact: true }).click();
  } while (offset < preview.files.length);
  while (offset > size) {
    await dialog.getByRole('button', { name: 'Previous files', exact: true }).click();
    offset = Math.floor((offset - 1) / size) * size;
    await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
    const file = preview.files[offset - size];
    await expect(tabs.first()).toHaveText(file.name ?? `Recipe ${file.recipeOrdinal} (filename withheld)`);
  }
}

try {
  report.failureSubstage = 'browser-launch';
  stage('browser-launch');
  browser = await chromium.launch({ headless: true });
  report.failureSubstage = 'viewport-setup';
  stage('viewport-setup');
  for (const coarse of [false, true]) for (const width of [320, 736, 1024, 1280, 1440]) {
    const id = `${width}-${coarse ? 'coarse' : 'fine'}`;
    const out = join(config.out, id);
    await mkdir(out, { mode: 0o700 });
    const row = { width, coarse, cases: 0, status: 'in-progress', cleanupStatus: 'not-reached', cleanupStage: null, pageErrors: 0, consoleErrors: 0, externalRequests: 0, failureSubstage: null, failureCase: null, cleanupFailures: [] };
    activeRow = row; activeCase = null;
    report.failureSubstage = null;
    report.rows.push(row);
    stage('viewer-start');
    let rowWorkPassed = false;
    let running, context;
    const apiWrites = new Set();
    let apiCount = 0;
    let apiWriteFailed = false;
    try {
      running = await viewer(out, row);
      stage('viewer-url');
      const viewerUrl = new URL(running.ready.url);
      assert.ok(viewerUrl.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(viewerUrl.hostname), 'loopback-viewer');
      const origin = viewerUrl.origin;
      stage('browser-context');
      context = await browser.newContext({ viewport: { width, height: 900 }, hasTouch: coarse, isMobile: coarse,
        colorScheme: coarse ? 'light' : 'dark', locale: 'en-US', acceptDownloads: true, reducedMotion: 'reduce', serviceWorkers: 'block' });
      await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      page.on('pageerror', () => { row.pageErrors += 1; });
      page.on('console', (message) => { if (message.type() === 'error') row.consoleErrors += 1; });
      let apiIndex = 0;
      page.on('response', (response) => {
        if (new URL(response.url()).origin === origin && new URL(response.url()).pathname.startsWith('/api/v1/') && response.headers()['content-type']?.includes('application/json')) {
          const name = `api-${apiIndex++}.json`;
          if (++apiCount > 4096) { apiWriteFailed = true; return; }
          const capture = (async () => {
            assert.ok(Number(response.headers()['content-length'] ?? 0) <= 32 * 1024 * 1024, 'api-body-limit');
            const body = await bounded(response.body(), 10_000, 'api-body-timeout');
            assert.ok(body.length <= 32 * 1024 * 1024, 'api-body-limit');
            await writeFile(join(out, name), body, { flag: 'wx', mode: 0o600 });
          })().catch(() => { apiWriteFailed = true; });
          apiWrites.add(capture);
          void capture.finally(() => apiWrites.delete(capture));
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
      stage('requests-load');
      await page.goto(running.ready.url, { waitUntil: 'domcontentloaded' });
      await showRequests();
      await expect(endpoint).toHaveCount(1);
      await snapshot(page, out, 'requests');
      assert.equal(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), coarse, 'pointer-mode');
      stage('system-theme');
      assert.equal(await page.evaluate(() => matchMedia('(prefers-color-scheme: light)').matches), coarse, 'system-color-scheme');
      await expect(page.locator('html')).toHaveAttribute('data-theme', coarse ? 'light' : 'dark');
      for (const scope of ['all', 'one']) for (const [format, yaml, label] of formats) {
        const caseId = `${scope}-${format}-${yaml ? 'yaml' : 'json'}`;
        activeCase = caseId;
        stage('choose-open');
        await showRequests();
        const expanded = await endpoint.getAttribute('aria-expanded') === 'true';
        if (expanded !== (scope === 'one')) await endpoint.click();
        const opener = page.getByRole('button', { name: scope === 'all' ? 'Export endpoints…' : 'Export this endpoint…', exact: true });
        await opener.click();
        stage('choose-keyboard');
        await keyboard(page, dialog, opener);
        stage('choose-format');
        await dialog.getByRole('button', { name: label, exact: false }).click();
        if (format === 'openapi') await dialog.getByLabel('File type').selectOption(yaml ? 'yaml' : 'json');
        stage('choose-scope');
        await expect(dialog.getByRole('button', { name: scope === 'all' ? 'All eligible endpoints' : 'This endpoint', exact: true })).toHaveAttribute('aria-pressed', 'true');
        stage('choose-capture');
        await snapshot(page, out, `${caseId}-choose`);
        if (scope === 'all' && format === 'openapi' && yaml) await page.screenshot({ path: join(out, 'choose.png') });
        stage('choose-geometry');
        await geometry(page, dialog);
        stage('preview-activate');
        const previewResponse = page.waitForResponse((response) => response.url() === `${origin}/api/v1/exports/preview`);
        await activate(page, dialog.getByRole('button', { name: 'Preview', exact: true }), 'Enter');
        stage('preview-response');
        const response = await previewResponse;
        assert.equal(response.status(), 200, 'preview-status');
        const preview = await bounded(response.json(), 10_000, 'preview-body-timeout');
        assert.deepEqual(preview.request, { format, yaml, revision: 'latest', scope: scope === 'all' ? 'all' : `observed:${config.operationId}` });
        assert.equal(preview.catalogOperationId, scope === 'all' ? null : config.catalogOperationId, 'catalog-scope-resolution');
        stage('preview-focus');
        await expect(dialog.getByRole('region', { name: 'Preview export' })).toBeFocused();
        stage('preview-content');
        await expect(dialog.getByText(preview.contentHash, { exact: true })).toBeVisible();
        await expect(dialog.getByText('Captured request and response bodies, cookies and credentials stay out of the export.', { exact: true })).toBeVisible();
        stage('preview-inventory-keyboard');
        await inventoryKeyboard(page, dialog, preview);
        stage('preview-capture');
        await writeFile(join(out, `${caseId}.preview.json`), JSON.stringify(preview), { flag: 'wx', mode: 0o600 });
        await writeFile(join(out, `${caseId}.dom.txt`), await page.locator('body').innerText(), { flag: 'wx', mode: 0o600 });
        await page.screenshot({ path: join(out, `${caseId}.png`) });
        stage('preview-command');
        await terminalCommand(page, dialog, preview, 'Preview');
        stage('preview-geometry');
        await geometry(page, dialog);
        stage('preview-keyboard');
        await trap(page, dialog);
        stage('save-activate');
        const saveResponse = page.waitForResponse((result) => result.url() === `${origin}/api/v1/exports/save`);
        const downloadEvent = page.waitForEvent('download');
        await activate(page, dialog.getByRole('button', { name: 'Save file', exact: true }), 'Space');
        stage('save-response');
        const saved = await saveResponse;
        assert.equal(saved.status(), 200, 'save-status');
        assert.deepEqual(saved.request().postDataJSON(), { ...preview.request, approval: preview.approval });
        assert.equal(saved.headers()['content-type']?.split(';')[0], preview.download.mediaType, 'download-media');
        assert.equal(saved.headers()['content-disposition'], `attachment; filename="${preview.download.filename}"`, 'download-disposition');
        assert.ok(Number(saved.headers()['content-length'] ?? 0) <= 20 * 1024 * 1024, 'download-size-limit');
        stage('save-download');
        const download = await downloadEvent;
        assert.equal(download.suggestedFilename(), preview.download.filename, 'download-name');
        await bounded(download.saveAs(join(out, `${caseId}.download`)), 10_000, 'download-body-timeout');
        assert.ok((await stat(join(out, `${caseId}.download`))).size <= 20 * 1024 * 1024, 'download-size-limit');
        assert.equal(await bounded(download.failure(), 10_000, 'download-status-timeout'), null, 'download-failed');
        stage('save-focus');
        await expect(dialog.getByRole('region', { name: 'Save export', exact: true })).toBeFocused();
        stage('save-content');
        await expect(dialog.getByRole('heading', { name: 'Download started', exact: true })).toBeVisible();
        stage('save-capture');
        await snapshot(page, out, `${caseId}-save`);
        if (scope === 'all' && format === 'openapi' && yaml) await page.screenshot({ path: join(out, 'save.png') });
        stage('save-command');
        await terminalCommand(page, dialog, preview, 'Save');
        stage('save-geometry');
        await geometry(page, dialog);
        stage('save-keyboard');
        await trap(page, dialog);
        stage('save-done');
        await dialog.getByRole('button', { name: 'Done', exact: true }).click();
        await expect(opener).toBeFocused();
        report.cases.push({ id, caseId, scope, format, yaml });
        row.cases += 1;
        checkpoint();
      }
      activeCase = null;
      stage('recording-select');
      await showRequests();
      if (await endpoint.getAttribute('aria-expanded') !== 'true') await endpoint.click();
      await page.getByRole('button', { name: new RegExp(config.recordingId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click();
      await page.locator('.event-seq').first().waitFor();
      await snapshot(page, out, 'recording');
      await page.getByLabel('More recording actions', { exact: true }).click();
      const recordingExport = page.getByRole('button', { name: 'Export…', exact: true });
      stage('recording-export-open');
      await recordingExport.click();
      stage('recording-export-keyboard');
      await keyboard(page, dialog, recordingExport);
      stage('recording-export-scope');
      await snapshot(page, out, 'recording-export-choose');
      await expect(dialog.getByRole('button', { name: 'This endpoint', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await page.keyboard.press('Escape');
      stage('page-health');
      assert.equal(row.pageErrors, 0, 'page-errors');
      assert.equal(row.consoleErrors, 0, 'console-errors');
      assert.equal(row.externalRequests, 0, 'external-requests');
      rowWorkPassed = true;
    } catch (error) {
      row.status = interrupted ? 'interrupted' : 'fail';
      row.failureSubstage = report.current.stage;
      row.failureCase = activeCase;
      await writeFile(join(out, 'failure.private.txt'), String(error?.stack ?? error), { mode: 0o600 });
    } finally {
      row.cleanupStatus = 'in-progress';
      // Close the context before draining captures: response.body() can otherwise
      // wait forever for a live JSON response whose request is still open.
      for (const [name, operation] of [
        ['context-close', async () => { if (context) await bounded(context.close(), 10_000, 'context-close-timeout'); }],
        ['api-evidence-write', async () => { await bounded(Promise.all([...apiWrites]), 10_000, 'api-evidence-timeout'); assert.equal(apiWriteFailed, false, 'api-evidence-write'); }],
        ['viewer-stop', async () => { if (running) await stop(running); }],
      ]) {
        row.cleanupStage = name;
        stage(name);
        try { await operation(); }
        catch (error) {
          row.cleanupFailures.push(name);
          await writeFile(join(out, `${name}.failure.private.txt`), String(error?.stack ?? error), { mode: 0o600 });
        }
        checkpoint();
      }
      row.cleanupStage = null;
      row.cleanupStatus = row.cleanupFailures.length ? 'fail' : 'pass';
      if (rowWorkPassed && (row.pageErrors || row.consoleErrors || row.externalRequests)) {
        rowWorkPassed = false;
        row.failureSubstage = 'page-health';
        row.failureCase = null;
      }
      row.status = interrupted ? 'interrupted' : rowWorkPassed && !row.cleanupFailures.length ? 'pass' : 'fail';
      stage('row-complete');
    }
    if (interrupted) throw new Error('interrupted');
    activeRow = null; activeCase = null;
  }
  report.failureSubstage = null;
  workPassed = report.rows.length === 10 && report.rows.every((row) => row.status === 'pass' && row.cases === 10);
} catch (error) {
  await writeFile(join(config.out, 'failure.private.txt'), String(error?.stack ?? error), { mode: 0o600 });
} finally {
  report.browserCleanup = browser ? 'in-progress' : 'not-reached';
  stage('browser-close');
  try { if (browser) { await bounded(browser.close(), 10_000, 'browser-close-timeout'); report.browserCleanup = 'pass'; } }
  catch (error) {
    report.browserCleanup = 'fail';
    await writeFile(join(config.out, 'browser-cleanup.failure.private.txt'), String(error?.stack ?? error), { mode: 0o600 });
  }
  report.status = interrupted ? 'interrupted' : workPassed && report.browserCleanup === 'pass' ? 'pass' : 'fail';
  activeRow = null; activeCase = null;
  stage('complete');
}
const passedRows = report.rows.filter((row) => row.status === 'pass');
console.log(JSON.stringify({ status: report.status, viewports: passedRows.length,
  downloads: passedRows.reduce((count, row) => count + row.cases, 0), completedCases: report.cases.length }));
process.exitCode = report.status === 'pass' ? 0 : 1;
