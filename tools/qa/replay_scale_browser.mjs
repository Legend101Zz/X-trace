// QA-only: actual embedded viewer, retained #94 store, no request mocking or product hooks.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';

const SAMPLES = 5;
const VIEWPORT = { width: 1440, height: 900 };
const ACTION_TIMEOUT = 10_000;
const DIAGNOSTIC_TIMEOUT = 2_000;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const check = (condition) => { if (!condition) throw new Error('measurement condition failed'); };
const identity = (event) => sha256(JSON.stringify([event.sequence, event.eventId, event.frameId]));

async function boundedDiagnostic(observe) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(observe), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('diagnostic unavailable')), DIAGNOSTIC_TIMEOUT);
    })]);
  } finally { clearTimeout(timer); }
}

function startViewer(binary, manifest) {
  const child = spawn(binary, ['open', '--project-dir', manifest.project_dir, '--viewer', '--no-browser'], {
    env: { ...process.env, XTRACE_DATA_HOME: manifest.data_home },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const ready = new Promise((resolve, reject) => {
    let buffer = '';
    const fail = () => { clearTimeout(timer); reject(new Error('viewer readiness failed')); };
    const timer = setTimeout(fail, 30_000);
    child.once('error', fail);
    child.once('exit', fail);
    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.length > 65_536) { fail(); return; }
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      try {
        const document = JSON.parse(buffer.slice(0, newline));
        const url = new URL(document.url);
        check(url.protocol === 'http:' && url.hostname === '127.0.0.1');
        check(url.hash.startsWith('#token='));
        clearTimeout(timer);
        resolve(document.url);
      } catch { fail(); }
    });
  });
  return { child, ready };
}

async function stopViewer(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL'); // Only the child this driver spawned, never a process group.
      reject(new Error('viewer shutdown failed'));
    }, 10_000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.kill('SIGTERM');
  });
}

// This runs before application scripts. The start and finish use the same browser clock.
// A second rAF means a rendering opportunity intervened; it cannot prove physical display.
function installClickClock({ recordingId }) {
  window.__xtraceScale = { started: false, completed: false };
  const visible = (node) => {
    if (!node || !node.checkVisibility()) return false;
    const rect = node.getBoundingClientRect();
    const x = (Math.max(rect.left, 0) + Math.min(rect.right, innerWidth)) / 2;
    const y = (Math.max(rect.top, 0) + Math.min(rect.bottom, innerHeight)) / 2;
    if (rect.width <= 0 || rect.height <= 0 || x < 0 || x >= innerWidth || y < 0 || y >= innerHeight) return false;
    return node.contains(document.elementFromPoint(x, y));
  };
  const selected = () => {
    if (document.querySelector('#events-panel h1')?.textContent !== recordingId) return null;
    const current = document.querySelector('.recording[aria-current="true"] .recording-title');
    if (current?.textContent !== recordingId) return null;
    const row = document.querySelector('.event-rail .event[aria-current="true"]');
    if (row?.querySelector('.event-seq')?.textContent !== '2' || !visible(row)) return null;
    const section = Array.from(document.querySelectorAll('.inspector-section')).find((node) =>
      node.querySelector('.inspector-label')?.textContent === 'Event identity');
    if (section?.querySelector('.inspector-value.mono')?.textContent !== 'synthetic-scale-00002') return null;
    return row;
  };
  window.addEventListener('click', (event) => {
    const button = event.target.closest?.('button.recording');
    if (!event.isTrusted || button?.querySelector('.recording-title')?.textContent !== recordingId) return;
    if (window.__xtraceScale.started) return;
    window.__xtraceScale = { started: true, trusted: true, startMs: performance.now(), completed: false };
    const observe = () => {
      if (!selected()) { requestAnimationFrame(observe); return; }
      requestAnimationFrame(() => {
        if (!selected()) { requestAnimationFrame(observe); return; }
        const state = window.__xtraceScale;
        state.endMs = performance.now();
        state.elapsedMs = state.endMs - state.startMs;
        state.sequence = '2';
        state.completed = true;
      });
    };
    requestAnimationFrame(observe);
  }, { capture: true });
}

async function waitSelection(page, mode, event, recordingId) {
  await page.waitForFunction(({ mode, sequence, frameId, eventId, recordingId }) => {
    if (document.querySelector('#events-panel h1')?.textContent !== recordingId) return false;
    if (document.querySelector('.recording[aria-current="true"] .recording-title')?.textContent !== recordingId) return false;
    const row = mode === 'steps'
      ? document.querySelector('.event-rail .event[aria-current="true"]')
      : document.querySelector('.canvas-tree [role="treeitem"][aria-selected="true"]');
    if (!row || !row.checkVisibility()) return false;
    if (mode === 'steps' && row.querySelector('.event-seq')?.textContent !== sequence) return false;
    if (mode === 'map' && row.getAttribute('data-key') !== frameId) return false;
    const section = Array.from(document.querySelectorAll('.inspector-section')).find((node) =>
      node.querySelector('.inspector-label')?.textContent === 'Event identity');
    if (section?.querySelector('.inspector-value.mono')?.textContent !== eventId) return false;
    const rect = row.getBoundingClientRect();
    const x = (Math.max(rect.left, 0) + Math.min(rect.right, innerWidth)) / 2;
    const y = (Math.max(rect.top, 0) + Math.min(rect.bottom, innerHeight)) / 2;
    return rect.width > 0 && rect.height > 0 && x >= 0 && x < innerWidth && y >= 0 && y < innerHeight
      && row.contains(document.elementFromPoint(x, y));
  }, { mode, sequence: event.sequence, frameId: event.frameId, eventId: event.eventId, recordingId });
}

async function domSample(page, phase, apiState, heap) {
  const dom = await page.evaluate(() => {
    const visible = (node) => {
      if (!node.checkVisibility()) return false;
      const rect = node.getBoundingClientRect();
      const x = (Math.max(rect.left, 0) + Math.min(rect.right, innerWidth)) / 2;
      const y = (Math.max(rect.top, 0) + Math.min(rect.bottom, innerHeight)) / 2;
      return rect.width > 0 && rect.height > 0 && x >= 0 && x < innerWidth && y >= 0 && y < innerHeight
        && node.contains(document.elementFromPoint(x, y));
    };
    const steps = [...document.querySelectorAll('.event-rail .event')];
    const tree = [...document.querySelectorAll('.canvas-tree [role="treeitem"]')];
    const svg = [...document.querySelectorAll('.canvas-svg .canvas-node')];
    const note = document.querySelector('.event-rail .window-note span')?.textContent ?? '';
    return {
      mountedStepRows: steps.length,
      visibleStepRows: steps.filter(visible).length,
      loadedRailLabelCount: /^\d+ ordered events$/.test(note) ? Number.parseInt(note, 10) : null,
      mapSvgNodes: svg.length,
      visibleMapSvgNodes: svg.filter(visible).length,
      mapTreeRows: tree.length,
      visibleMapTreeRows: tree.filter(visible).length,
      documentElements: document.querySelectorAll('*').length,
    };
  });
  let browserHeap = { status: 'not_requested' };
  if (heap) {
    let cdp;
    try {
      cdp = await page.context().newCDPSession(page);
      const value = await cdp.send('Runtime.getHeapUsage');
      browserHeap = { status: 'measured', usedBytes: value.usedSize, totalBytes: value.totalSize,
        scope: 'CDP Runtime JS heap for this page target; not browser RSS or a forced-GC measurement' };
    } catch { browserHeap = { status: 'unavailable', reason: 'cdp_heap_unsupported_or_failed' }; }
    finally { if (cdp) await cdp.detach().catch(() => {}); }
  }
  return { phase, ...apiState, ...dom, browserHeap };
}

// Failure-only observation: fixed surface names and boolean/numeric facts, never DOM content.
// Do not scroll, focus, click or otherwise change the state whose failure is being diagnosed.
async function selectionDiagnostic(page, mode, event, recordingId) {
  return page.evaluate(({ mode, sequence, frameId, eventId, recordingId }) => {
    const steps = [...document.querySelectorAll('.event-rail .event[aria-current="true"]')];
    const tree = [...document.querySelectorAll('.canvas-tree [role="treeitem"][aria-selected="true"]')];
    const matchingTree = [...document.querySelectorAll('.canvas-tree [role="treeitem"]')]
      .filter((node) => node.getAttribute('data-key') === frameId);
    const svg = [...document.querySelectorAll('.canvas-svg .canvas-node[data-selected="true"]')];
    const sections = [...document.querySelectorAll('.inspector-section')].filter((node) =>
      node.querySelector('.inspector-label')?.textContent === 'Event identity');
    const ancestors = {
      documentRoot: document.documentElement, body: document.body,
      shell: document.querySelector('.shell'), workspace: document.querySelector('.viewer-workspace'),
      stepsAndCode: document.querySelector('.steps-and-code'), codePanel: document.querySelector('#code-panel'),
      eventsPanel: document.querySelector('#events-panel'), eventRail: document.querySelector('.event-rail'),
      mapView: document.querySelector('.canvas-view'), mapScroll: document.querySelector('.canvas-scroll'),
      mapSvg: document.querySelector('.canvas-svg'), mapTree: document.querySelector('.canvas-tree'),
      inspector: document.querySelector('.inspector'), inspectorWorkspace: document.querySelector('.workspace-inspector'),
      evidencePanel: document.querySelector('#evidence-panel'), documentScroller: document.scrollingElement,
    };
    const geometry = (node) => {
      if (!node) return { present: false };
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      const x = (Math.max(rect.left, 0) + Math.min(rect.right, innerWidth)) / 2;
      const y = (Math.max(rect.top, 0) + Math.min(rect.bottom, innerHeight)) / 2;
      const hitPointInViewport = x >= 0 && x < innerWidth && y >= 0 && y < innerHeight;
      const hit = hitPointInViewport ? document.elementFromPoint(x, y) : null;
      const positiveArea = rect.width > 0 && rect.height > 0;
      const checkVisibility = node.checkVisibility();
      return {
        present: true, connected: node.isConnected, checkVisibility,
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
        width: rect.width, height: rect.height, clientWidth: node.clientWidth, clientHeight: node.clientHeight,
        scrollWidth: node.scrollWidth, scrollHeight: node.scrollHeight,
        scrollLeft: node.scrollLeft ?? null, scrollTop: node.scrollTop ?? null,
        displayNone: style.display === 'none', visibilityHidden: style.visibility === 'hidden',
        opacityZero: Number(style.opacity) === 0,
        overflowXClips: ['hidden', 'clip', 'auto', 'scroll'].includes(style.overflowX),
        overflowYClips: ['hidden', 'clip', 'auto', 'scroll'].includes(style.overflowY),
        viewportIntersects: positiveArea && rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight,
        hitPointX: x, hitPointY: y, hitPointInViewport, hitFound: hit !== null,
        hitInsideSurface: hit !== null && node.contains(hit),
        selectionWaitVisibilityPass: checkVisibility && positiveArea && hitPointInViewport && hit !== null && node.contains(hit),
        ancestors: Object.fromEntries(Object.entries(ancestors).map(([key, ancestor]) =>
          [key, ancestor !== null && ancestor !== node && ancestor.contains(node)])),
        hitInside: Object.fromEntries(Object.entries(ancestors).map(([key, ancestor]) =>
          [key, ancestor !== null && hit !== null && ancestor.contains(hit)])),
      };
    };
    const modeButtons = [...document.querySelectorAll('.mode-switch button')];
    const buttons = (label) => modeButtons.filter((node) => node.textContent === label);
    const stepsButtons = buttons('Steps');
    const mapButtons = buttons('Map');
    const selectedStepMatches = steps.filter((node) => node.querySelector('.event-seq')?.textContent === sequence);
    const selectedTreeMatches = tree.filter((node) => node.getAttribute('data-key') === frameId);
    return {
      requestedMap: mode === 'map', viewportWidth: innerWidth, viewportHeight: innerHeight,
      recordingHeaderMatches: document.querySelector('#events-panel h1')?.textContent === recordingId,
      recordingCatalogMatches: document.querySelector('.recording[aria-current="true"] .recording-title')?.textContent === recordingId,
      inspectorIdentitySectionCount: sections.length,
      inspectorIdentityMatchCount: sections.filter((node) => node.querySelector('.inspector-value.mono')?.textContent === eventId).length,
      selectedStepRowCount: steps.length, selectedStepSequenceMatchCount: selectedStepMatches.length,
      selectedTreeRowCount: tree.length, selectedTreeKeyMatchCount: selectedTreeMatches.length,
      expectedTreeKeyMatchCount: matchingTree.length, selectedSvgNodeCount: svg.length,
      // SVG exposes selection only, with no frame-key attribute. Do not infer identity from it.
      svgFrameIdentityComparable: false,
      stepsButtonCount: stepsButtons.length, mapButtonCount: mapButtons.length,
      stepsPressedCount: stepsButtons.filter((node) => node.getAttribute('aria-selected') === 'true').length,
      mapPressedCount: mapButtons.filter((node) => node.getAttribute('aria-selected') === 'true').length,
      surfaces: {
        stepsButton: geometry(stepsButtons[0]), mapButton: geometry(mapButtons[0]),
        selectedStep: geometry(steps[0]), selectedTree: geometry(tree[0]), expectedTree: geometry(matchingTree[0]),
        selectedSvg: geometry(svg[0]), inspectorIdentity: geometry(sections[0]),
        ...Object.fromEntries(Object.entries(ancestors).map(([key, node]) => [key, geometry(node)])),
      },
    };
  }, { mode, sequence: event.sequence, frameId: event.frameId, eventId: event.eventId, recordingId });
}

async function detailFromAction(page, manifest, expectedCursor, action) {
  const recordingId = manifest.recording_id;
  const [response] = await Promise.all([
    page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/api/v1/recordings/${recordingId}`
        && url.searchParams.get('cursor') === expectedCursor;
    }),
    action(),
  ]);
  check(response.status() === 200 && response.request().method() === 'GET');
  check(new URL(response.url()).searchParams.get('limit') === '200');
  const detail = await response.json();
  check(detail.recordingId === recordingId && detail.projectId === manifest.project_id);
  check(detail.status === 'complete' && detail.completion === 'complete');
  check(detail.cursor === expectedCursor && detail.events.length > 0 && detail.events.length <= 200);
  check(detail.capacity?.eventCount === 10_000 && detail.capacity?.capacityDroppedEvents === '0');
  let priorSequence = null;
  const frameIds = new Set();
  for (const event of detail.events) {
    check(/^\d+$/.test(event.sequence) && typeof event.frameId === 'string');
    check(event.eventId === `synthetic-scale-${event.sequence.padStart(5, '0')}`);
    if (priorSequence !== null) check(BigInt(event.sequence) === priorSequence + 1n);
    priorSequence = BigInt(event.sequence);
    check(!frameIds.has(event.frameId));
    frameIds.add(event.frameId);
  }
  return detail;
}

async function measureSample(index, options, manifest, chromium) {
  const result = { sample: index, status: 'failed', stage: 'viewer_start', substage: null,
    initial: null, dom: [], actions: [], modeTransitions: [], failures: [] };
  const setStage = (stage, substage = null) => { result.stage = stage; result.substage = substage; };
  let viewer;
  let browser;
  let context;
  let page;
  let pageErrors = null;
  let externalRequests = null;
  let expectedMode = 'steps';
  let expectedSelection;
  let detail;
  let cumulative = 0;
  const apiState = () => ({ apiLastPageEvents: detail?.events.length ?? null, apiEventsReturnedCumulative: cumulative });
  try {
    viewer = startViewer(options.xtrace, manifest);
    const url = await viewer.ready;
    setStage('browser_start');
    browser = await chromium.launch({ headless: true });
    result.browserVersion = browser.version();
    context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1, locale: 'en-US',
      timezoneId: 'UTC', colorScheme: 'light', reducedMotion: 'no-preference' });
    page = await context.newPage();
    page.setDefaultTimeout(ACTION_TIMEOUT);
    page.setDefaultNavigationTimeout(30_000);
    pageErrors = 0;
    externalRequests = 0;
    page.on('pageerror', () => { pageErrors += 1; });
    page.on('request', (request) => { if (new URL(request.url()).origin !== new URL(url).origin) externalRequests += 1; });
    await page.addInitScript(installClickClock, { recordingId: manifest.recording_id });
    setStage('catalog');
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'Not linked to an endpoint', exact: true }).click();
    const recording = page.locator('.recording').filter({ has: page.locator('.recording-title', { hasText: manifest.recording_id }) });
    await recording.waitFor({ state: 'visible' });
    check(await recording.count() === 1);

    setStage('initial_click_response');
    detail = await detailFromAction(page, manifest, null, () => recording.click());
    check(detail.events[0].sequence === '2');
    let selected = detail.events[0];
    expectedSelection = selected;
    cumulative = detail.events.length;
    setStage('initial_visible_paint_opportunity');
    await page.waitForFunction(() => window.__xtraceScale?.completed === true);
    const clock = await page.evaluate(() => ({ ...window.__xtraceScale }));
    check(clock.trusted && clock.sequence === selected.sequence && Number.isFinite(clock.elapsedMs));
    await waitSelection(page, 'steps', selected, manifest.recording_id);
    result.initial = { elapsedMs: clock.elapsedMs, over1500Ms: clock.elapsedMs > 1500,
      apiFirstPageEvents: detail.events.length, selectedIdentitySha256: identity(selected),
      responseAndUiIdentityMatched: true, trustedClickCaptured: true, paintOpportunityObserved: true };
    let lastSequence = BigInt(detail.events.at(-1).sequence);
    setStage('initial_steps', 'dom_snapshot');
    result.dom.push(await domSample(page, 'initial_steps', apiState(), options['cdp-heap']));
    const mode = page.getByRole('tablist', { name: 'Replay view', exact: true });
    const navigation = page.getByRole('group', { name: 'Replay navigation', exact: true });
    const switchMode = async (target, phase) => {
      setStage(phase, 'mode_click');
      expectedMode = target;
      expectedSelection = selected;
      const button = mode.getByRole('tab', { name: target === 'map' ? 'Map' : 'Steps', exact: true });
      const transition = { phase, requestedMap: target === 'map', clickCompleted: false,
        pressedObserved: null, selectionMatched: false };
      result.modeTransitions.push(transition);
      await button.click();
      transition.clickCompleted = true;
      result.substage = 'mode_pressed';
      transition.pressedObserved = await button.getAttribute('aria-selected') === 'true';
      check(transition.pressedObserved);
      result.substage = 'selection_wait';
      await waitSelection(page, target, selected, manifest.recording_id);
      transition.selectionMatched = true;
      result.actions.push(phase);
      result.substage = 'dom_snapshot';
      const snapshot = await domSample(page, phase, apiState(), options['cdp-heap']);
      result.substage = 'dom_assertions';
      result.dom.push(snapshot);
      check(target === 'map' ? snapshot.mapSvgNodes > 0 && snapshot.mapTreeRows > 0 : snapshot.mountedStepRows > 0);
    };
    const navigateBoth = async (target, events, phase) => {
      setStage(phase, 'next_event_lookup');
      expectedMode = target;
      const original = selected;
      const next = events[events.findIndex((event) => event.frameId === original.frameId) + 1];
      check(next && next.frameId !== original.frameId);
      result.substage = 'next_click';
      expectedSelection = next;
      await navigation.getByRole('button', { name: 'Next', exact: true }).click();
      result.substage = 'next_selection_wait';
      await waitSelection(page, target, next, manifest.recording_id);
      result.substage = 'back_click';
      expectedSelection = original;
      await navigation.getByRole('button', { name: 'Back', exact: true }).click();
      result.substage = 'back_selection_wait';
      await waitSelection(page, target, original, manifest.recording_id);
      result.actions.push(`${phase}_next`, `${phase}_back`);
    };
    await navigateBoth('steps', detail.events, 'initial_steps_navigation');
    await switchMode('map', 'initial_map');
    await navigateBoth('map', detail.events, 'initial_map_navigation');
    await switchMode('steps', 'initial_steps_return');

    for (let later = 1; later <= options['later-pages']; later += 1) {
      setStage(`load_later_${later}`, 'detail_response');
      check(typeof detail.nextCursor === 'string');
      detail = await detailFromAction(page, manifest, detail.nextCursor,
        () => page.getByRole('button', { name: 'Load next window', exact: true }).click());
      for (const event of detail.events) { check(BigInt(event.sequence) === lastSequence + 1n); lastSequence += 1n; }
      cumulative += detail.events.length;
      selected = detail.events[0];
      expectedSelection = selected;
      const row = page.locator('.event-rail .event').filter({
        has: page.locator('.event-seq').filter({ hasText: new RegExp(`^${selected.sequence}$`) }),
      });
      result.substage = 'row_click';
      await row.click();
      result.substage = 'selection_wait';
      await waitSelection(page, 'steps', selected, manifest.recording_id);
      result.actions.push(`load_later_${later}`);
    }
    setStage('later_steps', 'dom_snapshot');
    result.dom.push(await domSample(page, 'later_steps', apiState(), options['cdp-heap']));
    await navigateBoth('steps', detail.events, 'later_steps_navigation');
    await switchMode('map', 'later_map');
    await navigateBoth('map', detail.events, 'later_map_navigation');
    await switchMode('steps', 'later_steps_return');
    setStage('page_observations');
    check(pageErrors === 0 && externalRequests === 0);
    result.status = 'exercised';
    setStage('complete');
  } catch {
    // Never serialize exception messages, URLs, response bodies, DOM text or Playwright traces.
    result.failures.push({ stage: result.stage, substage: result.substage, code: 'journey_failed_or_unreached' });
    if (page) {
      // Preserve the functional failure first; either diagnostic may itself be unavailable.
      const observation = { stage: result.stage, substage: result.substage,
        selection: { status: 'unavailable' }, dom: { status: 'unavailable' } };
      result.failureObservation = observation;
      try {
        if (expectedSelection) observation.selection = { status: 'observed',
          ...await boundedDiagnostic(() => selectionDiagnostic(page, expectedMode, expectedSelection, manifest.recording_id)) };
      } catch { /* Bounded status only; diagnostic errors must not replace the journey failure. */ }
      try {
        const snapshot = await boundedDiagnostic(() => domSample(page, `failed_${result.stage}`, apiState(), options['cdp-heap']));
        result.dom.push(snapshot);
        observation.dom = { status: 'observed', phase: snapshot.phase };
      } catch { /* A closed page still retains the original failure and unavailable status. */ }
    }
  } finally {
    result.pageErrors = pageErrors;
    result.externalRequests = externalRequests;
    try { if (context) await context.close(); if (browser) await browser.close(); }
    catch { result.failures.push({ stage: 'browser_cleanup', code: 'cleanup_failed' }); }
    try { if (viewer) await stopViewer(viewer.child); }
    catch { result.failures.push({ stage: 'viewer_cleanup', code: 'cleanup_failed' }); }
    if (result.failures.length) result.status = 'failed';
  }
  return result;
}

async function main() {
  const { values: options } = parseArgs({ options: {
    manifest: { type: 'string' }, xtrace: { type: 'string' }, out: { type: 'string' },
    'source-sha': { type: 'string' }, provenance: { type: 'string' },
    'package-sha256': { type: 'string' }, 'later-pages': { type: 'string', default: '12' },
    'cdp-heap': { type: 'boolean', default: false },
  } });
  check(options.manifest && options.xtrace && options.out && /^[a-f0-9]{40}$/.test(options['source-sha']));
  check(['source-built', 'installed'].includes(options.provenance));
  if (options['package-sha256']) check(/^[a-f0-9]{64}$/.test(options['package-sha256']));
  if (options.provenance === 'installed') check(options['package-sha256']);
  options['later-pages'] = Number(options['later-pages']);
  check(Number.isInteger(options['later-pages']) && options['later-pages'] >= 1 && options['later-pages'] <= 49);
  const metadata = await lstat(options.manifest);
  check(metadata.isFile() && (metadata.mode & 0o077) === 0);
  const manifest = JSON.parse(await readFile(options.manifest, 'utf8'));
  check(manifest.schema_version === 1 && manifest.synthetic === true && manifest.verified_frame_count === 10_000);
  check(/^[a-f0-9-]{36}$/.test(manifest.recording_id));
  check(/^[a-f0-9-]{36}$/.test(manifest.project_id));
  const root = await realpath(manifest.fixture_root);
  check(((await lstat(root)).mode & 0o077) === 0);
  for (const field of ['project_dir', 'data_home']) check((await realpath(manifest[field])).startsWith(`${root}${path.sep}`));
  options.xtrace = await realpath(options.xtrace);
  const require = createRequire(new URL('../../web/app/package.json', import.meta.url));
  const { chromium } = require('@playwright/test');
  const output = await open(options.out, 'wx', 0o600);
  const report = {
    schemaVersion: 1, kind: 'synthetic_replay_scale_browser', synthetic: true,
    provenance: { declaredSourceSha: options['source-sha'], distribution: options.provenance,
      binarySha256: sha256(await readFile(options.xtrace)), declaredPackageSha256: options['package-sha256'] ?? null },
    conditions: { samples: SAMPLES, viewport: VIEWPORT, headless: true, deviceScaleFactor: 1,
      locale: 'en-US', timezone: 'UTC', colorScheme: 'light', reducedMotion: 'no-preference',
      freshBrowserProcessContextAndViewerPerSample: true, cpuOrNetworkThrottling: 'none',
      osAndFilesystemCaches: 'uncontrolled; may be warm', fixtureFrames: 10_000, laterPages: options['later-pages'],
      timing: 'trusted recording-click capture to visible selected first row after intervening rAF paint opportunity; no physical-display claim',
      excludedFromTiming: ['fixture seeding', 'viewer startup', 'catalog loading'],
      domScope: 'mounted current document; visible counts require viewport hit-test; Map SVG and accessible tree counted separately',
      runner: { platform: os.platform(), release: os.release(), arch: os.arch(), cpuModel: os.cpus()[0]?.model ?? 'unavailable', cpuCount: os.cpus().length },
    }, samples: [],
  };
  try {
    for (let index = 1; index <= SAMPLES; index += 1) report.samples.push(await measureSample(index, options, manifest, chromium));
    // A later functional failure cannot erase an already valid initial observation.
    const times = report.samples.filter((sample) => sample.initial !== null).map((sample) => sample.initial.elapsedMs).sort((a, b) => a - b);
    const middle = Math.floor(times.length / 2);
    report.summary = { functionalFailures: report.samples.filter((sample) => sample.status !== 'exercised').length,
      completeJourneySamples: report.samples.filter((sample) => sample.status === 'exercised').length,
      validInitialSamples: times.length, medianMs: times.length ? (times[middle] + times[Math.floor((times.length - 1) / 2)]) / 2 : null,
      maxMs: times.length ? times.at(-1) : null, samplesOver1500Ms: times.filter((value) => value > 1500).length,
      aggregationDecision: 'unsettled; descriptive statistics only', memoryThreshold: 'unsettled' };
    await output.writeFile(`${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify(report));
    if (report.summary.functionalFailures) process.exitCode = 1;
  } finally { await output.close(); }
}

main().catch(() => { console.error('replay_scale_browser: setup_or_output_failed'); process.exitCode = 2; });
