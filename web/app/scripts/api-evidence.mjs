// Browser-response capture. This never issues, retries, fulfills or rewrites a request.
export const API_CAPTURE_PHASES = ['headers', 'finish', 'body', 'bounds', 'write'];
export const API_CAPTURE_CATEGORIES = ['response-limit', 'header-limit', 'request-aborted', 'request-failed',
  'context-closed', 'navigation-invalidated', 'finish-unavailable', 'body-unavailable', 'body-timeout',
  'body-limit', 'write-failed', 'write-timeout', 'drain-timeout', 'coverage-gap'];
export const API_CAPTURE_RESOURCES = ['auth', 'endpoints', 'linked', 'recordings', 'detail', 'preview', 'save', 'other'];
const BODY_LIMIT = 32 * 1024 * 1024;
const RESPONSE_LIMIT = 4096;
const DEADLINE = 10_000;

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function beforeDeadline(operation, deadline, category) {
  if (Date.now() >= deadline) throw new CaptureFailure(category);
  let timer;
  try {
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new CaptureFailure(category)), Math.max(0, deadline - Date.now()));
    })]);
  } finally { clearTimeout(timer); }
}

class CaptureFailure extends Error {}

/** Ignore parameters and case; +json is a structured JSON media-type suffix. */
export function isJsonMediaType(contentType) {
  if (typeof contentType !== 'string') return false;
  const mediaType = contentType.split(';', 1)[0].trim();
  return /^application\/(?:json|[!#$%&'*+.^_`|~a-z0-9-]+\+json)$/i.test(mediaType);
}

/**
 * Install before navigation. The viewer uses only auth response headers to advance;
 * drain a clone of that same response so Chromium can finish without changing the
 * Response, promise, or body state observed by the viewer.
 *
 * This function runs in the browser and must be self-contained.
 */
function drainAuthExchange({ origin, bodyLimit, timeout }) {
  if (window.top !== window || window.location.origin !== origin) return;
  const fetch = window.fetch;
  const authUrl = origin + '/api/v1/auth/exchange';
  const json = /^application\/(?:json|[!#$%&'*+.^_\x60|~a-z0-9-]+\+json)$/i;
  async function consume(response) {
    if (response.url !== authUrl || response.redirected) return;
    const type = response.headers.get('content-type')?.split(';', 1)[0].trim();
    if (!type || !json.test(type)) return;
    const length = Number(response.headers.get('content-length') ?? 0);
    if (!Number.isSafeInteger(length) || length < 0 || length > bodyLimit) return;

    const reader = response.clone().body?.getReader();
    if (!reader) return;
    let stopped = false;
    const stop = () => {
      stopped = true;
      // The original tee branch may remain unread. Do not wait on its cancellation.
      void reader.cancel().catch(() => {});
    };
    const timer = setTimeout(stop, timeout);
    try {
      let remaining = bodyLimit;
      while (!stopped) {
        const { value, done } = await reader.read();
        if (done || stopped) return;
        remaining -= value.byteLength;
        if (remaining < 0) stop();
      }
    } finally {
      clearTimeout(timer);
      reader.releaseLock();
    }
  }
  window.fetch = function (...args) {
    const result = Reflect.apply(fetch, this, args);
    try {
      const [input, init] = args;
      const request = input instanceof Request ? input : null;
      const url = new URL(request ? request.url : input, window.location.href);
      const method = init?.method ?? request?.method ?? 'GET';
      if (url.href === authUrl && typeof method === 'string' && method.toUpperCase() === 'POST') {
        // The collector still requires Playwright's real completion event and original bytes.
        // Do not publish, supply substitute bytes, or log browser-side drain failures.
        void result.then(consume).catch(() => {});
      }
    } catch {
      // A local diagnostic must preserve the viewer's original fetch behavior.
    }
    return result;
  };
}

function resource(path) {
  if (path === '/api/v1/auth/exchange') return 'auth';
  if (path === '/api/v1/endpoints') return 'endpoints';
  if (/^\/api\/v1\/endpoints\/[^/]+\/recordings$/.test(path)) return 'linked';
  if (path === '/api/v1/recordings') return 'recordings';
  if (/^\/api\/v1\/recordings\/[^/]+$/.test(path)) return 'detail';
  if (path === '/api/v1/exports/preview') return 'preview';
  if (path === '/api/v1/exports/save') return 'save';
  return 'other';
}

export function newApiEvidence() {
  return {
    schemaVersion: 1, status: 'not-reached', sealed: false,
    counts: { requests: 0, responses: 0, jsonResponses: 0, nonJsonResponses: 0, terminalRequests: 0,
      abortedBeforeResponse: 0, teardownAborted: 0, activeRequests: 0, pendingCaptures: 0, bytesWritten: 0 },
    phases: Object.fromEntries(API_CAPTURE_PHASES.map((name) => [name, { started: 0, passed: 0, failed: 0 }])),
    resources: Object.fromEntries(API_CAPTURE_RESOURCES.map((name) => [name, { responses: 0, written: 0 }])),
    failures: Object.fromEntries(API_CAPTURE_CATEGORIES.map((name) => [name, 0])),
  };
}

/**
 * Capture every observed local JSON API response while its browser target is alive.
 * A browser cancellation before headers has no response payload; it is counted explicitly.
 * A JSON response whose body is unavailable is always a failure, including after an abort.
 * The cleanup fence aborts only new API requests after the workload's final assertion.
 */
export function apiEvidence({ page, origin, write, state }) {
  const evidence = state ?? newApiEvidence();
  evidence.status = 'in-progress';
  const records = new WeakMap();
  let changed = deferred();
  let generation = 0;
  let closed = false;
  let preparation;
  const notify = () => {
    if (evidence.status === 'pass' && (evidence.counts.activeRequests || evidence.counts.pendingCaptures)) evidence.status = 'in-progress';
    changed.resolve(); changed = deferred();
  };
  const fail = (category) => { evidence.failures[category] += 1; evidence.status = 'fail'; notify(); };
  const isApi = (request) => {
    const url = new URL(request.url());
    return url.origin === origin && url.pathname.startsWith('/api/v1/');
  };
  function admit(request) {
    if (!isApi(request)) return;
    let record = records.get(request);
    if (record) return record;
    evidence.counts.requests += 1;
    evidence.counts.activeRequests += 1;
    record = { request, response: null, terminal: false, admittedAfterFence: evidence.sealed,
      teardownAbortRequested: false, generation };
    records.set(request, record);
    if (evidence.counts.requests > RESPONSE_LIMIT) fail('response-limit');
    notify();
    return record;
  }
  function failureCategory(record, fallback) {
    if (closed || page.isClosed()) return 'context-closed';
    if (record.request.failure()) return record.request.failure().errorText === 'net::ERR_ABORTED' ? 'request-aborted' : 'request-failed';
    if (record.generation !== generation) return 'navigation-invalidated';
    return fallback;
  }
  function terminal(request) {
    const record = records.get(request) ?? admit(request);
    if (!record || record.terminal) return;
    record.terminal = true;
    evidence.counts.terminalRequests += 1;
    evidence.counts.activeRequests -= 1;
    if (!record.response) {
      if (request.failure()?.errorText === 'net::ERR_ABORTED') {
        if (record.teardownAbortRequested) evidence.counts.teardownAborted += 1;
        else evidence.counts.abortedBeforeResponse += 1;
      } else fail(failureCategory(record, 'finish-unavailable'));
    }
    notify();
  }
  async function capture(record) {
    const { response } = record;
    const index = evidence.counts.jsonResponses++;
    const group = evidence.resources[resource(new URL(response.url()).pathname)];
    group.responses += 1;
    evidence.counts.pendingCaptures += 1;
    const deadline = Date.now() + DEADLINE;
    let activePhase;
    const run = async (name, operation, timeoutCategory, fallback) => {
      const phase = evidence.phases[name];
      phase.started += 1;
      activePhase = phase;
      try {
        const result = await beforeDeadline(Promise.resolve().then(operation), deadline, timeoutCategory);
        phase.passed += 1;
        activePhase = undefined;
        return result;
      } catch (error) {
        throw error instanceof CaptureFailure ? error : new CaptureFailure(failureCategory(record, fallback));
      }
    };
    try {
      await run('headers', () => {
        const length = Number(response.headers()['content-length'] ?? 0);
        if (!Number.isSafeInteger(length) || length < 0 || length > BODY_LIMIT) throw new CaptureFailure('header-limit');
        if (index >= RESPONSE_LIMIT) throw new CaptureFailure('response-limit');
      }, 'body-timeout', 'header-limit');
      await run('finish', async () => {
        await response.finished();
        if (record.request.failure()) throw new CaptureFailure(failureCategory(record, 'request-failed'));
      }, 'body-timeout', 'finish-unavailable');
      const body = await run('body', () => response.body(), 'body-timeout', 'body-unavailable');
      await run('bounds', () => {
        if (!Buffer.isBuffer(body) || body.length > BODY_LIMIT) throw new CaptureFailure('body-limit');
      }, 'body-timeout', 'body-limit');
      const controller = new AbortController();
      activePhase = evidence.phases.write;
      activePhase.started += 1;
      try {
        await beforeDeadline(Promise.resolve().then(() => write(`api-${index}.json`, body, controller.signal)), deadline, 'write-timeout');
        // Credit the file, byte count and resource together before a checkpoint can observe them.
        activePhase.passed += 1;
        activePhase = undefined;
        evidence.counts.bytesWritten += body.length;
        group.written += 1;
      } catch (error) {
        throw error instanceof CaptureFailure ? error : new CaptureFailure('write-failed');
      } finally { controller.abort(); }
    } catch (error) {
      if (activePhase) activePhase.failed += 1;
      fail(error instanceof CaptureFailure ? error.message : 'body-unavailable');
    } finally {
      evidence.counts.pendingCaptures -= 1;
      notify();
    }
  }
  function response(response) {
    const record = records.get(response.request()) ?? admit(response.request());
    if (!record || record.response) return;
    record.response = response;
    evidence.counts.responses += 1;
    if (isJsonMediaType(response.headers()['content-type'])) void capture(record);
    else evidence.counts.nonJsonResponses += 1;
    notify();
  }
  page.on('request', admit);
  page.on('response', response);
  page.on('requestfinished', terminal);
  page.on('requestfailed', terminal);
  page.on('framenavigated', (frame) => { if (frame === page.mainFrame()) generation += 1; });
  page.on('close', () => { closed = true; notify(); });
  page.context().on('close', () => { closed = true; notify(); });

  function complete() {
    const counts = evidence.counts;
    const failed = Object.values(evidence.failures).some(Boolean);
    const accounted = counts.requests === counts.terminalRequests && counts.activeRequests === 0 && counts.pendingCaptures === 0
      && counts.responses === counts.jsonResponses + counts.nonJsonResponses
      && counts.requests === counts.responses + counts.abortedBeforeResponse + counts.teardownAborted
      && counts.jsonResponses === evidence.phases.write.passed;
    evidence.status = failed || !accounted ? 'fail' : evidence.sealed ? 'pass' : 'in-progress';
    return evidence.status === 'pass';
  }
  return {
    evidence, isApi,
    prepare() {
      // The driver must await the init script's acknowledgment before page.goto.
      preparation ??= beforeDeadline(
        Promise.resolve().then(() => page.addInitScript(drainAuthExchange, {
          origin, bodyLimit: BODY_LIMIT, timeout: DEADLINE,
        })), Date.now() + DEADLINE, 'finish-unavailable',
      ).catch(() => {
        fail('finish-unavailable');
        throw new Error('api-evidence-write');
      });
      return preparation;
    },
    shouldAbort(request) {
      if (!evidence.sealed || !isApi(request)) return false;
      const record = records.get(request) ?? admit(request);
      // Playwright may emit Request before dispatching its interception callback.
      if (!record.admittedAfterFence || record.terminal) return false;
      record.teardownAbortRequested = true;
      return true;
    },
    async drain() {
      evidence.sealed = true;
      const deadline = Date.now() + DEADLINE;
      try {
        while (evidence.counts.activeRequests || evidence.counts.pendingCaptures) {
          await beforeDeadline(changed.promise, deadline, 'drain-timeout');
        }
      } catch { fail('drain-timeout'); }
      if (!complete()) throw new Error('api-evidence-write');
    },
    verifyCoverage() {
      // Two scopes × five formats; only JSON OpenAPI and Postman saves are JSON responses.
      const minima = { auth: 1, endpoints: 1, linked: 1, detail: 1, preview: 10, save: 4 };
      if (Object.entries(minima).some(([name, minimum]) => evidence.resources[name].written < minimum)) fail('coverage-gap');
      if (!complete()) throw new Error('api-evidence-write');
    },
  };
}
