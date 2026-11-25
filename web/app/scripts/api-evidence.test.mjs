// @vitest-environment node
// Collector lifetime regressions; these are not installed-product receipts.
import { EventEmitter } from 'node:events';
import { runInNewContext } from 'node:vm';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { apiEvidence, isJsonMediaType } from './api-evidence.mjs';

const origin = 'http://127.0.0.1:1234';
const privateError = 'private-path-payload-message-must-not-project';
const directories = [];
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
};
function harness(write = vi.fn(async () => undefined)) {
  const context = new EventEmitter();
  const page = new EventEmitter();
  let closed = false;
  const frame = {};
  Object.assign(page, { context: () => context, isClosed: () => closed, mainFrame: () => frame,
    addInitScript: vi.fn(async () => undefined) });
  const capture = apiEvidence({ page, origin, write });
  const close = () => { closed = true; context.emit('close'); page.emit('close'); };
  const request = (path = '/api/v1/exports/preview') => {
    let failure = null;
    const request = { url: () => origin + path, failure: () => failure };
    page.emit('request', request);
    return { request, finish: () => page.emit('requestfinished', request),
      fail: (errorText = 'net::ERR_ABORTED') => { failure = { errorText }; page.emit('requestfailed', request); } };
  };
  const response = (entry, { body = async () => Buffer.from('{}'), finished, headers = {} } = {}) => {
    const completed = deferred();
    const bodyStarted = deferred();
    const response = { request: () => entry.request, url: entry.request.url,
      headers: () => ({ 'content-type': 'application/json', ...headers }),
      finished: finished ?? (() => completed.promise), body: vi.fn(() => { bodyStarted.resolve(); return body(); }) };
    page.emit('response', response);
    return { response, bodyStarted: bodyStarted.promise, complete: () => { entry.finish(); completed.resolve(); } };
  };
  return { capture, page, request, response, close, frame, write };
}
afterEach(async () => {
  vi.useRealTimers();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
});

function installAuthInitScript(test, fetch, startOrigin = origin) {
  const [script, options] = test.page.addInitScript.mock.calls[0];
  const window = { fetch, location: new URL(startOrigin + '/') };
  window.top = window;
  // Match Playwright's serialized init-script execution rather than importing node closures.
  runInNewContext('(' + script.toString() + ')(options)', {
    window, options, URL, Request, setTimeout, clearTimeout,
  });
  return window;
}

const authPath = '/api/v1/auth/exchange';

it('drains the original auth response without replacing the viewer promise or replaying the request', async () => {
  const test = harness();
  await Promise.all([test.capture.prepare(), test.capture.prepare()]);
  expect(test.page.addInitScript).toHaveBeenCalledTimes(1);
  const startRead = deferred();
  const userData = deferred();
  const payload = Buffer.from('{"authenticated":true,"requestId":"private-id"}');
  const entry = test.request(authPath);
  const transport = test.response(entry, { body: async () => payload });
  let chunk = 0;
  const reader = {
    cancel: vi.fn(async () => undefined),
    releaseLock: vi.fn(),
    read: vi.fn(async () => {
      if (chunk++ === 0) {
        startRead.resolve();
        return { value: await userData.promise, done: false };
      }
      // Model a body that has no finish signal until a browser consumer drains it.
      transport.complete();
      return { done: true };
    }),
  };
  const original = { url: origin + authPath, ok: true, bodyUsed: false,
    headers: new Headers({ 'content-type': 'application/json' }),
    clone: vi.fn(() => ({ body: { getReader: () => reader } })) };
  const promise = Promise.resolve(original);
  const fetch = vi.fn(() => promise);
  const window = installAuthInitScript(test, fetch);
  const init = { method: 'POST', body: '{"token":"private-token"}' };
  const returned = window.fetch(authPath, init);
  expect(returned).toBe(promise);
  expect(await returned).toBe(original);
  expect(original.bodyUsed).toBe(false);
  await startRead.promise;
  const drained = test.capture.drain();
  expect(test.capture.evidence.counts.activeRequests).toBe(1);
  expect(transport.response.body).not.toHaveBeenCalled();
  userData.resolve(payload);
  await drained;
  expect(fetch).toHaveBeenCalledExactlyOnceWith(authPath, init);
  expect(original.clone).toHaveBeenCalledTimes(1);
  expect(reader.cancel).not.toHaveBeenCalled();
  expect(reader.releaseLock).toHaveBeenCalledTimes(1);
  expect(test.write).toHaveBeenCalledExactlyOnceWith('api-0.json', payload, expect.any(AbortSignal));
  expect(test.capture.evidence.resources.auth).toEqual({ responses: 1, written: 1 });
  expect(test.capture.evidence.counts).toMatchObject({ terminalRequests: 1, activeRequests: 0, pendingCaptures: 0 });
  expect(JSON.stringify(test.capture.evidence)).not.toContain('private-id');
  expect(JSON.stringify(test.capture.evidence)).not.toContain('private-token');
});

it.each([
  ['GET', authPath, origin, origin + authPath, 'application/json', false],
  ['POST', '/api/v1/exports/preview', origin, origin + '/api/v1/exports/preview', 'application/json', false],
  ['POST', 'http://127.0.0.1:4321' + authPath, origin, 'http://127.0.0.1:4321' + authPath, 'application/json', false],
  ['POST', authPath, 'http://127.0.0.1:4321', origin + authPath, 'application/json', false],
  ['POST', authPath, origin, origin + authPath, 'text/plain', false],
  ['POST', authPath, origin, origin + authPath, 'application/json', true],
])('limits browser draining to the original local auth JSON response (%s %s from %s)', async (
  method, input, startOrigin, responseUrl, type, redirected,
) => {
  const test = harness();
  await test.capture.prepare();
  const original = { url: responseUrl, redirected, headers: new Headers({ 'content-type': type }), clone: vi.fn() };
  const promise = Promise.resolve(original);
  const fetch = vi.fn(() => promise);
  const window = installAuthInitScript(test, fetch, startOrigin);
  const returned = window.fetch(input, { method });
  expect(returned).toBe(promise);
  await returned;
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(original.clone).not.toHaveBeenCalled();
});

it('keeps a failed init-script acknowledgment fixed and fail-closed', async () => {
  const test = harness();
  test.page.addInitScript.mockRejectedValue(new Error(privateError));
  await expect(test.capture.prepare()).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.failures['finish-unavailable']).toBe(1);
  expect(JSON.stringify(test.capture.evidence)).not.toContain(privateError);
  await expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
});

it('bounds the diagnostic clone drain without crediting a missing terminal event or body', async () => {
  vi.useFakeTimers();
  const test = harness();
  await test.capture.prepare();
  const pending = deferred();
  const started = deferred();
  const reader = { releaseLock: vi.fn(),
    read: vi.fn(() => { started.resolve(); return pending.promise; }),
    cancel: vi.fn(() => {
      pending.resolve({ done: true });
      // Cancel of one tee branch can await disposal of the original unread branch.
      return new Promise(() => {});
    }) };
  const response = { url: origin + authPath, headers: new Headers({ 'content-type': 'application/json' }),
    clone: () => ({ body: { getReader: () => reader } }) };
  const window = installAuthInitScript(test, () => Promise.resolve(response));
  test.response(test.request(authPath));
  await window.fetch(authPath, { method: 'POST' });
  await started.promise;
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  await vi.advanceTimersByTimeAsync(10_000);
  await drained;
  expect(reader.cancel).toHaveBeenCalledTimes(1);
  expect(reader.releaseLock).toHaveBeenCalledTimes(1);
  expect(test.capture.evidence.resources.auth).toEqual({ responses: 1, written: 0 });
  expect(test.capture.evidence.phases.finish.failed).toBe(1);
  expect(test.write).not.toHaveBeenCalled();
});

it('never substitutes clone EOF for an actual Playwright terminal event', async () => {
  vi.useFakeTimers();
  const test = harness();
  await test.capture.prepare();
  const eof = deferred();
  const response = { url: origin + authPath, headers: new Headers({ 'content-type': 'application/json' }),
    clone: () => ({ body: { getReader: () => ({
      read: async () => ({ done: true }),
      releaseLock: () => eof.resolve(),
    }) } }) };
  const window = installAuthInitScript(test, () => Promise.resolve(response));
  const transport = test.response(test.request(authPath));
  await window.fetch(authPath, { method: 'POST' });
  await eof.promise;
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  await vi.advanceTimersByTimeAsync(10_000);
  await drained;
  expect(test.capture.evidence.counts).toMatchObject({ activeRequests: 1, terminalRequests: 0 });
  expect(test.capture.evidence.resources.auth).toEqual({ responses: 1, written: 0 });
  expect(transport.response.body).not.toHaveBeenCalled();
  expect(test.write).not.toHaveBeenCalled();
});

it('drains the original response and private write before the browser target closes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'api-evidence-'));
  directories.push(directory);
  const payload = deferred();
  const test = harness((name, body, signal) => writeFile(join(directory, name), body, { flag: 'wx', mode: 0o600, signal }));
  const entry = test.request();
  const result = test.response(entry, { body: () => payload.promise });
  const drained = test.capture.drain();
  expect(result.response.body).not.toHaveBeenCalled();
  result.complete();
  await result.bodyStarted;
  expect(test.capture.evidence.counts.pendingCaptures).toBe(1);
  payload.resolve(Buffer.from('{"observed":true}'));
  await drained;
  test.close();
  expect(await readFile(join(directory, 'api-0.json'), 'utf8')).toBe('{"observed":true}');
  expect((await stat(join(directory, 'api-0.json'))).mode & 0o777).toBe(0o600);
  expect(test.capture.evidence.status).toBe('pass');
  expect(test.capture.evidence.phases.write.passed).toBe(1);
});

it('includes a late response from a request already active at the cleanup fence', async () => {
  const test = harness();
  const entry = test.request('/api/v1/endpoints');
  const drained = test.capture.drain();
  const result = test.response(entry);
  result.complete();
  await drained;
  expect(test.write).toHaveBeenCalledExactlyOnceWith('api-0.json', Buffer.from('{}'), expect.any(AbortSignal));
  expect(test.capture.evidence.resources.endpoints).toEqual({ responses: 1, written: 1 });
});

it('continues pre-fence requests with delayed interception and drains their late JSON write', async () => {
  const writeStarted = deferred();
  const writeFinished = deferred();
  const payload = Buffer.from('{"late":true}');
  const test = harness(vi.fn(async (_name, body) => {
    if (body.equals(payload)) {
      writeStarted.resolve();
      await writeFinished.promise;
    }
  }));
  for (const [path, count] of [['/api/v1/auth/exchange', 1], ['/api/v1/endpoints', 1],
    ['/api/v1/endpoints/orders/recordings', 1], ['/api/v1/recordings/order', 1],
    ['/api/v1/exports/preview', 10], ['/api/v1/exports/save', 4]]) {
    for (let index = 0; index < count; index += 1) test.response(test.request(path)).complete();
  }
  const entry = test.request('/api/v1/recordings');
  const drained = test.capture.drain();
  let settled = false;
  void drained.then(() => { settled = true; }, () => { settled = true; });
  expect(test.capture.shouldAbort(entry.request)).toBe(false);
  expect(test.capture.evidence.counts.activeRequests).toBe(1);
  expect(test.capture.evidence.counts.teardownAborted).toBe(0);
  const result = test.response(entry, { body: async () => payload });
  result.complete();
  await writeStarted.promise;
  expect(test.capture.evidence.counts.activeRequests).toBe(0);
  expect(test.capture.evidence.counts.pendingCaptures).toBeGreaterThan(0);
  expect(settled).toBe(false);
  expect(test.capture.evidence.status).toBe('in-progress');
  writeFinished.resolve();
  await drained;
  test.capture.verifyCoverage();
  expect(test.capture.evidence.status).toBe('pass');
  expect(test.capture.evidence.counts).toMatchObject({ requests: 19, terminalRequests: 19,
    responses: 19, jsonResponses: 19, teardownAborted: 0, pendingCaptures: 0 });
  expect(test.capture.evidence.resources.recordings).toEqual({ responses: 1, written: 1 });
  expect(test.write).toHaveBeenCalledTimes(19);
});

it('does not attribute a native post-fence cancellation to an unrequested cleanup abort', async () => {
  const test = harness();
  const retained = test.request();
  const result = test.response(retained);
  const drained = test.capture.drain();
  const late = test.request('/api/v1/recordings');
  late.fail();
  result.complete();
  await drained;
  expect(test.capture.evidence.counts).toMatchObject({ abortedBeforeResponse: 1, teardownAborted: 0,
    terminalRequests: 2, activeRequests: 0, pendingCaptures: 0 });
});

it.each(['finished', 'failed'])('requires actual cancellation after a cleanup abort request, not %s', async (terminal) => {
  const test = harness();
  const retained = test.request();
  const result = test.response(retained);
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  const late = test.request('/api/v1/recordings');
  expect(test.capture.shouldAbort(late.request)).toBe(true);
  expect(test.capture.evidence.counts).toMatchObject({ activeRequests: 2, teardownAborted: 0 });
  if (terminal === 'finished') late.finish();
  else late.fail('net::ERR_FAILED');
  result.complete();
  await drained;
  expect(test.capture.evidence.counts).toMatchObject({ terminalRequests: 2, activeRequests: 0, teardownAborted: 0 });
  expect(test.capture.evidence.failures[terminal === 'finished' ? 'finish-unavailable' : 'request-failed']).toBe(1);
});

it('keeps a cleanup abort request active until a terminal event confirms cancellation', async () => {
  vi.useFakeTimers();
  const test = harness();
  const retained = test.request();
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  const late = test.request('/api/v1/recordings');
  expect(test.capture.shouldAbort(late.request)).toBe(true);
  retained.fail();
  expect(test.capture.evidence.counts).toMatchObject({ activeRequests: 1, terminalRequests: 1, teardownAborted: 0 });
  await vi.advanceTimersByTimeAsync(10_000);
  await drained;
  expect(test.capture.evidence.failures['drain-timeout']).toBe(1);
  expect(test.capture.evidence.counts).toMatchObject({ activeRequests: 1, terminalRequests: 1, teardownAborted: 0 });
});

it('accounts for native aborts before headers and fences only new cleanup-time API requests', async () => {
  const test = harness();
  const abandoned = test.request('/api/v1/endpoints');
  abandoned.fail();
  const retained = test.request();
  const response = test.response(retained);
  const drained = test.capture.drain();
  const late = test.request('/api/v1/recordings');
  expect(test.capture.shouldAbort(late.request)).toBe(true);
  late.fail();
  response.complete();
  await drained;
  expect(test.capture.evidence.counts).toMatchObject({ requests: 3, responses: 1, jsonResponses: 1,
    abortedBeforeResponse: 1, teardownAborted: 1, terminalRequests: 3, activeRequests: 0, pendingCaptures: 0 });
  expect(test.write).toHaveBeenCalledTimes(1);
});

it('never treats an abort after JSON headers as a response without a required payload', async () => {
  const test = harness();
  const entry = test.request();
  const finished = deferred();
  const result = test.response(entry, { finished: () => finished.promise });
  const drained = test.capture.drain();
  entry.fail(); finished.resolve();
  await expect(drained).rejects.toThrow('api-evidence-write');
  expect(result.response.body).not.toHaveBeenCalled();
  expect(test.capture.evidence.failures['request-aborted']).toBe(1);
  expect(test.capture.evidence.counts.jsonResponses).toBe(1);
  expect(test.capture.evidence.counts.abortedBeforeResponse).toBe(0);
  expect(test.capture.evidence.phases.finish.failed).toBe(1);
  expect(test.write).not.toHaveBeenCalled();
});

it('retains a fixed finish category when target closure invalidates a pending response', async () => {
  const test = harness();
  const finished = deferred();
  const entry = test.request();
  test.response(entry, { finished: () => finished.promise });
  const drained = test.capture.drain();
  test.close(); entry.fail(); finished.reject(new Error(privateError));
  await expect(drained).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.failures['context-closed']).toBe(1);
  expect(test.capture.evidence.phases.finish.failed).toBe(1);
  expect(JSON.stringify(test.capture.evidence)).not.toContain(privateError);
});

it('reports a refused passive body read without substituting another payload', async () => {
  const test = harness();
  const result = test.response(test.request(), { body: async () => { throw new Error(privateError); } });
  result.complete();
  await expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.failures['body-unavailable']).toBe(1);
  expect(test.capture.evidence.phases.body.failed).toBe(1);
  expect(test.write).not.toHaveBeenCalled();
  expect(JSON.stringify(test.capture.evidence)).not.toContain(privateError);
});

it('names a navigation-invalidated body read without exporting the protocol error', async () => {
  const test = harness();
  const pending = deferred();
  const entry = test.request();
  const result = test.response(entry, { body: () => pending.promise });
  result.complete();
  await result.bodyStarted;
  test.page.emit('framenavigated', test.frame);
  pending.reject(new Error(privateError));
  await expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.phases.body.failed).toBe(1);
  expect(test.capture.evidence.failures['navigation-invalidated']).toBe(1);
  expect(JSON.stringify(test.capture.evidence)).not.toContain(privateError);
});

it('fails a real exclusive-file collision rather than counting an unwritten payload', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'api-evidence-'));
  directories.push(directory);
  await writeFile(join(directory, 'api-0.json'), 'old', { mode: 0o600 });
  const test = harness((name, body, signal) => writeFile(join(directory, name), body, { flag: 'wx', mode: 0o600, signal }));
  const result = test.response(test.request());
  result.complete();
  await expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.phases.write.failed).toBe(1);
  expect(test.capture.evidence.failures['write-failed']).toBe(1);
  expect(test.capture.evidence.counts.bytesWritten).toBe(0);
  expect(await readFile(join(directory, 'api-0.json'), 'utf8')).toBe('old');
});

it('bounds an unfinished body by the original 10-second deadline and keeps it failed', async () => {
  vi.useFakeTimers();
  const test = harness();
  const result = test.response(test.request(), { body: () => new Promise(() => {}) });
  result.complete();
  await result.bodyStarted;
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  await vi.advanceTimersByTimeAsync(10_000);
  await drained;
  expect(test.capture.evidence.failures['body-timeout']).toBe(1);
  expect(test.capture.evidence.phases.body.failed).toBe(1);
  expect(test.capture.evidence.phases.write.started).toBe(0);
});

it('aborts a stalled write at the same deadline and never credits bytes', async () => {
  vi.useFakeTimers();
  const started = deferred();
  const test = harness((_name, _body, signal) => new Promise((_, reject) => {
    started.resolve();
    signal.addEventListener('abort', () => reject(new Error(privateError)), { once: true });
  }));
  const result = test.response(test.request());
  result.complete();
  await started.promise;
  const drained = expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  await vi.advanceTimersByTimeAsync(10_000);
  await drained;
  expect(test.capture.evidence.failures['write-timeout']).toBe(1);
  expect(test.capture.evidence.phases.write.failed).toBe(1);
  expect(test.capture.evidence.counts.bytesWritten).toBe(0);
});

it('rejects an oversized response before asking Chromium for its body', async () => {
  const test = harness();
  const result = test.response(test.request(), { headers: { 'content-length': String(32 * 1024 * 1024 + 1) } });
  result.complete();
  await expect(test.capture.drain()).rejects.toThrow('api-evidence-write');
  expect(test.capture.evidence.failures['header-limit']).toBe(1);
  expect(test.capture.evidence.phases.headers.failed).toBe(1);
  expect(result.response.body).not.toHaveBeenCalled();
});

it('fails coverage even when every observed response was written', async () => {
  const test = harness();
  const result = test.response(test.request());
  result.complete();
  await test.capture.drain();
  expect(() => test.capture.verifyCoverage()).toThrow('api-evidence-write');
  expect(test.capture.evidence.failures['coverage-gap']).toBe(1);
});

it('captures case-insensitive application JSON and structured suffix types without substring false positives', async () => {
  for (const type of ['APPLICATION/JSON; Charset=UTF-8', 'application/problem+json', 'Application/Vnd.xtrace+JSON; q=1']) {
    expect(isJsonMediaType(type)).toBe(true);
    const test = harness();
    const result = test.response(test.request(), { headers: { 'content-type': type } });
    result.complete();
    await test.capture.drain();
    expect(test.write).toHaveBeenCalledTimes(1);
    expect(test.capture.evidence.counts.jsonResponses).toBe(1);
  }
  for (const type of ['text/application/json', 'application/jsonp', 'application/json+xml', 'text/plain; note=application/json', undefined]) {
    expect(isJsonMediaType(type)).toBe(false);
  }
});
