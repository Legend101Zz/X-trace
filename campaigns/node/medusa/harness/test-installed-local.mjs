import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { ownedRequest, ownedViewerRequest, processStart, verifyListener } from './installed-local.mjs';

async function fixture(handler, run) {
  const server = http.createServer(handler);
  let connections = 0;
  server.on('connection', () => { connections++; });
  server.listen(0, '127.0.0.1');
  try {
    await once(server, 'listening');
    const owner = { pid: process.pid, start: processStart(process.pid), port: server.address().port };
    await run(owner, `http://127.0.0.1:${owner.port}`, () => connections);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('local commerce reads and writes use the verified accepted socket', async () => {
  await fixture(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ method: request.method, path: request.url, body: Buffer.concat(chunks).toString() }));
  }, async (owner, origin, connections) => {
    verifyListener(owner);
    const phases = [];
    const local = ownedRequest(owner, { observe: (phase) => phases.push(phase) });
    const read = await local(origin + '/store/products?fields=title', { method: 'GET', signal: AbortSignal.timeout(2000) });
    assert.equal(read.status, 200);
    assert.equal(read.headers.get('content-type'), 'application/json');
    assert.deepEqual(JSON.parse(await read.text()), { method: 'GET', path: '/store/products?fields=title', body: '' });
    const body = '{"title":"Fixture product"}';
    const write = await local(origin + '/admin/products', {
      method: 'POST', body, headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(2000),
    });
    assert.deepEqual(JSON.parse(await write.text()), { method: 'POST', path: '/admin/products', body });
    assert.equal(connections(), 2);
    const expected = ['listener', 'connect', 'accepted-socket', 'response'];
    assert.deepEqual(phases, [...expected, ...expected]);
  });
});

test('local checkout redirect never fetches the local confirmation', async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const paths = [];
    await fixture((request, response) => {
      paths.push(request.url);
      response.writeHead(status, { location: '/checkout/confirmation' });
      response.end();
    }, async (owner, origin) => {
      await assert.rejects(ownedRequest(owner)(origin + '/checkout', {
        method: 'POST', body: '{}', signal: AbortSignal.timeout(2000),
      }), { name: 'MedusaRedirectRefused' });
      assert.deepEqual(paths, ['/checkout']);
    });
  }
});

test('local catalogue revalidation without Location also fails closed', async () => {
  await fixture((_request, response) => {
    response.writeHead(304);
    response.end();
  }, async (owner, origin) => {
    await assert.rejects(ownedRequest(owner)(origin + '/store/products', {
      method: 'GET', signal: AbortSignal.timeout(2000),
    }), { name: 'MedusaRedirectRefused' });
  });
});

test('listener verification refuses a stale birth identity before sending a local request', async () => {
  let requests = 0;
  await fixture((_request, response) => {
    requests++;
    response.end();
  }, async (owner, origin) => {
    const phases = [];
    const stale = ownedRequest({ ...owner, start: '0' }, { observe: (phase) => phases.push(phase) });
    await assert.rejects(stale(origin + '/store/products', {
      method: 'GET', signal: AbortSignal.timeout(2000),
    }), /local process changed/);
    assert.deepEqual(phases, ['listener']);
    assert.equal(requests, 0);
  });
});

test('viewer exchange and read each use one verified local connection', async () => {
  const token = 'a'.repeat(43);
  const cookie = 'xtrace_viewer_session=' + 'b'.repeat(43);
  const received = [];
  await fixture(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({ path: request.url, cookie: request.headers.cookie, body: Buffer.concat(chunks).toString() });
    if (request.url === '/api/v1/auth/exchange') response.setHeader('set-cookie', cookie + '; Path=/; HttpOnly');
    response.end('{}');
  }, async (owner, _origin, connections) => {
    const exchange = await ownedViewerRequest(owner, { path: '/api/v1/auth/exchange', token, timeoutMs: 2000 });
    assert.equal(exchange.headers.getSetCookie()[0].split(';', 1)[0], cookie);
    const page = await ownedViewerRequest(owner, { path: '/api/v1/recordings?limit=20', cookie, timeoutMs: 2000 });
    assert.equal(await page.text(), '{}');
    assert.deepEqual(received, [
      { path: '/api/v1/auth/exchange', cookie: undefined, body: JSON.stringify({ token }) },
      { path: '/api/v1/recordings?limit=20', cookie, body: '' },
    ]);
    assert.equal(connections(), 2);
    // The fixture and address are unchanged. Changing only the recorded owner
    // identity must stop both credential-bearing calls before a TCP connection.
    const stale = { ...owner, start: '0' };
    await assert.rejects(ownedViewerRequest(stale, { path: '/api/v1/auth/exchange', token, timeoutMs: 2000 }),
      /local process changed/);
    await assert.rejects(ownedViewerRequest(stale, { path: '/api/v1/recordings?limit=20', cookie, timeoutMs: 2000 }),
      /local process changed/);
    assert.equal(connections(), 2);
    assert.equal(received.length, 2);
  });
});
