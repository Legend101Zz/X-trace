import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as wait } from 'node:timers/promises';

const host = '127.0.0.1';

export function processStart(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new Error('invalid local process identity');
  const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  const start = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/)[19];
  if (!/^[0-9]+$/.test(start || '')) throw new Error('local process birth unavailable');
  return start;
}

function tuple(port) {
  return `0100007F:${port.toString(16).padStart(4, '0').toUpperCase()}`;
}

function ownedSocket({ pid, start, port }, status, remote) {
  if (processStart(pid) !== start) throw new Error('local process changed');
  const matches = fs.readFileSync(`/proc/${pid}/net/tcp`, 'utf8').trim().split('\n').slice(1)
    .map((line) => line.trim().split(/\s+/))
    .filter((fields) => fields[1] === tuple(port) && fields[3] === status && (!remote || fields[2] === remote));
  if (matches.length !== 1) return false;
  const inode = matches[0][9];
  if (!/^[1-9][0-9]*$/.test(inode || '')) return false;
  const directory = `/proc/${pid}/fd`;
  const held = fs.readdirSync(directory).some((fd) => {
    try { return fs.readlinkSync(`${directory}/${fd}`) === `socket:[${inode}]`; }
    catch (error) { if (error.code !== 'ENOENT') throw error; return false; }
  });
  if (processStart(pid) !== start) throw new Error('local process changed');
  return held;
}

export function verifyListener(owner) {
  const { port } = owner;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 || !ownedSocket(owner, '0A')) {
    throw new Error('owned loopback listener unavailable');
  }
}

export function ownedRequest(owner, { maxBytes = Infinity } = {}) {
  const { port } = owner;
  const origin = new URL(`http://${host}:${port}`).origin;
  return async (address, { method, headers, body, signal }) => {
    const target = new URL(address);
    if (target.origin !== origin || target.username || target.password || target.hash
      || !['GET', 'POST', 'DELETE'].includes(method)) throw new Error('local commerce target required');
    signal.throwIfAborted();
    verifyListener(owner);
    const socket = net.createConnection({ host, port });
    // During kernel ownership checks there may not yet be a request to handle an error.
    socket.on('error', () => {});
    try {
      await once(socket, 'connect', { signal });
      if (socket.remoteAddress !== host || socket.remotePort !== port || socket.localAddress !== host
        || !socket.localPort) throw new Error('unexpected loopback peer');
      const client = tuple(socket.localPort);
      // TCP connect may complete before the server accepts. Send no HTTP bytes until
      // the exact reverse connection appears in the expected process's descriptor table.
      while (!ownedSocket(owner, '01', client)) {
        if (socket.destroyed) throw new Error('owned socket closed before verification');
        await wait(10, undefined, { signal });
      }
      const response = await new Promise((resolve, reject) => {
        const request = http.request({
          host, port, path: target.pathname + target.search, method, headers,
          signal, createConnection: () => socket,
        }, resolve);
        request.once('error', reject);
        request.end(body);
      });
      const status = response.statusCode;
      if (status >= 300 && status < 400) {
        response.destroy();
        const error = new Error('redirect refused');
        error.name = 'MedusaRedirectRefused';
        throw error;
      }
      const responseHeaders = new Headers();
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        responseHeaders.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
      }
      const chunks = [];
      let length = 0;
      for await (const chunk of response) {
        length += chunk.length;
        if (length > maxBytes) throw new Error('local response exceeded its byte bound');
        chunks.push(chunk);
      }
      return { status, headers: responseHeaders, text: async () => Buffer.concat(chunks).toString('utf8') };
    } finally {
      socket.destroy();
    }
  };
}

export function ownedViewerRequest(owner, { path, token, cookie, timeoutMs }) {
  const origin = `http://127.0.0.1:${owner.port}`;
  const headers = { 'Sec-Fetch-Site': 'same-origin', 'X-XTrace-Client': 'viewer-v1', Accept: 'application/json' };
  let method = 'GET';
  let body;
  if (path === '/api/v1/auth/exchange' && typeof token === 'string' && /^[a-zA-Z0-9_-]{43}$/.test(token)) {
    method = 'POST';
    headers.Origin = origin;
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify({ token });
  } else if (typeof path === 'string' && /^\/api\/v1\/(?:recordings(?:\/[a-f0-9-]{36})?|endpoints)\?/.test(path)
    && typeof cookie === 'string' && /^xtrace_viewer_session=[a-zA-Z0-9_-]{43}$/.test(cookie)) {
    headers.Cookie = cookie;
  } else {
    throw new Error('invalid owned viewer request');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error('invalid viewer request budget');
  return ownedRequest(owner, { maxBytes: 16 * 1024 * 1024 })(origin + path, {
    method, headers, body, signal: AbortSignal.timeout(timeoutMs),
  });
}
