import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { runScenarios } from '../../lib/harness.mjs';
import { medusaScenarios } from './scenarios.mjs';
import { sha256Hex } from '../../lib/canonical.mjs';
import { ownedRequest, ownedViewerRequest, verifyListener } from './installed-local.mjs';

const baseUrl = 'http://127.0.0.1:9000';
const dockerSocket = 'unix:///var/run/docker.sock';

function ownedRows(id, database, sql, user) {
  if (!/^[a-f0-9]{64}$/.test(id) || database !== 'medusa' || user !== 'xtrace') {
    throw new Error('owned local database required');
  }
  const out = execFileSync('docker', ['--host', dockerSocket, 'exec', id,
    'psql', '-U', user, '-d', database, '-At', '-F', '|', '-v', 'ON_ERROR_STOP=1', '-c', sql],
  { encoding: 'utf8', timeout: 600000, maxBuffer: 256 * 1024 * 1024 }).trim();
  return out === '' ? [] : out.split('\n').map((line) => line.split('|'));
}

// This process's stdout, stderr and results must stay in owner-only runner files.
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (config.mode === 'package-inventory') {
  const app = createRequire(path.join(config.backend, 'package.json'));
  const versions = {};
  for (const name of ['@medusajs/cli', '@medusajs/framework', '@medusajs/medusa']) {
    // Resolution is from the actual application, through pnpm's workspace links.
    const manifest = fs.realpathSync(path.join(config.backend, 'node_modules', name, 'package.json'));
    const bytes = fs.readFileSync(manifest);
    const parsed = JSON.parse(bytes);
    if (parsed.name !== name || parsed.version !== config.version) throw new Error('resolved Medusa package mismatch');
    versions[name] = { version: parsed.version, manifestSha256: sha256Hex(bytes), manifest };
  }
  const medusa = createRequire(app.resolve('@medusajs/medusa'));
  const express = fs.realpathSync(medusa.resolve('express/package.json'));
  const expressBytes = fs.readFileSync(express);
  const expressVersion = JSON.parse(expressBytes).version;
  if (expressVersion !== config.expressVersion) throw new Error('resolved Express version mismatch');
  versions.express = { version: expressVersion, manifestSha256: sha256Hex(expressBytes), manifest: express };
  fs.writeFileSync(config.out, JSON.stringify(versions), { flag: 'wx', mode: 0o600 });
} else if (config.mode === 'health') {
  if (config.owner.port !== 9000 || !(config.timeoutMs > 0 && config.timeoutMs <= 3000)) {
    throw new Error('invalid local readiness budget');
  }
  const response = await ownedRequest(config.owner)(baseUrl + '/health', {
    method: 'GET', signal: AbortSignal.timeout(config.timeoutMs),
  });
  if (response.status !== 200 || await response.text() !== 'OK') throw new Error('owned Medusa readiness failed');
} else if (config.mode === 'viewer') {
  const response = await ownedViewerRequest(config.owner, config);
  fs.writeFileSync(config.out, await response.text(), { flag: 'wx', mode: 0o600 });
  const cookie = response.headers.getSetCookie()[0]?.split(';', 1)[0];
  console.log(JSON.stringify({ status: response.status, cookie: cookie ?? null }));
} else if (config.mode === 'workload') {
  if (config.owner.port !== 9000) throw new Error('invalid local workload port');
  verifyListener(config.owner);
  const request = ownedRequest(config.owner);
  const transport = { attempted: 0, ownedResponses: 0, refusedRedirects: 0, otherFailures: 0 };
  const summary = await runScenarios({
    project: 'medusa', baseUrl, outDir: config.out, scenarios: medusaScenarios(config, ownedRows),
    request: async (address, options) => {
      transport.attempted++;
      try {
        const response = await request(address, options);
        transport.ownedResponses++;
        return response;
      } catch (error) {
        if (error.name === 'MedusaRedirectRefused') transport.refusedRedirects++;
        else transport.otherFailures++;
        throw error;
      }
    },
  });
  fs.writeFileSync(path.join(config.out, 'local-transport.json'), JSON.stringify(transport), { flag: 'wx', mode: 0o600 });
  process.exitCode = summary.result === 'passed' && transport.attempted === 46 && transport.ownedResponses === 46 ? 0 : 1;
} else {
  throw new Error('invalid Medusa proof mode');
}
