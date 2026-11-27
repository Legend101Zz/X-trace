// Hosted, single-sample Steps check against the #94 synthetic store.
import { spawn } from 'node:child_process';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

function check(condition) {
  if (!condition) throw new Error('validation failed');
}

function readReady(child) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => finish(), 30_000);
    function finish(url) {
      clearTimeout(timer);
      child.stdout.off('data', read);
      child.stdout.resume();
      child.off('exit', fail);
      if (url) resolve(url);
      else reject(new Error('viewer readiness failed'));
    }
    const fail = () => finish();
    function read(chunk) {
      buffer += chunk.toString();
      if (buffer.length > 65_536) return finish();
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      try {
        const url = new URL(JSON.parse(buffer.slice(0, newline)).url);
        check(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.hash.startsWith('#token='));
        finish(url.href);
      } catch { finish(); }
    }
    child.once('error', fail);
    child.once('exit', fail);
    child.stdout.on('data', read);
  });
}

function stopViewer(child) {
  if (!child || !child.pid || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('viewer cleanup failed'));
    }, 10_000);
    child.once('close', () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill('SIGTERM');
  });
}

function browserReceipt(context) {
  const script = new URL('../../web/app/scripts/synthetic-step-window-journey.mjs', import.meta.url);
  const child = spawn(process.execPath, [fileURLToPath(script)], { stdio: ['pipe', 'pipe', 'ignore'] });
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish();
    }, 120_000);
    function finish(report) {
      clearTimeout(timer);
      if (report) resolve(report);
      else reject(new Error('synthetic browser failed'));
    }
    child.once('error', () => finish());
    child.stdin.on('error', () => finish());
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      if (output.length > 8_192) {
        child.kill('SIGTERM');
        finish();
      }
    });
    child.once('close', (code) => {
      if (code !== 0) return finish();
      try { finish(JSON.parse(output)); } catch { finish(); }
    });
    child.stdin.end(JSON.stringify(context));
  });
}

function aggregate(report) {
  const amount = (value) => Number.isSafeInteger(value) && value >= 0;
  const { fixtureFrames, retainedEvents, mountedRowCap, openToVisibleAndSettledMs, samples } = report;
  check(report.synthetic === true && fixtureFrames === 10_000 && mountedRowCap === 80 &&
    amount(retainedEvents) && retainedEvents > mountedRowCap && retainedEvents <= fixtureFrames &&
    amount(openToVisibleAndSettledMs) && samples?.length === 4);
  const widths = [320, 736, 1024, 1440];
  const viewports = samples.map(({ width, peakMountedRows, scrollToNewRowsMs, fullWindowScrollAndAssertionMs }, index) => {
    check(width === widths[index] && amount(peakMountedRows) && peakMountedRows > 0 && peakMountedRows <= mountedRowCap &&
      amount(scrollToNewRowsMs) && amount(fullWindowScrollAndAssertionMs));
    return { width, peakMountedRows, scrollToNewRowsMs, fullWindowScrollAndAssertionMs };
  });
  return { synthetic: true, fixtureFrames, retainedEvents, mountedRowCap, openToVisibleAndSettledMs, samples: viewports };
}

let stage = 'admit private fixture';
let viewer;
let receipt;
try {
  const { values: { manifest: manifestPath, xtrace } } = parseArgs({ options: {
    manifest: { type: 'string' },
    xtrace: { type: 'string' },
  } });
  check(manifestPath && xtrace);
  const metadata = await lstat(manifestPath);
  check(metadata.isFile() && (metadata.mode & 0o077) === 0);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  check(manifest.schema_version === 1 && manifest.synthetic === true && manifest.verified_frame_count === 10_000);
  check(/^[0-9a-f-]{36}$/.test(manifest.recording_id));
  const root = await realpath(manifest.fixture_root);
  const rootMetadata = await lstat(root);
  check(rootMetadata.isDirectory() && (rootMetadata.mode & 0o077) === 0);
  const privateDirectory = async (path) => {
    const canonical = await realpath(path);
    const nested = relative(root, canonical);
    check(nested && nested !== '..' && !nested.startsWith(`..${sep}`) && !isAbsolute(nested));
    check((await lstat(canonical)).isDirectory());
    return canonical;
  };
  const [binary, project, dataHome] = await Promise.all([
    realpath(xtrace), privateDirectory(manifest.project_dir), privateDirectory(manifest.data_home),
  ]);

  stage = 'start embedded viewer';
  viewer = spawn(binary, ['open', '--project-dir', project, '--viewer', '--no-browser'], {
    env: { ...process.env, XTRACE_DATA_HOME: dataHome },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const url = await readReady(viewer);
  stage = 'measure synthetic Steps';
  receipt = aggregate(await browserReceipt({
    url,
    recordingId: manifest.recording_id,
    verifiedFrameCount: manifest.verified_frame_count,
  }));
  stage = 'stop embedded viewer';
  await stopViewer(viewer);
} catch {
  console.error(`Synthetic Steps check failed during ${stage}`);
  process.exitCode = 1;
  try { await stopViewer(viewer); } catch { /* Keep cleanup failures private. */ }
}
if (!process.exitCode && receipt) console.log(JSON.stringify(receipt));
