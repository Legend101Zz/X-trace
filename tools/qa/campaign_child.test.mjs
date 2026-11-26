// Pure child-handle fixtures: these tests start no process and send no OS signal.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { stopViewer, waitForExit } from './campaign_child.mjs';

function child() {
  const handle = new EventEmitter();
  return Object.assign(handle, { pid: 12345, exitCode: null, signalCode: null, signals: [],
    kill(signal) { this.signals.push(signal); return true; } });
}

test('graceful stop signals only the supplied handle and retains the full viewer wait', async () => {
  const own = child(), other = child(), waits = [];
  await stopViewer(own, async (handle, timeout) => { assert.equal(handle, own); waits.push(timeout); return true; });
  assert.deepEqual(own.signals, ['SIGTERM']);
  assert.deepEqual(other.signals, []);
  assert.deepEqual(waits, [15000]);
});

test('an already exited or unstarted handle is never signalled', async () => {
  for (const changed of [{ exitCode: 0 }, { signalCode: 'SIGTERM' }, { pid: undefined }]) {
    const own = Object.assign(child(), changed);
    await stopViewer(own, () => assert.fail('no wait for an already reaped or unstarted handle'));
    assert.deepEqual(own.signals, []);
  }
});

test('forced direct-handle kill remains failure even after final reap', async () => {
  const own = child(), waits = [];
  await assert.rejects(stopViewer(own, async (_handle, timeout) => { waits.push(timeout); return waits.length === 2; }),
    /graceful shutdown timed out/);
  assert.deepEqual(own.signals, ['SIGTERM', 'SIGKILL']);
  assert.deepEqual(waits, [15000, 5000]);
});

test('an unreaped owned child remains an explicit cleanup failure', async () => {
  const own = child();
  await assert.rejects(stopViewer(own, async () => false), /was not reaped/);
  assert.equal(own.exitCode, null);
  assert.equal(own.signalCode, null);
  assert.deepEqual(own.signals, ['SIGTERM', 'SIGKILL']);
});

test('an observed exit before escalation cannot receive a stale PID signal', async () => {
  const own = child();
  let calls = 0;
  await assert.rejects(stopViewer(own, async () => {
    calls++;
    own.exitCode = 0;
    return calls > 1;
  }), /graceful shutdown timed out/);
  assert.deepEqual(own.signals, ['SIGTERM']);
});

test('exit observation releases its timer and listener on the real emitted signal', async () => {
  const own = child();
  const completion = waitForExit(own, 15000);
  assert.equal(own.listenerCount('exit'), 1);
  own.exitCode = 0;
  own.emit('exit', 0, null);
  assert.equal(await completion, true);
  assert.equal(own.listenerCount('exit'), 0);
});
