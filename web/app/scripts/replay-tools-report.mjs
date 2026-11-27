import assert from 'node:assert/strict';
import { closeSync, existsSync, fsyncSync, lstatSync, openSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';

export const replayToolsViewports = [[320, 640], [736, 900], [1024, 768], [1280, 900], [1440, 900]];
export const replayToolsJumpKinds = ['gap', 'exception', 'database', 'http'];
const directions = ['next', 'previous'];
const maxBytes = 65536;

/** Counts assertion-completed interactions, without recording event IDs, source values or exception text. */
export function createReplayToolsReport({
  path = process.env.XTRACE_REPLAY_TOOLS_REPORT,
  sourceSha = process.env.XTRACE_REPLAY_TOOLS_SOURCE_SHA,
  receiptId = process.env.XTRACE_REPLAY_TOOLS_RECEIPT_ID,
} = {}) {
  assert.ok((!path && !sourceSha && !receiptId) || (path && sourceSha && receiptId), 'report binding must be complete');
  if (path) {
    assert.ok(isAbsolute(path) && normalize(path) === path, 'report path must be absolute and normalized');
    assert.match(sourceSha, /^[0-9a-f]{40}$/, 'report source pin must be immutable');
    assert.match(receiptId, /^[0-9a-f]{64}$/, 'report receipt ID must be fresh and bounded');
    const parent = lstatSync(dirname(path));
    assert.ok(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === process.getuid()
      && (parent.mode & 0o777) === 0o700 && realpathSync(dirname(path)) === dirname(path), 'report parent must be private');
  }
  const value = {
    schemaVersion: 1, kind: 'spring-replay-tools-jumps', sourceSha: sourceSha ?? null, receiptId: receiptId ?? null,
    status: 'running', stage: 'before-tools', failureStage: null,
    viewports: replayToolsViewports.flatMap(([width, height]) => ['fine', 'coarse'].map((pointer) => ({
      width, height, pointer, status: 'not-started', jumps: [],
    }))),
  };
  let active;
  const checkpoint = () => {
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    assert.ok(bytes.length <= maxBytes, 'report exceeds its private byte bound');
    if (!path) return;
    let existing;
    try { existing = lstatSync(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (existing) {
      assert.ok(existing.isFile() && !existing.isSymbolicLink() && existing.uid === process.getuid()
        && (existing.mode & 0o777) === 0o600 && existing.nlink === 1, 'existing report must be private');
    }
    const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
    const fd = openSync(temporary, 'wx', 0o600);
    try {
      writeFileSync(fd, bytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      renameSync(temporary, path);
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  };
  const running = () => assert.equal(value.status, 'running', 'finished report cannot accept more observations');
  checkpoint();
  return {
    beginViewport(width, height, pointer) {
      running();
      assert.equal(active, undefined, 'the preceding viewport must complete first');
      active = value.viewports.find((cell) => cell.width === width && cell.height === height && cell.pointer === pointer);
      assert.ok(active && active.status === 'not-started', 'viewport must be one fresh declared size and pointer');
      active.status = 'running';
      value.stage = 'viewport';
      checkpoint();
    },
    observeJump(kind, observedCount, nextAvailable, previousAvailable) {
      running();
      assert.ok(active && active.status === 'running', 'observations require an active viewport');
      assert.ok(replayToolsJumpKinds.includes(kind) && !active.jumps.some((row) => row.kind === kind), 'jump kind must be unique and declared');
      assert.ok(Number.isSafeInteger(observedCount) && observedCount >= 0 && observedCount <= 100000, 'observed count must be bounded');
      assert.equal(typeof nextAvailable, 'boolean');
      assert.equal(typeof previousAvailable, 'boolean');
      assert.equal(nextAvailable || previousAvailable, observedCount > 0, 'a matching event must be reachable from at least one loaded boundary');
      assert.ok(observedCount <= 1 || (nextAvailable && previousAvailable), 'multiple matching events must be reachable from both boundaries');
      active.jumps.push({ kind, observedCount,
        next: { targetAvailable: nextAvailable, activated: 0, absenceReasonChecked: 0 },
        previous: { targetAvailable: previousAvailable, activated: 0, absenceReasonChecked: 0 },
      });
      value.stage = 'jump-observation';
      checkpoint();
    },
    checkedJump(kind, direction, outcome) {
      running();
      assert.ok(active && active.status === 'running' && directions.includes(direction), 'jump result requires an active direction');
      const row = active.jumps.find((item) => item.kind === kind);
      assert.ok(row, 'jump result requires its observed-kind inventory');
      const result = row[direction];
      assert.equal(result.activated + result.absenceReasonChecked, 0, 'each direction is credited once');
      assert.equal(outcome, result.targetAvailable ? 'activated' : 'absence-reason-checked', 'absence never counts as an activated target');
      if (result.targetAvailable) result.activated = 1;
      else result.absenceReasonChecked = 1;
      value.stage = result.targetAvailable ? 'jump-activation' : 'jump-absence';
      checkpoint();
    },
    finishViewport() {
      running();
      assert.ok(active && active.status === 'running');
      assert.deepEqual(active.jumps.map(({ kind }) => kind), replayToolsJumpKinds, 'every declared kind must be checked in order');
      assert.ok(active.jumps.every((row) => directions.every((direction) => row[direction].activated + row[direction].absenceReasonChecked === 1)),
        'both directions must complete their actual target or absence assertions');
      active.status = 'pass';
      active = undefined;
      value.stage = 'viewport-complete';
      checkpoint();
    },
    complete() {
      running();
      assert.equal(active, undefined);
      assert.ok(value.viewports.every((cell) => cell.status === 'pass'), 'all widths and both pointers must complete');
      value.status = 'pass';
      value.stage = 'complete';
      checkpoint();
    },
    fail() {
      value.failureStage = value.stage;
      value.status = 'fail';
      if (active) active.status = 'fail';
      checkpoint();
    },
    snapshot: () => structuredClone(value),
  };
}
