// @vitest-environment node
import assert from 'node:assert/strict';
import { lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'vitest';
import { createReplayToolsReport, replayToolsJumpKinds, replayToolsViewports } from './replay-tools-report.mjs';

const unbound = () => createReplayToolsReport({ path: null, sourceSha: null, receiptId: null });
const observe = (report, positive = true) => {
  for (const kind of replayToolsJumpKinds) {
    report.observeJump(kind, positive ? 1 : 0, positive, false);
    report.checkedJump(kind, 'next', positive ? 'activated' : 'absence-reason-checked');
    report.checkedJump(kind, 'previous', 'absence-reason-checked');
  }
};

test('begins with ten unexercised cells and a bounded value-free schema', () => {
  const value = unbound().snapshot();
  assert.equal(value.status, 'running');
  assert.equal(value.viewports.length, 10);
  assert.ok(value.viewports.every((cell) => cell.status === 'not-started' && cell.jumps.length === 0));
  assert.ok(Buffer.byteLength(JSON.stringify(value)) < 65536);
});

test('credits a positive jump only after the activated-target assertion completes', () => {
  const report = unbound();
  report.beginViewport(320, 640, 'fine');
  report.observeJump('gap', 1, true, false);
  assert.equal(report.snapshot().viewports[0].jumps[0].next.activated, 0);
  report.checkedJump('gap', 'next', 'activated');
  assert.deepEqual(report.snapshot().viewports[0].jumps[0].next, { targetAvailable: true, activated: 1, absenceReasonChecked: 0 });
});

test('records absent kinds without positive target credit', () => {
  const report = unbound();
  report.beginViewport(320, 640, 'fine');
  observe(report, false);
  report.finishViewport();
  assert.ok(report.snapshot().viewports[0].jumps.every((row) => row.observedCount === 0
    && row.next.activated === 0 && row.previous.activated === 0
    && row.next.absenceReasonChecked === 1 && row.previous.absenceReasonChecked === 1));
});

test('rejects invented activation, duplicate credit and inconsistent observed targets', () => {
  const report = unbound();
  report.beginViewport(320, 640, 'fine');
  assert.throws(() => report.observeJump('gap', 0, true, false));
  report.observeJump('gap', 1, true, false);
  assert.throws(() => report.checkedJump('gap', 'previous', 'activated'));
  assert.throws(() => report.checkedJump('gap', 'next', 'absence-reason-checked'));
  report.checkedJump('gap', 'next', 'activated');
  assert.throws(() => report.checkedJump('gap', 'next', 'activated'));
});

test('cannot complete a partially checked viewport or omit a width and pointer', () => {
  const report = unbound();
  report.beginViewport(320, 640, 'fine');
  report.observeJump('gap', 1, true, false);
  report.checkedJump('gap', 'next', 'activated');
  assert.throws(() => report.finishViewport());
  assert.throws(() => report.complete());
});

test('a complete report preserves positive and absence counts separately in every cell', () => {
  const report = unbound();
  for (const [width, height] of replayToolsViewports) for (const pointer of ['fine', 'coarse']) {
    report.beginViewport(width, height, pointer);
    observe(report);
    report.finishViewport();
  }
  report.complete();
  const value = report.snapshot();
  assert.equal(value.status, 'pass');
  assert.ok(value.viewports.every((cell) => cell.status === 'pass' && cell.jumps.every((row) => row.next.activated === 1
    && row.next.absenceReasonChecked === 0 && row.previous.activated === 0 && row.previous.absenceReasonChecked === 1)));
  assert.throws(() => report.beginViewport(320, 640, 'fine'));
});

test('failure retains only already-checked interactions and leaves unreached cells unstarted', () => {
  const report = unbound();
  report.beginViewport(320, 640, 'fine');
  report.observeJump('gap', 1, true, false);
  report.checkedJump('gap', 'next', 'activated');
  report.fail();
  const value = report.snapshot();
  assert.equal(value.status, 'fail');
  assert.equal(value.failureStage, 'jump-activation');
  assert.equal(value.viewports[0].status, 'fail');
  assert.equal(value.viewports[0].jumps[0].previous.absenceReasonChecked, 0);
  assert.ok(value.viewports.slice(1).every((cell) => cell.status === 'not-started'));
});

test('private atomic receipts bind the source and reject links or incomplete identity', () => {
  const parent = mkdtempSync(join(tmpdir(), 'xtrace-jump-report-'));
  const path = join(parent, 'report.json');
  const sourceSha = 'a'.repeat(40);
  const receiptId = 'b'.repeat(64);
  try {
    const report = createReplayToolsReport({ path, sourceSha, receiptId });
    report.beginViewport(320, 640, 'fine');
    report.fail();
    const value = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(value.sourceSha, sourceSha);
    assert.equal(value.receiptId, receiptId);
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
    assert.equal(lstatSync(path).nlink, 1);
    assert.throws(() => createReplayToolsReport({ path, sourceSha, receiptId: null }));
    const link = join(parent, 'link.json');
    symlinkSync(path, link);
    assert.throws(() => createReplayToolsReport({ path: link, sourceSha, receiptId }));
    const dangling = join(parent, 'dangling.json');
    symlinkSync(join(parent, 'missing.json'), dangling);
    assert.throws(() => createReplayToolsReport({ path: dangling, sourceSha, receiptId }));
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});
