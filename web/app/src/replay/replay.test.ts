import { describe, expect, it } from 'vitest';
import { dwell, MAX_DWELL_MS, STOP_REASONS, stopsPlaybackAt } from './playback';
import { initialReplayState, passesFilter, replayReducer } from './state';
import type { ReplayState } from './state';

const withFrame: ReplayState = { ...initialReplayState, recordingId: 'r1', frameId: 'f1', sequence: '5' };

describe('replay-core reducer', () => {
  it('reducer: switching mode leaves the reducer frame untouched (App-level selection sharing is asserted in main.replay.test.tsx)', () => {
    const canvas = replayReducer(withFrame, { type: 'set-mode', mode: 'canvas' });
    expect(canvas.mode).toBe('canvas');
    expect(canvas.frameId).toBe('f1');
    expect(replayReducer(canvas, { type: 'set-mode', mode: 'linear' }).frameId).toBe('f1');
  });

  it('selecting another recording clears frame and playback but keeps mode and filter', () => {
    let state = replayReducer(withFrame, { type: 'set-mode', mode: 'canvas' });
    state = replayReducer(state, { type: 'set-filter', kinds: ['gap'] });
    state = replayReducer(state, { type: 'play' });
    expect(state.playback.status).toBe('playing');
    state = replayReducer(state, { type: 'select-recording', recordingId: 'r2' });
    expect(state).toMatchObject({ recordingId: 'r2', frameId: null, sequence: null, mode: 'canvas', filter: { kinds: ['gap'] } });
    expect(state.playback.status).toBe('paused');
  });

  it('selecting the same recording is a no-op (same reference)', () => {
    expect(replayReducer(withFrame, { type: 'select-recording', recordingId: 'r1' })).toBe(withFrame);
  });

  it('selecting an operation drops the recording', () => {
    const state = replayReducer(withFrame, { type: 'select-operation', operationId: 'op' });
    expect(state).toMatchObject({ operationId: 'op', recordingId: '', frameId: null });
  });

  it('cannot play without a selected frame', () => {
    expect(replayReducer(initialReplayState, { type: 'play' }).playback.status).toBe('paused');
    expect(replayReducer({ ...initialReplayState, recordingId: 'r1' }, { type: 'play' }).playback.status).toBe('paused');
  });

  it('manual frame selection pauses playback', () => {
    const playing = replayReducer(withFrame, { type: 'play' });
    const moved = replayReducer(playing, { type: 'select-frame', frameId: 'f2', sequence: '6' });
    expect(moved.playback.status).toBe('paused');
    expect(moved.frameId).toBe('f2');
  });

  it('reducer retains the stop reason until the next play', () => {
    const playing = replayReducer(withFrame, { type: 'play' });
    const stopped = replayReducer(playing, { type: 'playback-stopped', reason: STOP_REASONS.gap });
    expect(stopped.playback).toMatchObject({ status: 'paused', stopReason: STOP_REASONS.gap });
    expect(replayReducer(stopped, { type: 'play' }).playback.stopReason).toBeNull();
  });

  it('filter kinds are de-duplicated and ordered so equal filters compare equal', () => {
    const a = replayReducer(initialReplayState, { type: 'set-filter', kinds: ['b', 'a', 'a'] });
    expect(a.filter.kinds).toEqual(['a', 'b']);
    expect(replayReducer(a, { type: 'set-filter', kinds: ['a', 'b'] })).toBe(a);
    expect(passesFilter(a.filter, 'a')).toBe(true);
    expect(passesFilter(a.filter, 'c')).toBe(false);
    expect(passesFilter(initialReplayState.filter, 'anything')).toBe(true);
  });

  it('reset returns the initial state', () => {
    expect(replayReducer(withFrame, { type: 'reset' })).toBe(initialReplayState);
  });
});

describe('evidence-timed playback', () => {
  it('scales the recorded delta by speed', () => {
    expect(dwell(0n, 400_000_000n, 1)).toEqual({ ms: 400, compressed: false, nonMonotonic: false });
    expect(dwell(0n, 400_000_000n, 2).ms).toBe(200);
    expect(dwell(0n, 400_000_000n, 4).ms).toBe(100);
    expect(dwell(0n, 400_000_000n, 0.5).ms).toBe(800);
    expect(dwell(0n, 1_999_999n, 1).ms).toBe(1);
  });

  it('caps long waits and marks them compressed', () => {
    expect(dwell(0n, 60_000_000_000n, 1)).toEqual({ ms: MAX_DWELL_MS, compressed: true, nonMonotonic: false });
  });

  it('yields zero and a flag for a non-monotonic pair, never reordering', () => {
    expect(dwell(10n, 5n, 1)).toEqual({ ms: 0, compressed: false, nonMonotonic: true });
  });

  it('stops at boundary, unavailable and gap with a stated reason; continues otherwise', () => {
    expect(stopsPlaybackAt({ state: 'boundary' }, null)).toBe(STOP_REASONS.boundary);
    expect(stopsPlaybackAt({ state: 'unavailable', reason: 'partial_frontier' }, null)).toContain('partial frontier');
    expect(stopsPlaybackAt({ state: 'unavailable' }, null)).toBe(STOP_REASONS.unavailable);
    expect(stopsPlaybackAt({ state: 'target', frameId: 'f' }, { kind: 'gap' })).toBe(STOP_REASONS.gap);
    expect(stopsPlaybackAt({ state: 'target', frameId: 'f' }, { kind: 'method' })).toBeNull();
  });
});
