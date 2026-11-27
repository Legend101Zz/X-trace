import { describe, expect, it } from 'vitest';
import type { Detail, ReplayEvent } from '../types';
import { pacingText, playbackStep, STOP_REASONS } from './playback';
import { initialReplayState, replayReducer } from './state';

const event = (sequence: string, monotonicNs: unknown, kind = 'recording_event_kind:frame_enter', frameId: string | null = 'shared') =>
  ({ sequence, monotonicNs, kind, frameId } as ReplayEvent);
const window = (events: ReplayEvent[], more = false, complete = true) => ({ events, nextCursor: more ? 'opaque' : null,
  completion: complete ? 'complete' : 'partial', status: complete ? 'complete' : 'partial' } as Detail);

describe('recording-order playback plans', () => {
  it('moves to the adjacent exact event even when a call has several events or no frame', () => {
    const events = [event('9007199254740993', '1'), event('9007199254740994', '500000001'), event('9007199254740995', '500000002', 'request_update', null)];
    expect(playbackStep(window(events), events[0].sequence, 'shared', 2)).toMatchObject({ target: events[1], dwell: { ms: 250 }, reason: null });
    expect(playbackStep(window(events), events[1].sequence, 'shared', 1)).toMatchObject({ target: events[2], dwell: { ms: 0 } });
  });
  it('stops before or on every gap, independently of a view filter', () => {
    const events = [event('1', '1'), event('2', '2', 'recording_event_kind:gap', null), event('3', '3')];
    expect(playbackStep(window(events), '1', 'shared', 1).reason).toBe(STOP_REASONS.gap);
    expect(playbackStep(window(events), '2', null, 1).reason).toBe(STOP_REASONS.gap);
    expect(playbackStep(window([{ ...events[0], gap: { reason: 'queue_full' } } as ReplayEvent, events[2]]), '1', 'shared', 1).reason).toBe(STOP_REASONS.gap);
  });
  it('distinguishes a loaded frontier, partial end and complete observed end', () => {
    const events = [event('1', '1')];
    expect(playbackStep(window(events, true), '1', 'shared', 1).reason).toBe(STOP_REASONS.window);
    expect(playbackStep(window(events, false, false), '1', 'shared', 1).reason).toBe(STOP_REASONS.partial);
    expect(playbackStep(window(events), '1', 'shared', 1).reason).toBe(STOP_REASONS.end);
    expect(playbackStep(window(events), '1', 'other', 1).reason).toBe(STOP_REASONS.unavailable);
  });
  it('refuses missing, numeric, malformed, negative and out-of-range timestamps', () => {
    for (const ns of [undefined, null, 5, '-1', '01', '1.1', '18446744073709551616']) {
      expect(playbackStep(window([event('1', '1'), event('2', ns)]), '1', 'shared', 1).reason).toBe(STOP_REASONS.timing);
      expect(playbackStep(window([event('1', ns), event('2', '2')]), '1', 'shared', 1).reason).toBe(STOP_REASONS.timing);
    }
  });
  it('keeps the baseline zero minimum and distinguishes backward order and capped display waits', () => {
    const backwards = playbackStep(window([event('1', '100'), event('2', '50')]), '1', 'shared', 1);
    expect(backwards).toMatchObject({ target: { sequence: '2' }, dwell: { ms: 0, nonMonotonic: true } });
    expect(pacingText(backwards, 1)).toContain('recording order is kept');
    const capped = playbackStep(window([event('1', '0'), event('2', '60000000000')]), '1', 'shared', 4);
    expect(capped).toMatchObject({ dwell: { ms: 2000, compressed: true } });
    expect(pacingText(capped, 4)).toContain('Time is compressed');
    expect(pacingText(capped, 4)).toContain('not a step duration');
  });
  it('rejects stale scheduled advances after manual selection, speed, mode, filter or tab changes', () => {
    const start = { ...initialReplayState, recordingId: 'r', sequence: '1', frameId: 'f' };
    const playing = replayReducer(start, { type: 'play' });
    const tick = { type: 'playback-advance', recordingId: 'r', fromSequence: '1', fromFrameId: 'f', epoch: playing.playback.epoch, frameId: 'f', sequence: '2' } as const;
    for (const state of [
      replayReducer(playing, { type: 'select-frame', sequence: '1', frameId: 'f' }),
      replayReducer(playing, { type: 'set-speed', speed: 2 }),
      replayReducer(playing, { type: 'set-mode', mode: 'canvas' }),
      replayReducer(playing, { type: 'set-filter', kinds: ['frame_enter'] }),
      replayReducer(playing, { type: 'select-recording', recordingId: 'other' }),
    ]) expect(replayReducer(state, tick)).toBe(state);
    const moved = replayReducer(playing, tick);
    expect(moved).toMatchObject({ sequence: '2', playback: { status: 'playing' } });
    expect(replayReducer(moved, tick)).toBe(moved);
  });
  it('can replay a selected frame-less recorded event without manufacturing a frame', () => {
    const playing = replayReducer({ ...initialReplayState, recordingId: 'r', sequence: '1' }, { type: 'play' });
    expect(playing.playback.status).toBe('playing');
    expect(playing.frameId).toBeNull();
  });
  it.each(['paused', 'playing'] as const)('preserves %s playback and exact selection across both views while retiring old callbacks', (status) => {
    const before = { ...initialReplayState, operationId: 'op', recordingId: 'r', sequence: '9007199254740994', frameId: null,
      filter: { kinds: ['frame_enter'] }, playback: { status, speed: 2 as const, stopReason: status === 'paused' ? STOP_REASONS.gap : null, epoch: 7 } };
    const canvas = replayReducer(before, { type: 'set-mode', mode: 'canvas' });
    expect(canvas).toEqual({ ...before, mode: 'canvas', playback: { ...before.playback, epoch: 8 } });
    expect(canvas.filter).toBe(before.filter);
    expect(replayReducer(canvas, { type: 'set-mode', mode: 'canvas' })).toBe(canvas);
    const linear = replayReducer(canvas, { type: 'set-mode', mode: 'linear' });
    expect(linear).toEqual({ ...before, playback: { ...before.playback, epoch: 9 } });
    expect(linear.filter).toBe(before.filter);
  });
});
