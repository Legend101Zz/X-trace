import { useReducer } from 'react';
import type { Dispatch } from 'react';
import { act, cleanup, render, renderHook, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Detail, ReplayEvent } from '../types';
import { initialReplayState } from './state';
import { replayReducer } from './state';
import type { ReplayAction } from './state';
import { usePlayback } from './use-playback';
import { STOP_REASONS } from './playback';

const events = [1, 2, 3].map((n) => ({ sequence: String(n), frameId: 'shared', kind: 'recording_event_kind:frame_enter', monotonicNs: String((n - 1) * 500_000_000) } as ReplayEvent));
const detail = { recordingId: 'r', events, completion: 'complete', status: 'complete', nextCursor: null } as Detail;
const initial = { ...initialReplayState, recordingId: 'r', frameId: 'shared', sequence: '1' };
let visible = true;

beforeEach(() => {
  vi.useFakeTimers();
  visible = true;
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visible ? 'visible' : 'hidden');
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

function setup() {
  const advanced = vi.fn();
  const announce = vi.fn();
  const hook = renderHook(({ detail: current, busy }) => {
    const [replay, dispatch] = useReducer(replayReducer, initial);
    const controller = usePlayback({ replay, detail: current, busy, ready: true, dispatch, prepareAdvance: (event) => () => advanced(event), announce });
    return { ...controller, replay, dispatch };
  }, { initialProps: { detail, busy: false } });
  return { ...hook, advanced, announce };
}

it('advances only after the exact evidence-timed delay and explicit Replay', () => {
  const hook = setup();
  act(() => vi.advanceTimersByTime(1000));
  expect(hook.result.current.replay.sequence).toBe('1');
  act(() => hook.result.current.toggle());
  act(() => vi.advanceTimersByTime(499));
  expect(hook.advanced).not.toHaveBeenCalled();
  act(() => vi.advanceTimersByTime(1));
  expect(hook.result.current.replay).toMatchObject({ sequence: '2', frameId: 'shared', playback: { status: 'playing' } });
  act(() => hook.result.current.pause());
  act(() => vi.advanceTimersByTime(2000));
  expect(hook.result.current.replay.sequence).toBe('2');
  expect(hook.advanced).toHaveBeenCalledTimes(1);
});

it('cancels a queued callback on a same-event manual selection and speed changes', () => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const old = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  act(() => hook.result.current.dispatch({ type: 'set-speed', speed: 2 }));
  act(old);
  expect(hook.advanced).not.toHaveBeenCalled();
  act(() => vi.advanceTimersByTime(250));
  expect(hook.result.current.replay.sequence).toBe('2');
  act(() => hook.result.current.dispatch({ type: 'select-frame', frameId: 'shared', sequence: '2' }));
  act(() => vi.advanceTimersByTime(1000));
  expect(hook.result.current.replay.sequence).toBe('2');
});

it('does not use an old window or carry a timer into another recording', () => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const old = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  hook.rerender({ detail: { ...detail }, busy: true });
  act(old);
  expect(hook.result.current.replay.playback).toMatchObject({ status: 'paused', stopReason: STOP_REASONS.loading });
  act(() => hook.result.current.dispatch({ type: 'select-recording', recordingId: 'other' }));
  hook.rerender({ detail: { ...detail, recordingId: 'other' }, busy: false });
  act(old);
  expect(hook.advanced).not.toHaveBeenCalled();
});

it('continues playing across a mode round trip with one fresh timer and rejects both stale callbacks', () => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.dispatch({ type: 'set-filter', kinds: ['frame_enter'] }));
  act(() => hook.result.current.dispatch({ type: 'set-speed', speed: 2 }));
  act(() => hook.result.current.toggle());
  const before = hook.result.current.replay;
  const oldLinear = timer.mock.calls.filter(([, ms]) => ms === 250).at(-1)![0] as () => void;
  act(() => vi.advanceTimersByTime(100));
  act(() => hook.result.current.dispatch({ type: 'set-mode', mode: 'canvas' }));
  const oldCanvas = timer.mock.calls.filter(([, ms]) => ms === 250).at(-1)![0] as () => void;
  expect(hook.result.current.replay).toEqual({ ...before, mode: 'canvas', playback: { ...before.playback, epoch: before.playback.epoch + 1 } });
  act(oldLinear);
  expect(hook.advanced).not.toHaveBeenCalled();
  act(() => hook.result.current.dispatch({ type: 'set-mode', mode: 'linear' }));
  const fresh = timer.mock.calls.filter(([, ms]) => ms === 250).at(-1)![0] as () => void;
  act(oldCanvas);
  act(oldLinear);
  act(() => vi.advanceTimersByTime(249));
  expect(hook.result.current.replay).toEqual({ ...before, playback: { ...before.playback, epoch: before.playback.epoch + 2 } });
  expect(hook.advanced).not.toHaveBeenCalled();
  act(() => vi.advanceTimersByTime(1));
  expect(hook.result.current.replay).toMatchObject({ sequence: '2', frameId: 'shared', filter: before.filter, playback: { status: 'playing', speed: 2, stopReason: null } });
  act(() => { oldLinear(); oldCanvas(); fresh(); });
  expect(hook.advanced).toHaveBeenCalledExactlyOnceWith(events[1]);
  expect(hook.announce.mock.calls.filter(([message]) => message === 'Replay selected event 2.')).toHaveLength(1);
});

it('consumes an accepted timer callback once even before React renders the new selection', () => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const tick = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  act(() => { tick(); tick(); });
  expect(hook.result.current.replay.sequence).toBe('2');
  expect(hook.advanced).toHaveBeenCalledExactlyOnceWith(events[1]);
  expect(hook.announce.mock.calls.filter(([message]) => message === 'Replay selected event 2.')).toHaveLength(1);
});

it.each([
  { type: 'select-frame', frameId: 'shared', sequence: '2' },
  { type: 'select-frame', frameId: 'shared', sequence: '1' },
  { type: 'set-mode', mode: 'canvas' },
  { type: 'set-speed', speed: 2 },
  { type: 'pause' },
  { type: 'select-recording', recordingId: 'other' },
] satisfies ReplayAction[])('does not publish a rejected timer after a same-batch $type action', (action) => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const tick = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  hook.announce.mockClear();
  act(() => { hook.result.current.dispatch(action); tick(); });
  expect(hook.advanced).not.toHaveBeenCalled();
  expect(hook.announce.mock.calls.some(([message]) => message === 'Replay selected event 2.')).toBe(false);
});

it.each([
  { type: 'set-mode', mode: 'canvas' },
  { type: 'set-speed', speed: 2 },
  { type: 'pause' },
  { type: 'set-filter', kinds: ['frame_enter'] },
  { type: 'select-recording', recordingId: 'other' },
] satisfies ReplayAction[])('publishes an accepted tick before a same-batch $type without stale focus or announcement', (action) => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const tick = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  hook.announce.mockClear();
  act(() => { tick(); hook.result.current.dispatch(action); });
  expect(hook.advanced).toHaveBeenCalledExactlyOnceWith(events[1]);
  expect(hook.announce.mock.calls.some(([message]) => message === 'Replay selected event 2.')).toBe(false);
});

it('does not announce a stop rejected after an accepted timer in the same batch', () => {
  const timer = vi.spyOn(window, 'setTimeout');
  const hook = setup();
  act(() => hook.result.current.toggle());
  const tick = timer.mock.calls.find(([, ms]) => ms === 500)![0] as () => void;
  hook.announce.mockClear();
  act(() => { tick(); visible = false; document.dispatchEvent(new Event('visibilitychange')); });
  expect(hook.announce.mock.calls.filter(([message]) => message === STOP_REASONS.hidden)).toHaveLength(1);
  expect(hook.result.current.replay.playback).toMatchObject({ status: 'paused', stopReason: STOP_REASONS.hidden });
});

it('cancels focus queued for the old view and follows only a fresh advance in the new view', () => {
  const frames: FrameRequestCallback[] = [];
  vi.spyOn(window, 'requestAnimationFrame').mockImplementation((callback) => { frames.push(callback); return frames.length; });
  const cancel = vi.spyOn(window, 'cancelAnimationFrame');
  const observed = [...events, { ...events[2], sequence: '4', monotonicNs: '1500000000' }];
  const advanced = vi.fn();
  let current: ReturnType<typeof usePlayback> & { dispatch: Dispatch<ReplayAction> };
  function Harness() {
    const [replay, dispatch] = useReducer(replayReducer, initial);
    current = { ...usePlayback({ replay, detail: { ...detail, events: observed }, busy: false, ready: true, dispatch, prepareAdvance: (event) => () => advanced(event), announce: () => undefined }), dispatch };
    return replay.mode === 'linear' ? <div>{observed.map((event) => <button key={event.sequence} className="event"
      aria-label={`Event ${event.sequence}`} aria-current={replay.sequence === event.sequence ? 'true' : undefined} />)}</div>
      : <ul className="canvas-tree">{observed.map((event) => <li key={event.sequence} role="treeitem" tabIndex={0}
        aria-label={`Frame event ${event.sequence}`} aria-selected={replay.sequence === event.sequence} />)}</ul>;
  }
  render(<Harness />);
  screen.getByRole('button', { name: 'Event 1' }).focus();
  act(() => current.toggle());
  act(() => vi.advanceTimersByTime(500));
  expect(frames).toHaveLength(1);
  act(() => current.dispatch({ type: 'set-mode', mode: 'canvas' }));
  expect(cancel).toHaveBeenCalledWith(1);
  act(() => frames[0](0));
  expect(document.body).toHaveFocus();
  screen.getByRole('treeitem', { name: 'Frame event 2' }).focus();
  act(() => vi.advanceTimersByTime(500));
  expect(frames).toHaveLength(2);
  act(() => frames[0](0));
  expect(screen.getByRole('treeitem', { name: 'Frame event 2' })).toHaveFocus();
  act(() => frames[1](0));
  expect(screen.getByRole('treeitem', { name: 'Frame event 3' })).toHaveFocus();
  expect(advanced.mock.calls.map(([event]) => event.sequence)).toEqual(['2', '3']);
});

it('pauses on visibility loss and never resumes automatically', () => {
  const hook = setup();
  act(() => hook.result.current.toggle());
  visible = false;
  act(() => document.dispatchEvent(new Event('visibilitychange')));
  expect(hook.result.current.replay.playback).toMatchObject({ status: 'paused', stopReason: STOP_REASONS.hidden });
  visible = true;
  act(() => document.dispatchEvent(new Event('visibilitychange')));
  act(() => vi.advanceTimersByTime(2000));
  expect(hook.advanced).not.toHaveBeenCalled();
});

it('stops before a filtered-out gap, missing timestamp and unloaded frontier', () => {
  const hook = setup();
  act(() => hook.result.current.dispatch({ type: 'set-filter', kinds: ['frame_enter'] }));
  hook.rerender({ detail: { ...detail, events: [events[0], { ...events[1], kind: 'recording_event_kind:gap', frameId: null }] }, busy: false });
  act(() => hook.result.current.toggle());
  expect(hook.result.current.replay.playback.stopReason).toBe(STOP_REASONS.gap);
  hook.rerender({ detail: { ...detail, events: [events[0], { ...events[1], monotonicNs: '' }] }, busy: false });
  act(() => hook.result.current.toggle());
  expect(hook.result.current.replay.playback.stopReason).toBe(STOP_REASONS.timing);
  hook.rerender({ detail: { ...detail, events: [events[0]], nextCursor: 'opaque' }, busy: false });
  act(() => hook.result.current.toggle());
  expect(hook.result.current.replay.playback.stopReason).toBe(STOP_REASONS.window);
  expect(hook.advanced).not.toHaveBeenCalled();
});

it('cancels owned work on unmount', () => {
  const hook = setup();
  act(() => hook.result.current.toggle());
  hook.unmount();
  act(() => vi.advanceTimersByTime(2000));
  expect(hook.advanced).not.toHaveBeenCalled();
});

it('follows focus only when replay started from a row and keeps a playback control focused', () => {
  let current: ReturnType<typeof usePlayback>;
  function Harness() {
    const [replay, dispatch] = useReducer(replayReducer, initial);
    current = usePlayback({ replay, detail, busy: false, ready: true, dispatch, prepareAdvance: () => () => undefined, announce: () => undefined });
    return <><button onClick={current.toggle}>Replay control</button>{events.map((event) => <button key={event.sequence}
      className="event" aria-label={`Event ${event.sequence}`} aria-current={replay.sequence === event.sequence ? 'true' : undefined}>
      <span className="event-seq">{event.sequence}</span></button>)}</>;
  }
  render(<Harness />);
  screen.getByRole('button', { name: 'Event 1' }).focus();
  act(() => current.toggle());
  act(() => vi.advanceTimersByTime(500));
  act(() => vi.advanceTimersByTime(16));
  expect(screen.getByRole('button', { name: 'Event 2' })).toHaveFocus();
  act(() => current.pause());
  const control = screen.getByRole('button', { name: 'Replay control' });
  control.focus();
  act(() => current.toggle());
  act(() => vi.advanceTimersByTime(500));
  expect(control).toHaveFocus();
});
