import { useCallback, useEffect, useRef } from 'react';
import type { Dispatch } from 'react';
import { focusStepControl } from '../features/events/useStepWindow';
import type { Detail, ReplayEvent } from '../types';
import { pacingText, playbackStep, STOP_REASONS } from './playback';
import type { ReplayAction, ReplayState } from './state';

/** Own one cancelable timer. Reducer epochs also reject a callback already queued before cleanup. */
export function usePlayback({ replay, detail, busy, ready, dispatch, prepareAdvance, announce }: {
  replay: ReplayState;
  detail: Detail | null;
  busy: boolean;
  ready: boolean;
  dispatch: Dispatch<ReplayAction>;
  prepareAdvance: (event: ReplayEvent) => () => void;
  announce: (message: string) => void;
}) {
  const latest = useRef({ replay, detail, busy, ready, prepareAdvance, announce });
  const focusFrame = useRef<number | null>(null);
  const pendingAdvance = useRef<{ id: object; event: ReplayEvent; recordingId: string; epoch: number; mode: ReplayState['mode']; focusOwner: Element | null; publish: () => void } | null>(null);
  const pendingStop = useRef<{ id: object; reason: string } | null>(null);
  latest.current = { replay, detail, busy, ready, prepareAdvance, announce };
  const selectedDetail = detail?.recordingId === replay.recordingId ? detail : null;
  const plan = playbackStep(selectedDetail, replay.sequence, replay.frameId, replay.playback.speed);
  const reason = !ready ? 'Replay unavailable while the local viewer is disconnected.' : busy ? STOP_REASONS.loading : plan.reason;
  const stop = useCallback((reason: string) => {
    const id = {};
    pendingStop.current = { id, reason };
    dispatch({ type: 'playback-stopped', reason, epoch: latest.current.replay.playback.epoch, stopId: id });
  }, [dispatch]);
  const pause = useCallback(() => {
    dispatch({ type: 'pause' });
    latest.current.announce('Replay paused.');
  }, [dispatch]);
  const toggle = useCallback(() => {
    const current = latest.current;
    if (current.replay.playback.status === 'playing') { pause(); return; }
    const step = playbackStep(current.detail?.recordingId === current.replay.recordingId ? current.detail : null,
      current.replay.sequence, current.replay.frameId, current.replay.playback.speed);
    const reason = document.visibilityState !== 'visible' ? STOP_REASONS.hidden
      : !current.ready ? 'Replay unavailable while the local viewer is disconnected.' : current.busy ? STOP_REASONS.loading : step.reason;
    if (reason) { stop(reason); return; }
    dispatch({ type: 'play' });
    current.announce('Replay started in recorded event order.');
  }, [dispatch, pause, stop]);

  useEffect(() => () => {
    if (focusFrame.current !== null) cancelAnimationFrame(focusFrame.current);
    focusFrame.current = null;
  }, [replay.mode]);

  useEffect(() => {
    const pending = pendingAdvance.current;
    if (!pending) return;
    pendingAdvance.current = null;
    // Dispatch can be rejected after another action queued in the same batch. Publish
    // side effects only once the committed selection proves this advance was accepted.
    if (replay.playback.acceptedAdvance !== pending.id) return;
    const sameRecording = replay.recordingId === pending.recordingId;
    if (sameRecording && (replay.sequence !== pending.event.sequence || replay.frameId !== (pending.event.frameId ?? null))) return;
    pending.publish();
    // A later action owns its announcement and focus, even if this advance was accepted.
    if (!sameRecording || replay.playback.epoch !== pending.epoch + 1) return;
    latest.current.announce(`Replay selected event ${pending.event.sequence}.`);
    if (!pending.focusOwner) return;
    if (focusFrame.current !== null) cancelAnimationFrame(focusFrame.current);
    const frame = requestAnimationFrame(() => {
      if (focusFrame.current !== frame) return;
      focusFrame.current = null;
      if (latest.current.replay.mode !== pending.mode || latest.current.replay.playback.epoch !== pending.epoch + 1
        || latest.current.replay.recordingId !== pending.recordingId || latest.current.replay.sequence !== pending.event.sequence
        || latest.current.replay.frameId !== (pending.event.frameId ?? null)
        || (document.activeElement !== pending.focusOwner && document.activeElement !== document.body)) return;
      const selected = document.querySelector<HTMLElement>('.event[aria-current="true"], .canvas-tree [aria-selected="true"]');
      if (selected) focusStepControl(selected);
    });
    focusFrame.current = frame;
  }, [replay]);

  useEffect(() => {
    const pending = pendingStop.current;
    if (!pending) return;
    pendingStop.current = null;
    if (replay.playback.acceptedStop === pending.id && replay.playback.status === 'paused'
      && replay.playback.stopReason === pending.reason) latest.current.announce(pending.reason);
  }, [replay]);

  useEffect(() => {
    const hidden = () => {
      if (document.visibilityState !== 'visible' && latest.current.replay.playback.status === 'playing') stop(STOP_REASONS.hidden);
    };
    document.addEventListener('visibilitychange', hidden);
    return () => document.removeEventListener('visibilitychange', hidden);
  }, [stop]);

  useEffect(() => {
    if (replay.playback.status !== 'playing') return;
    const step = playbackStep(detail?.recordingId === replay.recordingId ? detail : null, replay.sequence, replay.frameId, replay.playback.speed);
    const reason = document.visibilityState !== 'visible' ? STOP_REASONS.hidden
      : !ready ? 'Replay unavailable while the local viewer is disconnected.' : busy ? STOP_REASONS.loading : step.reason;
    if (reason) { stop(reason); return; }
    if (step.reason !== null || replay.sequence === null) return;
    const expected = { recordingId: replay.recordingId, fromFrameId: replay.frameId, fromSequence: replay.sequence, epoch: replay.playback.epoch };
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const current = latest.current;
      if (cancelled || document.visibilityState !== 'visible' || current.busy || !current.ready || current.detail !== detail
        || current.replay.playback.status !== 'playing' || current.replay.playback.epoch !== expected.epoch
        || current.replay.recordingId !== expected.recordingId || current.replay.sequence !== expected.fromSequence || current.replay.frameId !== expected.fromFrameId) return;
      // Consume this callback before dispatch: a queued invocation cannot advance or announce twice.
      cancelled = true;
      const focusOwner = document.activeElement;
      const followFocus = focusOwner instanceof Element && !!focusOwner.closest('.event, .canvas-tree [role="treeitem"]');
      const id = {};
      const publish = current.prepareAdvance(step.target);
      pendingAdvance.current = { id, event: step.target, recordingId: expected.recordingId, epoch: expected.epoch,
        mode: current.replay.mode, focusOwner: followFocus ? focusOwner : null, publish };
      dispatch({ type: 'playback-advance', ...expected, advanceId: id, frameId: step.target.frameId ?? null, sequence: step.target.sequence });
    }, step.dwell.ms);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [busy, detail, dispatch, ready, replay, stop]);

  return { toggle, pause, reason, pacing: pacingText(plan, replay.playback.speed) };
}
