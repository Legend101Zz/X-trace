/** Evidence-timed display pacing; independent of view filters. The reading-hold proposal remains an owner decision. */
import type { PlaybackSpeed } from './state';
import type { Detail, ReplayEvent } from '../types';

export const MAX_DWELL_MS = 2_000;

export interface Dwell {
  ms: number;
  /** True when the cap applied; the UI must then say time is compressed. */
  compressed: boolean;
  /** True when the next event is earlier than the previous one (cross-thread); never reordered. */
  nonMonotonic: boolean;
}

export function dwell(prevNs: bigint, nextNs: bigint, speed: PlaybackSpeed): Dwell {
  if (nextNs < prevNs) return { ms: 0, compressed: false, nonMonotonic: true };
  // floor((next - prev) / 1e6 / speed), done in integers: speeds are 0.5, 1, 2, 4.
  const scaled = speed === 0.5 ? (nextNs - prevNs) * 2n : (nextNs - prevNs) / BigInt(speed);
  const ms = Number(scaled / 1_000_000n);
  return ms > MAX_DWELL_MS ? { ms: MAX_DWELL_MS, compressed: true, nonMonotonic: false } : { ms, compressed: false, nonMonotonic: false };
}

export type NavigationOutcome =
  | { state: 'target'; frameId: string }
  | { state: 'boundary' }
  | { state: 'unavailable'; reason?: string };

export const STOP_REASONS = {
  boundary: 'Playback stopped: there is no further frame in this recording.',
  gap: 'Playback stopped at a gap: the adapter did not emit events here.',
  unavailable: 'Playback stopped: the next step is not available for this recording.',
  timing: 'Replay stopped: a recorded timestamp is unavailable or invalid. No delay was invented.',
  window: 'Replay stopped at the loaded window. Load later steps to continue.',
  partial: 'Replay stopped: the recording stops here. Playback stopped: the next step is not available for this recording.',
  hidden: 'Replay paused because this viewer is hidden. Press Replay to continue.',
  loading: 'Replay stopped while the loaded event window changed. Press Replay to continue.',
  end: 'Replay stopped: no later observed step is available from this window.',
} as const;

function timestamp(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(value)) return null;
  const ns = BigInt(value);
  return ns <= 18_446_744_073_709_551_615n ? ns : null;
}

export type PlaybackStep = { target: ReplayEvent; dwell: Dwell; reason: null } | { reason: string; target?: never; dwell?: never };

/** Walk the retained recording order, before any view filter; no navigation edge or timestamp is inferred. */
export function playbackStep(detail: Pick<Detail, 'events' | 'nextCursor' | 'completion' | 'status'> | null,
  sequence: string | null, frameId: string | null, speed: PlaybackSpeed): PlaybackStep {
  if (!detail || sequence === null) return { reason: STOP_REASONS.unavailable };
  const index = detail.events.findIndex((event) => event.sequence === sequence && (event.frameId ?? null) === frameId);
  if (index < 0) return { reason: STOP_REASONS.unavailable };
  const current = detail.events[index];
  const next = detail.events[index + 1];
  const gap = (event: ReplayEvent) => event.kind.replace(/^recording_event_kind:/, '') === 'gap' || event.gap != null;
  if (gap(current) || (next && gap(next))) return { reason: STOP_REASONS.gap };
  if (!next) return { reason: detail.nextCursor ? STOP_REASONS.window
    : detail.completion === 'complete' && detail.status === 'complete' ? STOP_REASONS.end : STOP_REASONS.partial };
  const before = timestamp(current.monotonicNs);
  const after = timestamp(next.monotonicNs);
  if (before === null || after === null) return { reason: STOP_REASONS.timing };
  return { target: next, dwell: dwell(before, after, speed), reason: null };
}

/** Display pacing is distinct from the recorded timestamps and from per-step durations. */
export function pacingText(step: PlaybackStep, speed: PlaybackSpeed): string {
  if (step.reason !== null) return step.reason;
  const prefix = step.dwell.nonMonotonic ? 'Non-monotonic timestamp; recording order is kept. ' : '';
  return `${prefix}Display delay ${step.dwell.ms} ms at ${speed}×.${step.dwell.compressed ? ' Time is compressed to the 2,000 ms display limit.' : ''} This is display pacing, not a step duration.`;
}

/** Why playback must pause, or null when it may continue to `next`. */
export function stopsPlaybackAt(result: NavigationOutcome, next: { kind: string } | null | undefined): string | null {
  if (result.state === 'boundary') return STOP_REASONS.boundary;
  if (result.state === 'unavailable') return result.reason ? `${STOP_REASONS.unavailable} Reason: ${result.reason.replaceAll('_', ' ')}.` : STOP_REASONS.unavailable;
  if (next && (next.kind === 'gap' || next.kind.toLowerCase().endsWith(':gap'))) return STOP_REASONS.gap;
  return null;
}
