/** Evidence-timed playback rules (CONTRACTS 8.4). Pure; mirrors the shared playback vectors. */
import type { PlaybackSpeed } from './state';

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
} as const;

/** Why playback must pause, or null when it may continue to `next`. */
export function stopsPlaybackAt(result: NavigationOutcome, next: { kind: string } | null | undefined): string | null {
  if (result.state === 'boundary') return STOP_REASONS.boundary;
  if (result.state === 'unavailable') return result.reason ? `${STOP_REASONS.unavailable} Reason: ${result.reason.replaceAll('_', ' ')}.` : STOP_REASONS.unavailable;
  if (next && (next.kind === 'gap' || next.kind.toLowerCase().endsWith(':gap'))) return STOP_REASONS.gap;
  return null;
}
