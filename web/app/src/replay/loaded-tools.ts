import type { ReplayEvent } from '../types';
import type { ReplayFilter } from './state';

export function eventKind(event: Pick<ReplayEvent, 'kind'>): string {
  return event.kind.replace(/^recording_event_kind:/, '');
}

export const STEP_FILTERS = [
  { id: 'all', label: 'All steps', kinds: [] },
  { id: 'frames', label: 'Calls and returns', kinds: ['frame_enter', 'frame_exit', 'frame_throw', 'exception'] },
  { id: 'lines', label: 'Lines', kinds: ['line_cursor'] },
  { id: 'interactions', label: 'Requests, responses and database', kinds: ['request_update', 'response', 'database_start', 'database_end', 'outbound_http_start', 'outbound_http_end', 'async_link'] },
  { id: 'gaps', label: 'Not recorded', kinds: ['gap'] },
] as const;

/** Filtering is a view over the retained window; it cannot replace the exact selected event. */
export function filteredSteps(events: readonly ReplayEvent[], filter: ReplayFilter, selected: ReplayEvent | undefined) {
  return filter.kinds.length === 0 ? events : events.filter((event) => event === selected || filter.kinds.includes(eventKind(event)));
}

export const JUMP_KINDS = [
  { id: 'gap', label: 'Not-recorded stretch' },
  { id: 'exception', label: 'Thrown exception' },
  { id: 'database', label: 'Database call' },
  { id: 'http', label: 'HTTP call' },
] as const;
export type JumpKind = typeof JUMP_KINDS[number]['id'];

export function matchesJump(event: ReplayEvent, kind: JumpKind) {
  switch (kind) {
    case 'gap': return eventKind(event) === 'gap';
    case 'exception': return eventKind(event) === 'frame_throw' || eventKind(event) === 'exception' || event.exception != null;
    case 'database': return eventKind(event) === 'database_start';
    case 'http': return eventKind(event) === 'outbound_http_start';
  }
}

/** Search evidence order, never numeric sequence offsets, and never wrap into another window. */
export function jumpTarget(events: readonly ReplayEvent[], selected: ReplayEvent | undefined, kind: JumpKind, direction: -1 | 1) {
  const index = selected ? events.indexOf(selected) : -1;
  if (index < 0) return undefined;
  for (let next = index + direction; next >= 0 && next < events.length; next += direction) {
    if (matchesJump(events[next], kind)) return events[next];
  }
  return undefined;
}

function timestamp(value: unknown): bigint | null {
  // The API carries decimal strings. Reject numbers: precision may already have been lost.
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(value)) return null;
  const ns = BigInt(value);
  return ns <= 18_446_744_073_709_551_615n ? ns : null;
}

/** Exact deltas from the first retained event, not durations or wall-clock times. */
export function loadedTiming(events: readonly ReplayEvent[]): ReadonlyMap<string, string> {
  const baseline = timestamp(events[0]?.monotonicNs);
  let previous: bigint | null = null;
  return new Map(events.map((event) => {
    const ns = timestamp(event.monotonicNs);
    const backwards = ns !== null && ((previous !== null && ns < previous) || (baseline !== null && ns < baseline));
    if (ns !== null) previous = ns;
    const text = ns === null || baseline === null ? 'Timing unavailable'
      : backwards ? 'Non-monotonic timestamp' : `+${ns - baseline} ns`;
    return [event.sequence, text];
  }));
}
