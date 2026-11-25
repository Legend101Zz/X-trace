import type { ReplayEvent } from '../types';

type SourceEvidence = Pick<ReplayEvent, 'kind' | 'source' | 'line'>;

export function recordedLine(event: SourceEvidence): number | null {
  if (event.kind !== 'recording_event_kind:line_cursor' && event.kind !== 'line_cursor') return null;
  return typeof event.line === 'number' && Number.isSafeInteger(event.line) && event.line > 0 ? event.line : null;
}

export function sourceRows(event: SourceEvidence) {
  const source = event.source;
  if (source?.status !== 'matched' || typeof source.excerpt !== 'string'
      || !Number.isSafeInteger(source.startLine) || source.startLine < 1) return [];
  const activeLine = recordedLine(event);
  return source.excerpt.split('\n').map((text, index) => ({
    number: source.startLine + index,
    text,
    active: source.startLine + index === activeLine,
  }));
}
