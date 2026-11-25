import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import type { Detail, ReplayEvent } from '../types';
import { sourceStateText } from './source-states';
import { sessionContextText } from './outcome';
import { valueEvidence } from './value-evidence';

export interface MissingTarget {
  recordingId: string;
  sequence: string;
  frameId: string | null;
}

export interface MissingEntry {
  key: string;
  label: string;
  detail: string;
  explanation: string[];
  target?: MissingTarget;
}

const lookup = (dictionary: Readonly<Record<string, string>>, code: string): string | undefined =>
  Object.hasOwn(dictionary, code) ? dictionary[code] : undefined;

const SOURCE_LIMITS = new Set(['attestation_missing', 'class_bytes_mismatch', 'debug_metadata_absent',
  'source_metadata_invalid', 'source_map_absent', 'source_map_unresolved']);

function eventMissing(recordingId: string, event: ReplayEvent): MissingEntry[] {
  const rows: MissingEntry[] = [];
  const target = { recordingId, sequence: event.sequence, frameId: event.frameId ?? null };
  const add = (key: string, label: string, detail: string, explanation: string[]) => {
    rows.push({ key: `${event.sequence}:${key}`, label, detail, explanation, target });
  };
  const gap = event.gap;
  if (gap || isGapEvent(event)) {
    add('gap', 'Recorded gap', gap ? `${gap.count} suppressed events · reason ${gap.reason}` : 'Gap details unavailable',
      [honesty.markers.gap, gap ? lookup(honesty.gapReasons, gap.reason) ?? gap.reason : 'Reason unavailable']);
  }
  const source = event.source;
  if (source?.status === 'mismatch' || source?.status === 'missing_file' || source?.status === 'unavailable' || SOURCE_LIMITS.has(event.sourceBinding)) {
    const marker = source?.status === 'mismatch' ? honesty.markers.mismatch
      : source?.status === 'missing_file' ? honesty.markers.source_missing : honesty.markers.unavailable;
    add('source', 'Source limitation', source?.status ?? event.sourceBinding,
      [marker, sourceStateText(event.sourceBinding, source)]);
  }
  if (source?.truncated) add('source-bounded', 'Bounded source excerpt', 'Only the retained source is shown', ['Source excerpt is bounded']);
  for (const [index, field] of (event.fieldTruncations ?? []).entries()) {
    add(`field:${index}`, 'Field limitation', `${field.field} · ${field.representation} · ${field.originalBytes} bytes`,
      [field.representation === 'truncated' ? honesty.markers.truncated : honesty.markers.unavailable]);
  }
  const bindings = new Map<string, { count: number; label: string; explanation: string[] }>();
  for (const binding of event.bindings ?? []) {
    const model = valueEvidence(binding);
    if (!model.wording) continue;
    const reasonCode = binding.value?.state === 'unavailable' || binding.value?.state === 'dropped' ? binding.value.reason : '';
    const key = `${model.state}:${reasonCode}`;
    const group = bindings.get(key);
    if (group) group.count += 1;
    else bindings.set(key, { count: 1, label: model.label, explanation: [model.wording, ...(model.reason ? [model.reason] : []), ...(reasonCode ? [reasonCode] : [])] });
  }
  for (const [key, group] of bindings) {
    add(`bindings:${key}`, group.label, `${group.count} observed binding ${group.count === 1 ? 'entry' : 'entries'}`, group.explanation);
  }
  return rows;
}

function isGapEvent(event: ReplayEvent): boolean {
  return event.kind === 'gap' || event.kind === 'recording_event_kind:gap';
}

/** Titles are provisional; exact shared wording is retained in Why. Only retained events get links. */
export function missingEvidence(detail: Pick<Detail, 'recordingId' | 'events' | 'completion' | 'incompleteEvidence' | 'limitations' | 'capacity' | 'sessionContext'>) {
  const window = detail.events.flatMap((event) => eventMissing(detail.recordingId, event));
  const loadedGaps = new Set(detail.events.filter((event) => event.gap || isGapEvent(event)).map((event) => event.sequence));
  const recording: MissingEntry[] = [];
  if (detail.completion === 'partial' || detail.completion === 'invalid') {
    recording.push({ key: 'completion', label: 'Recording completion', detail: detail.completion, explanation: [honesty.markers.incomplete] });
  }
  for (const code of new Set(detail.incompleteEvidence)) {
    const sequence = /^gap_event_sequence:(\d+)$/.exec(code)?.[1];
    if (sequence && loadedGaps.has(sequence)) continue;
    recording.push({
      key: `incomplete:${code}`,
      label: sequence ? 'Gap marker outside the loaded window' : 'Persisted incomplete evidence',
      detail: code,
      explanation: [sequence ? honesty.markers.gap : lookup(honesty.markers, code) ?? code],
    });
  }
  for (const code of new Set(detail.limitations ?? [])) {
    recording.push({
      key: `limitation:${code}`, label: 'Recording limitation', detail: code,
      explanation: [code === 'capture_policy_not_armed' ? honesty.unavailableReasons.focused_capture_not_armed : code],
    });
  }
  const dropped = detail.capacity?.capacityDroppedEvents;
  if (dropped && /^\d+$/.test(dropped) && /[1-9]/.test(dropped)) {
    recording.push({
      key: 'capacity', label: 'Capacity drops', detail: `${dropped} events`,
      explanation: [honesty.markers.capacity_dropped_events],
    });
  }
  const session = detail.sessionContext ? sessionContextText(detail.sessionContext) : null;
  return { window, recording, session };
}
