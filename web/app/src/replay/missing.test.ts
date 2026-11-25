import { expect, it } from 'vitest';
import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import type { ReplayEvent } from '../types';
import { missingEvidence } from './missing';

const event: ReplayEvent = {
  kind: 'recording_event_kind:frame_enter', sourceBinding: 'unspecified', sequence: '2', frameId: null,
  monotonicNs: '10', navigation: {
    previous: { state: 'boundary' }, next: { state: 'boundary' }, into: { state: 'boundary' },
    over: { state: 'boundary' }, out: { state: 'boundary' },
  }, exception: null, depth: null, parentFrameId: null, asyncParentFrameId: null,
  line: null, gap: null, bindings: [], fieldTruncations: [],
};
const detail = { recordingId: 'recording', completion: 'complete' as const, events: [event],
  limitations: [], incompleteEvidence: [], capacity: null, sessionContext: { runtimeSessionId: 'session', rejectedRequests: null } };

it('uses all retained pages and deduplicates only matching loaded gap markers', () => {
  const gap = { ...event, kind: 'recording_event_kind:gap',
    gap: { reason: 'line_budget', count: '9007199254740993', firstSequence: '1', lastSequence: '3' } };
  const missing = missingEvidence({
    ...detail, events: [gap, { ...event, sequence: '6', sourceBinding: 'source_map_absent' }],
    incompleteEvidence: ['gap_event_sequence:2', 'gap_event_sequence:4', 'gap_event_sequence:4', 'future_code'],
  });
  expect(missing.window).toHaveLength(2);
  expect(missing.window[0]).toMatchObject({ detail: '9007199254740993 suppressed events · reason line_budget',
    explanation: [honesty.markers.gap, honesty.gapReasons.line_budget], target: { recordingId: 'recording', sequence: '2', frameId: null } });
  expect(missing.recording.map(({ detail }) => detail)).toEqual(['gap_event_sequence:4', 'future_code']);
  expect(missing.recording.every(({ target }) => target === undefined)).toBe(true);
});

it('does not infer missing source, values or parents from absent compatibility data', () => {
  const missing = missingEvidence(detail);
  expect(missing.window).toEqual([]);
  expect(missing.recording).toEqual([]);
  expect(missing.session).toContain('agent capacity rejections not observed');
  const zero = missingEvidence({ ...detail, sessionContext: { ...detail.sessionContext, rejectedRequests: '0' } });
  expect(zero.session).toContain('0 requests were not recorded due to agent capacity');
});

it('retains decimal recording counts and groups binding issues without discarded contents', () => {
  const privateBinding = { name: 'private-binding', role: 'local', nameOrigin: 'declared',
    value: { state: 'unavailable' as const, reason: 'constructor', preview: 'private-preview' } };
  const missing = missingEvidence({
    ...detail,
    events: [{ ...event, bindings: [privateBinding, privateBinding], fieldTruncations: [
      { field: 'symbol', representation: 'truncated', originalBytes: '9007199254740994' },
    ] }],
    capacity: { eventCap: 10, eventCount: 10, capacityDroppedEvents: '9007199254740993', dropsByPriority: {} },
  });
  expect(missing.window.some(({ detail }) => detail.includes('9007199254740994'))).toBe(true);
  expect(missing.window.some(({ detail }) => detail === '2 observed binding entries')).toBe(true);
  expect(missing.window.some(({ explanation }) => explanation.includes('constructor'))).toBe(true);
  expect(missing.recording[0]).toMatchObject({ detail: '9007199254740993 events', explanation: [honesty.markers.capacity_dropped_events] });
  expect(JSON.stringify(missing)).not.toMatch(/private-preview|private-binding/);
});
