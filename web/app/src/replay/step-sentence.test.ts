import { expect, it } from 'vitest';
import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import { stepSentence } from './step-sentence';

const empty = { symbol: null, line: null, depth: null, interaction: null, exception: null, gap: null };

it.each([
  ['unspecified', 'Event kind unavailable'],
  ['request_update', 'Request updated'],
  ['frame_enter', 'Call recorded'],
  ['frame_exit', 'Return recorded'],
  ['frame_throw', 'Exception recorded'],
  ['line_cursor', 'Line number unavailable'],
  ['value_snapshot', 'Value snapshot recorded'],
  ['database_start', 'Database call started'],
  ['database_end', 'Database call ended'],
  ['outbound_http_start', 'HTTP call started'],
  ['outbound_http_end', 'HTTP call ended'],
  ['async_link', 'Async link recorded'],
  ['exception', 'Exception recorded'],
  ['response', 'Response event recorded'],
  ['gap', 'Events were not recorded here'],
])('provides provisional wording for %s with missing fields', (kind, text) => {
  const step = stepSentence({ ...empty, kind: `recording_event_kind:${kind}` });
  expect(step.text).toBe(text);
  expect(step.depth).toBeNull();
});

it('uses a recorded symbol, depth, line and exception type only where they describe that event', () => {
  const item = { ...empty, symbol: 'OrderService.place', depth: 3, line: 12, exception: { exceptionType: 'ExampleError' } };
  expect(stepSentence({ ...item, kind: 'recording_event_kind:frame_enter' })).toEqual({ text: 'Called OrderService.place', depth: 3, gap: null });
  expect(stepSentence({ ...item, kind: 'recording_event_kind:frame_exit' }).text).toBe('Returned from OrderService.place');
  expect(stepSentence({ ...item, kind: 'recording_event_kind:line_cursor' }).text).toBe('Ran line 12');
  expect(stepSentence({ ...item, kind: 'recording_event_kind:frame_throw' }).text).toBe('Threw ExampleError');
  expect(stepSentence({ ...item, kind: 'unknown:42', depth: -1 })).toEqual({ text: 'Event recorded', depth: null, gap: null });
});

it('uses only observed interaction fields and does not imply an HTTP response status', () => {
  const interaction = { method: 'POST', host: 'example.test', table: 'orders', schema: null, statusCode: '201' };
  expect(stepSentence({ ...empty, kind: 'recording_event_kind:outbound_http_end', interaction }).text).toBe('HTTP call ended · POST example.test');
  expect(stepSentence({ ...empty, kind: 'recording_event_kind:database_end', interaction }).text).toBe('Database call ended · orders');
  expect(stepSentence({ ...empty, kind: 'recording_event_kind:response', symbol: 'node:http.response.close' }).text).toBe('Response event recorded');
});

it('preserves precise gap counts and uses verbatim canonical Why text', () => {
  const gap = { count: '9007199254740993', firstSequence: '2', lastSequence: '4', reason: 'line_budget' };
  const input = { ...empty, kind: 'recording_event_kind:gap', gap };
  expect(stepSentence(input)).toEqual({
    text: '9007199254740993 events were not recorded here',
    depth: null,
    gap: { wording: honesty.markers.gap, reason: honesty.gapReasons.line_budget },
  });
  expect(stepSentence({ ...input, gap: { ...gap, count: '1' } }).text).toBe('1 event was not recorded here');
  expect(stepSentence({ ...input, gap: { ...gap, count: 'bad', reason: 'future_reason' } })).toEqual({
    text: 'Events were not recorded here', depth: null,
    gap: { wording: honesty.markers.gap, reason: null },
  });
});

it('removes only the recognized Java method identity digest from a display sentence', () => {
  const prefix = 'OrderService.place';
  const symbol = `${prefix}#m1:${'a'.repeat(64)}`;
  const kind = 'recording_event_kind:frame_enter';
  expect(stepSentence({ ...empty, kind, symbol }).text).toBe(`Called ${prefix}`);
  expect(stepSentence({ ...empty, kind, symbol: `${prefix}#m1:ordinary` }).text).toBe(`Called ${prefix}#m1:ordinary`);
});
