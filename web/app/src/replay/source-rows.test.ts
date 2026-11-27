import { expect, it } from 'vitest';
import type { ReplayEvent } from '../types';
import { recordedLine, sourceRows } from './source-rows';

const matched: NonNullable<ReplayEvent['source']> = {
  path: 'Example.java', status: 'matched', startLine: 7, endLine: 10, excerpt: '\n\n  body();\n', truncated: false,
};

it('keeps exact leading, consecutive and trailing blank rows in a debug range', () => {
  expect(sourceRows({ kind: 'recording_event_kind:frame_enter', source: matched, line: 9 })).toEqual([
    { number: 7, text: '', active: false },
    { number: 8, text: '', active: false },
    { number: 9, text: '  body();', active: false },
    { number: 10, text: '', active: false },
  ]);
});

it('highlights a positive recorded cursor only within its own matched excerpt', () => {
  const input = { kind: 'recording_event_kind:line_cursor', source: matched, line: 9 };
  expect(sourceRows(input).filter(({ active }) => active)).toEqual([{ number: 9, text: '  body();', active: true }]);
  expect(sourceRows({ ...input, line: 11 }).some(({ active }) => active)).toBe(false);
  expect(recordedLine({ ...input, line: 0 })).toBeNull();
  expect(recordedLine({ ...input, kind: 'unknown:5' })).toBeNull();
});

it('keeps empty excerpts and truncated final lines without filling unretained rows', () => {
  const input = { kind: 'recording_event_kind:line_cursor', line: 7 };
  expect(sourceRows({ ...input, source: { ...matched, excerpt: '' } })).toEqual([{ number: 7, text: '', active: true }]);
  expect(sourceRows({ ...input, source: { ...matched, excerpt: '\n  par', truncated: true } })).toEqual([
    { number: 7, text: '', active: true }, { number: 8, text: '  par', active: false },
  ]);
});

it.each(['mismatch', 'unavailable', 'missing_file'] as const)('withholds a %s excerpt even if bytes appear in the payload', (status) => {
  expect(sourceRows({ kind: 'line_cursor', line: 9, source: { ...matched, status, excerpt: '<canary>' } })).toEqual([]);
});

it('leaves an observed line available as a fact without showing source rows', () => {
  const event = { kind: 'recording_event_kind:line_cursor', line: 9 };
  expect(sourceRows(event)).toEqual([]);
  expect(recordedLine(event)).toBe(9);
});
