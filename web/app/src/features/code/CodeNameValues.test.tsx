import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import type { ReplayEvent } from '../../types';
import type { Binding } from '../../replay/value-evidence';
import { CodeNameValues } from './CodeNameValues';
import { javaNameMatches } from './java-name-matches';

afterEach(cleanup);

const observed = (name: string): Binding => ({
  name, nameOrigin: 'declared', role: 'local',
  value: { state: 'captured', preview: 'safe', shape: 'string', contentHash: 'a'.repeat(64) },
});

function lineEvent(excerpt: string, line: number, bindings: Binding[]): ReplayEvent {
  const boundary = { state: 'boundary' } as const;
  return {
    kind: 'recording_event_kind:line_cursor', line, sequence: '9', bindings,
    frameId: null, monotonicNs: '1', exception: null, sourceBinding: 'observed_unattested',
    fieldTruncations: [], depth: null, parentFrameId: null, asyncParentFrameId: null, gap: null,
    navigation: { previous: boundary, next: boundary, into: boundary, over: boundary, out: boundary },
    source: { status: 'matched', path: 'Example.java', startLine: 1, endLine: line, truncated: false, excerpt },
  };
}

it('matches Unicode identifiers exactly and skips comments, quoted text and numeric suffixes', () => {
  const first = '/* τέλος';
  const second = 'τέλος */ String s = """';
  const third = 'τέλος';
  const fourth = '"""; call(τέλος, τέλος2, $τέλος, τέλος́, "τέλος", 0xFF); // τέλος';
  const excerpt = [first, second, third, fourth].join('\n');
  const event = lineEvent(excerpt, 4, [observed('τέλος'), observed('xFF')]);
  const spans = javaNameMatches(event);
  expect(spans).toHaveLength(1);
  expect(spans[0].from).toBe(fourth.indexOf('τέλος'));
  expect(fourth.slice(spans[0].from, spans[0].to)).toBe('τέλος');
  expect(javaNameMatches({ ...event, line: 3 })).toEqual([]);
});

it('omits duplicate/synthesized names and omits ambiguous, unmatched, redacted or truncated source', () => {
  const sourceText = 'call(value);';
  const event = lineEvent(sourceText, 1, [observed('value')]);
  expect(javaNameMatches(event)).toHaveLength(1);
  expect(javaNameMatches({ ...event, bindings: [observed('value'), { ...observed('value'), role: 'argument' }] })).toEqual([]);
  expect(javaNameMatches({ ...event, bindings: [{ ...observed('value'), nameOrigin: 'synthesized' }] })).toEqual([]);
  expect(javaNameMatches({ ...event, line: 2, source: { ...event.source!, startLine: 2 } })).toEqual([]);
  expect(javaNameMatches({ ...event, source: { ...event.source!, truncated: true } })).toEqual([]);
  expect(javaNameMatches({ ...event, source: { ...event.source!, status: 'mismatch' } })).toEqual([]);
  expect(javaNameMatches(lineEvent('[redacted by x-trace]\ncall(value);', 2, event.bindings))).toEqual([]);
  expect(javaNameMatches(lineEvent(String.raw`\u002f\u002f call(value);`, 1, event.bindings))).toEqual([]);
});

it.each([
  ['redacted', 'Value withheld by a redaction rule.'],
  ['unavailable', 'Not observed; the reason is shown.'],
  ['dropped', 'Value or event was dropped before it was stored.'],
] as const)('withholds %s preview content and restores focus on Escape', (state, wording) => {
  // Simulate a stray preview on an otherwise well-formed withheld value.
  const preview = 'DISCARDED-CANARY';
  const value: Binding['value'] & { preview: string } = state === 'redacted'
    ? { state, preview, ruleId: 'fixture-redaction', shapeHint: null }
    : { state, preview, reason: state === 'dropped' ? 'queue_full' : 'unsafe_to_render' };
  const binding: Binding = { ...observed('value'), value };
  const text = 'call(value);';
  render(<CodeNameValues event={lineEvent(text, 1, [binding])} text={text} />);
  const token = screen.getByRole('button', { name: 'Recorded value for value, matched by name' });
  expect(token.parentElement).toHaveTextContent(text);
  fireEvent.click(token);
  const card = screen.getByRole('region', { name: 'Recorded value for value' });
  const close = within(card).getByRole('button', { name: 'Close value' });
  expect(close).toHaveFocus();
  expect(card).toHaveTextContent('Event sequence 9 · Matched by name only');
  expect(card).toHaveTextContent(wording);
  expect(card).not.toHaveTextContent('DISCARDED-CANARY');
  fireEvent.keyDown(close, { key: 'Escape' });
  expect(card).not.toBeInTheDocument();
  expect(token).toHaveFocus();
});

it('shows sanctioned captured and truncated previews for the exact clicked name', () => {
  const bindings: Binding[] = [observed('left'), {
    ...observed('right'), value: { state: 'truncated', preview: 'prefix', originalSizeLowerBound: '10', limit: '6' },
  }];
  const text = 'compare(left, right);';
  render(<CodeNameValues event={lineEvent(text, 1, bindings)} text={text} />);
  const left = screen.getByRole('button', { name: 'Recorded value for left, matched by name' });
  const right = screen.getByRole('button', { name: 'Recorded value for right, matched by name' });
  fireEvent.click(left);
  expect(screen.getByRole('region', { name: 'Recorded value for left' })).toHaveTextContent('safe');
  fireEvent.click(right);
  const card = screen.getByRole('region', { name: 'Recorded value for right' });
  expect(card).toHaveTextContent('prefix');
  expect(card).not.toHaveTextContent('safe');
  expect(card).toHaveTextContent('Value cut at its size limit; only the retained prefix is shown.');
});
