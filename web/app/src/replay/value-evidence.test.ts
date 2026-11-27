import { expect, it } from 'vitest';
import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import { valueEvidence } from './value-evidence';
import type { Binding } from './value-evidence';

const binding = (value: Binding['value']): Binding => ({ name: 'local', role: 'local', nameOrigin: 'declared', value });

it('shows only the captured or bounded preview and distinguishes empty captured text', () => {
  expect(valueEvidence(binding({ state: 'captured', preview: '', shape: 'string', contentHash: '' }))).toMatchObject({
    state: 'captured', preview: '', wording: null,
  });
  expect(valueEvidence(binding({ state: 'truncated', preview: 'prefix', originalSizeLowerBound: '9007199254740993', limit: '512' }))).toMatchObject({
    state: 'truncated', preview: 'prefix', wording: honesty.markers.truncated,
  });
});

it('withholds even stray preview fields and preserves exact canonical privacy copy', () => {
  const hidden = { state: 'redacted' as const, ruleId: 'private-rule', shapeHint: null, preview: 'PRIVATE' };
  const missing = { state: 'unavailable' as const, reason: 'focused_capture_not_armed', preview: 'PRIVATE' };
  const dropped = { state: 'dropped' as const, reason: 'value_budget', preview: 'PRIVATE' };
  expect(valueEvidence(binding(hidden))).toMatchObject({ label: 'Hidden', preview: null, wording: honesty.markers.redacted });
  expect(valueEvidence(binding(missing))).toMatchObject({
    label: 'Not captured', preview: null, wording: honesty.markers.unavailable,
    reason: honesty.unavailableReasons.focused_capture_not_armed,
  });
  expect(valueEvidence(binding(dropped))).toMatchObject({
    label: 'Dropped', preview: null, wording: honesty.markers.dropped, reason: honesty.dropReasons.value_budget,
  });
});

it('does not treat prototype keys or an unfamiliar reason as explanatory copy', () => {
  for (const reason of ['constructor', 'future_reason']) {
    expect(valueEvidence(binding({ state: 'unavailable', reason })).reason).toBe('Reason unavailable');
  }
});
