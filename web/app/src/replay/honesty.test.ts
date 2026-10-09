import { describe, expect, it } from 'vitest';
import { outcomeBanner } from './outcome';
import { sourceStateText } from './source-states';

describe('source binding states render distinct strings', () => {
  const cases: Array<[string, string | undefined, { status: string } | null]> = [
    ['verified', 'verified', { status: 'matched' }],
    ['observed_unattested', 'observed_unattested', { status: 'matched' }],
    ['mismatch', 'verified', { status: 'mismatch' }],
    ['missing_file', 'verified', { status: 'missing_file' }],
    ['unverifiable', 'verified', { status: 'unavailable' }],
    ['attestation_missing', 'attestation_missing', null],
    ['class_bytes_mismatch', 'class_bytes_mismatch', null],
    ['debug_metadata_absent', 'debug_metadata_absent', null],
    ['source_metadata_invalid', 'source_metadata_invalid', null],
    ['unattested no source', 'observed_unattested', null],
    ['source_map_absent', 'source_map_absent', null],
    ['source_map_unresolved', 'source_map_unresolved', null],
    ['unspecified', 'unspecified', null],
  ];
  it('gives every state its own sentence', () => {
    const texts = cases.map(([, binding, source]) => sourceStateText(binding, source));
    expect(new Set(texts).size).toBe(cases.length);
  });
  it('says what each state means', () => {
    expect(sourceStateText('verified', { status: 'matched' })).toContain('verified build attestation');
    expect(sourceStateText('observed_unattested', { status: 'matched' })).toContain('Source as read when the class loaded');
    expect(sourceStateText('verified', { status: 'mismatch' })).toContain('source changed since recording');
    expect(sourceStateText('verified', { status: 'missing_file' })).toContain('Source file missing');
    expect(sourceStateText('source_map_absent', null)).toContain('Source map absent');
  });
});

describe('outcome banner', () => {
  const base = { completion: 'complete', incompleteEvidence: [], durationNs: null };
  it('labels duration as adapter-observed, never as verified', () => {
    const model = outcomeBanner({ ...base, durationNs: '20' });
    expect(model.lines.join('\n')).toContain('Adapter-observed duration 20 ns (measured by the adapter, not verified by X-trace)');
    expect(outcomeBanner({ ...base, durationNs: '2500000' }).lines.join('\n')).toContain('2.5 ms');
  });
  it('says so when status and duration were not observed', () => {
    const lines = outcomeBanner(base).lines;
    expect(lines).toContain('Response status was not observed');
    expect(lines).toContain('Duration unavailable for this capture');
  });
  it('states exception redaction explicitly', () => {
    const model = outcomeBanner({ ...base, outcome: { httpStatus: 500, exception: { type: 'java.lang.IllegalStateException', message: { state: 'redacted' } } } });
    expect(model.lines).toContain('Response status 500 (as reported by the adapter)');
    expect(model.lines).toContain('Exception java.lang.IllegalStateException: message redacted');
  });
  it('maps completion to a tone and lists persisted incomplete evidence', () => {
    const model = outcomeBanner({ ...base, completion: 'partial', incompleteEvidence: ['gap_event_sequence:123'] });
    expect(model.tone).toBe('partial');
    expect(model.lines).toContain('Persisted incomplete evidence: gap_event_sequence:123');
    expect(outcomeBanner({ ...base, completion: 'surprise' }).tone).toBe('unavailable');
  });
});
