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
    ['unattested mismatch', 'observed_unattested', { status: 'mismatch' }],
    ['unspecified matched', 'unspecified', { status: 'matched' }],
    ['unspecified mismatch', 'unspecified', { status: 'mismatch' }],
  ];
  it('gives every state its own sentence', () => {
    const texts = cases.map(([, binding, source]) => sourceStateText(binding, source));
    expect(new Set(texts).size).toBe(cases.length);
  });
  it('gives generated-path bindings their specific text even when a source object is present', () => {
    expect(sourceStateText('source_map_absent', { status: 'unavailable' })).toContain('Source map absent');
    expect(sourceStateText('source_map_unresolved', { status: 'unavailable' })).toContain('did not resolve');
    expect(sourceStateText('verified', { status: 'unavailable' })).toBe('Current source could not be verified safely');
  });
  it('does not claim the binding was unspecified when it is another binding', () => {
    expect(sourceStateText('attestation_missing', { status: 'matched' })).not.toContain('was not specified');
    expect(sourceStateText('attestation_missing', { status: 'mismatch' })).not.toContain('was not specified');
    expect(sourceStateText('unspecified', { status: 'matched' })).toContain('was not specified');
  });
  it('says what each state means', () => {
    expect(sourceStateText('verified', { status: 'matched' })).toContain('verified build attestation');
    expect(sourceStateText('observed_unattested', { status: 'matched' })).toContain('Source as read when the class loaded');
    expect(sourceStateText('unspecified', { status: 'matched' })).not.toContain('verified build attestation');
    expect(sourceStateText('observed_unattested', { status: 'mismatch' })).not.toContain('compile-time');
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
    const lines = outcomeBanner({ ...base, outcome: { kind: 'unobserved', httpStatus: null, exception: null } }).lines;
    expect(lines).toContain('Response status was not observed');
    expect(lines).toContain('Duration unavailable for this capture');
  });
  it('shows exception type and message verbatim, and says when the message was not recorded', () => {
    const exception = { exceptionType: 'java.lang.IllegalStateException', message: 'boom' };
    const model = outcomeBanner({ ...base, outcome: { kind: 'exception', httpStatus: 500, exception } });
    expect(model.lines).toContain('Response status 500 (as reported by the adapter)');
    expect(model.lines).toContain('Exception java.lang.IllegalStateException: boom');
    const none = outcomeBanner({ ...base, outcome: { kind: 'exception', httpStatus: null, exception: { ...exception, message: null } } });
    expect(none.lines).toContain('Exception java.lang.IllegalStateException: message not recorded');
  });
  it('uses kind for unobserved and absent outcomes', () => {
    expect(outcomeBanner({ ...base, outcome: { kind: 'unobserved', httpStatus: null, exception: null } }).lines).toContain('Response status was not observed');
    expect(outcomeBanner({ ...base, outcome: null }).lines).toContain('Outcome unavailable: no terminal evidence was recorded');
    expect(outcomeBanner({ ...base, outcome: { kind: 'responded', httpStatus: 204, exception: null } }).lines).toContain('Response status 204 (as reported by the adapter)');
  });
  it('does not throw on a non-numeric duration', () => {
    expect(outcomeBanner({ ...base, durationNs: 'not-a-number' }).lines.join('\n')).toContain('unavailable');
  });
  it('maps completion to a tone and lists persisted incomplete evidence', () => {
    const model = outcomeBanner({ ...base, completion: 'partial', incompleteEvidence: ['gap_event_sequence:123'] });
    expect(model.tone).toBe('partial');
    expect(model.lines).toContain('Persisted incomplete evidence: gap_event_sequence:123');
    expect(outcomeBanner({ ...base, completion: 'surprise' }).tone).toBe('unavailable');
  });
});
