import { expect, it } from 'vitest';
import type { ReplayEvent } from '../types';
import { filteredSteps, jumpTarget, loadedTiming, matchesJump, STEP_FILTERS } from './loaded-tools';

const event = (sequence: string, kind: string, monotonicNs = '9007199254740993') => ({
  sequence, kind: `recording_event_kind:${kind}`, monotonicNs, frameId: 'shared-frame', exception: null,
}) as ReplayEvent;

it('filters only named observed kinds, keeps exact selection, and never treats an unknown frameless event as an interaction', () => {
  const steps = [event('2', 'frame_enter'), { ...event('4', 'line_cursor'), frameId: null },
    { ...event('6', 'unknown'), frameId: null }, event('8', 'outbound_http_start'), event('10', 'gap')];
  expect(filteredSteps(steps, STEP_FILTERS[2], steps[4])).toEqual([steps[1], steps[4]]);
  expect(filteredSteps(steps, STEP_FILTERS[3], undefined)).toEqual([steps[3]]);
  expect(filteredSteps(steps, STEP_FILTERS[0], steps[0])).toBe(steps);
  expect(filteredSteps(steps.slice(1), STEP_FILTERS[1], steps[0])).toEqual([]);
});

it('jumps in retained evidence order without numeric sequence coercion, wrapping, or frame-id substitution', () => {
  const steps = [event('9007199254740993', 'gap'), event('9007199254740995', 'frame_enter'),
    { ...event('9007199254740997', 'gap'), frameId: null }, event('9007199254740999', 'database_end'), event('9007199254741001', 'database_start')];
  expect(jumpTarget(steps, steps[1], 'gap', -1)).toBe(steps[0]);
  expect(jumpTarget(steps, steps[1], 'gap', 1)).toBe(steps[2]);
  expect(jumpTarget(steps, steps[2], 'gap', 1)).toBeUndefined();
  expect(jumpTarget(steps, { ...steps[1] }, 'gap', 1)).toBeUndefined();
  expect(jumpTarget(steps, steps[1], 'database', 1)).toBe(steps[4]);
});

it('counts observed throw events with unavailable exception payload and selects HTTP starts only', () => {
  expect(matchesJump(event('1', 'frame_throw'), 'exception')).toBe(true);
  expect(matchesJump({ ...event('2', 'frame_exit'), exception: { exceptionType: 'RecordedType' } }, 'exception')).toBe(true);
  expect(matchesJump(event('3', 'outbound_http_end'), 'http')).toBe(false);
  expect(matchesJump(event('4', 'outbound_http_start'), 'http')).toBe(true);
  expect(matchesJump(event('5', 'database_end'), 'database')).toBe(false);
});

it('subtracts exact recorded decimal strings beyond JS safe-integer range and labels backwards timestamps', () => {
  const steps = [event('1', 'frame_enter'), event('2', 'frame_exit', '9007199254740994'),
    event('3', 'gap', '9007199254740993'), event('4', 'response', '9007199254740992')];
  expect([...loadedTiming(steps).values()]).toEqual(['+0 ns', '+1 ns', 'Non-monotonic timestamp', 'Non-monotonic timestamp']);
  expect([...loadedTiming(steps.slice(1, 2)).values()]).toEqual(['+0 ns']);
});

it('does not manufacture timing from invalid, numeric, unsafe, or missing baseline timestamps', () => {
  const invalid = ['', '-1', '1.5', 'NaN', '01', '18446744073709551616', 9007199254740992, 5, null];
  for (const monotonicNs of invalid) {
    const steps = [event('1', 'frame_enter', '1'), { ...event('2', 'frame_exit'), monotonicNs } as ReplayEvent];
    expect(loadedTiming(steps).get('2')).toBe('Timing unavailable');
    expect(loadedTiming(steps.slice(1)).get('2')).toBe('Timing unavailable');
  }
  expect([...loadedTiming([event('1', 'frame_enter', ''), event('2', 'frame_exit', '2')]).values()])
    .toEqual(['Timing unavailable', 'Timing unavailable']);
});
