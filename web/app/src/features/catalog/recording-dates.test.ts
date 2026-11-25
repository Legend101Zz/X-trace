import { describe, expect, it } from 'vitest';
import { formatRecordingDates } from './recording-dates';

describe('recording timestamps', () => {
  it('groups by local midnight rather than the date in the server timestamp', () => {
    const format = formatRecordingDates(new Date('2026-03-09T07:05:00Z'), 'America/Los_Angeles');
    expect(format('2026-03-09T07:00:00Z').day).toBe('Today');
    expect(format('2026-03-09T06:59:59Z').day).toBe('Yesterday');
    expect(format('2026-03-08T00:01:00-08:00').day).toBe('Yesterday');
  });

  it('keeps a 25-hour day together and distinguishes its two local 1:30 times', () => {
    const format = formatRecordingDates(new Date('2026-11-01T22:00:00Z'), 'America/New_York');
    const first = format('2026-11-01T05:30:00Z');
    const second = format('2026-11-01T06:30:00Z');
    expect(first.day).toBe('Today');
    expect(second.key).toBe(first.key);
    expect(second.time).not.toBe(first.time);
    expect(format('2026-11-01T03:59:59Z').day).toBe('Yesterday');
  });

  it('labels older dates with their local calendar day', () => {
    const timeZone = 'America/Los_Angeles';
    const format = formatRecordingDates(new Date('2026-01-03T08:05:00Z'), timeZone);
    expect(format('2026-01-01T07:59:59Z').day).toBe(
      new Intl.DateTimeFormat(undefined, { timeZone, dateStyle: 'medium' }).format(new Date('2025-12-31T12:00:00Z')),
    );
  });

  it.each([undefined, null, '', 'yesterday', '2026-02-30T08:00:00Z', '2026-03-08T12:00:00'])(
    'shows a date-unavailable fallback for %s',
    (value) => {
      const format = formatRecordingDates(new Date('2026-03-09T07:05:00Z'), 'UTC');
      expect(format(value)).toEqual({ key: null, day: 'Date unavailable', time: null });
    },
  );
});
