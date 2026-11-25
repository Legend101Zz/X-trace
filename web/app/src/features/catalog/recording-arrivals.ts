import type { Recording } from '../../types';

type TimestampedRecording = Pick<Recording, 'recordingId' | 'openedAt'>;

// A bounded page cannot establish capture time relative to polling. This marks rows new to the list.
export function recentlyObserved(previous: readonly TimestampedRecording[], current: readonly TimestampedRecording[]): ReadonlySet<string> {
  const latest = Math.max(...previous.map(({ openedAt }) => Date.parse(openedAt)).filter(Number.isFinite));
  if (previous.length > 0 && !Number.isFinite(latest)) return new Set();
  const seen = new Set(previous.map(({ recordingId }) => recordingId));
  return new Set(current.filter(({ recordingId, openedAt }) => !seen.has(recordingId) && Date.parse(openedAt) > latest)
    .map(({ recordingId }) => recordingId));
}
