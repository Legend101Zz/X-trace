import { expect, it } from 'vitest';
import { recentlyObserved } from './recording-arrivals';

const row = (recordingId: string, openedAt: string) => ({ recordingId, openedAt });

it('does not treat an older recording entering a bounded page as an arrival', () => {
  const original = row('existing', '2026-10-03T10:00:00Z');
  const older = row('older', '2026-10-03T09:00:00Z');
  const newer = row('newer', '2026-10-03T11:00:00Z');
  expect([...recentlyObserved([original], [newer, original, older])]).toEqual(['newer']);
});

it('only marks observed timestamps when an empty list gains its first records', () => {
  const valid = row('dated', '2026-10-03T10:00:00Z');
  const unknown = row('unknown', 'unavailable');
  expect([...recentlyObserved([], [valid, unknown])]).toEqual(['dated']);
  expect([...recentlyObserved([unknown], [valid])]).toEqual([]);
});
