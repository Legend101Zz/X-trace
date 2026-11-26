import { expect, it } from 'vitest';
import type { ReplayEvent } from '../types';
import { retainReplayWindow } from './window';
import type { ReplayPage } from './window';

function page(items: string[], requestCursor: string | null, prevCursor: string | null, nextCursor: string | null): ReplayPage {
  return { events: items.map((sequence) => ({ sequence }) as ReplayEvent), requestCursor, prevCursor, nextCursor, startKnown: prevCursor === null };
}

it('keeps whole pages and their exact boundary cursors across eviction in either direction', () => {
  const first = page(['2', '3'], null, null, 'forward');
  const later = page(['4', '5'], 'forward', 'backward', 'continue');
  const joined = retainReplayWindow([first], later, 'later', 4);
  expect(joined.events.map(({ sequence }) => sequence)).toEqual(['2', '3', '4', '5']);
  expect(joined.prevCursor).toBeNull();
  expect(joined.nextCursor).toBe('continue');
  const newest = retainReplayWindow([first], later, 'later', 3);
  expect(newest.events.map(({ sequence }) => sequence)).toEqual(['4', '5']);
  expect(newest.prevCursor).toBe('backward');
  expect(newest.released).toBe(2);
  const earlier = page(['2', '3'], 'backward', null, 'forward');
  const oldest = retainReplayWindow(newest.pages, earlier, 'earlier', 3);
  expect(oldest.events.map(({ sequence }) => sequence)).toEqual(['2', '3']);
  expect(oldest.nextCursor).toBe('forward');
  expect(oldest.startKnown).toBe(true);
});

it('allows a short page and compares exact large sequences without number conversion', () => {
  const old = page(['9007199254740992'], null, null, 'next');
  const updated = retainReplayWindow([old], page(['9007199254740993'], 'next', 'prev', null), 'later', 10);
  expect(updated.events.map(({ sequence }) => sequence)).toEqual(['9007199254740992', '9007199254740993']);
  expect(updated.nextCursor).toBeNull();
});

it('rejects wrong and looping cursors and out-of-order or overlapping pages', () => {
  const old = page(['4', '5'], null, 'prev', 'next');
  for (const invalid of [
    page(['6'], 'wrong', 'prev2', null),
    page(['6'], 'next', 'prev2', 'next'),
    page(['5', '6'], 'next', 'prev2', null),
    page(['7', '6'], 'next', 'prev2', null),
    page([], 'next', 'prev2', null),
  ]) expect(() => retainReplayWindow([old], invalid, 'later', 10)).toThrow();
  expect(() => retainReplayWindow([old], page(['3', '4'], 'prev', null, 'next'), 'earlier', 10)).toThrow();
});
