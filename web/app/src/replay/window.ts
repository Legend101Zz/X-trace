import type { Detail, ReplayEvent } from '../types';

export type WindowDirection = 'replace' | 'earlier' | 'later';

export interface ReplayPage {
  requestCursor: string | null;
  prevCursor: string | null;
  nextCursor: string | null;
  events: readonly ReplayEvent[];
  /** Only an initial read or a successful earlier read establishes this boundary. */
  startKnown: boolean;
}

export function replayPage(response: Detail, requestCursor: string | null, direction: WindowDirection): ReplayPage {
  const prevCursor = response.prevCursor ?? null;
  return {
    requestCursor, prevCursor, nextCursor: response.nextCursor ?? null, events: response.events,
    startKnown: prevCursor === null && (requestCursor === null || direction === 'earlier'),
  };
}

const sequence = (value: string): bigint | null => /^\d+$/.test(value) ? BigInt(value) : null;

function precedes(before: ReplayEvent, after: ReplayEvent): boolean {
  const first = sequence(before.sequence);
  const second = sequence(after.sequence);
  return first !== null && second !== null && first < second;
}

/** Keep whole pages so a retained boundary always has the corresponding server cursor. */
export function retainReplayWindow(previous: readonly ReplayPage[], incoming: ReplayPage, direction: WindowDirection, maximum: number) {
  if (incoming.events.length > maximum) throw new Error('Replay page exceeds the retained event limit');
  if (direction !== 'replace' && previous.length > 0) {
    const edge = direction === 'earlier' ? previous[0] : previous[previous.length - 1];
    const first = incoming.events[0];
    const last = incoming.events[incoming.events.length - 1];
    if (!first || !last || incoming.events.some((item, index) => index > 0 && !precedes(incoming.events[index - 1], item))) {
      throw new Error('Replay continuation did not return an advancing ordered page');
    }
    if (direction === 'earlier') {
      if (edge.prevCursor !== incoming.requestCursor || !edge.events[0] || !precedes(last, edge.events[0])
          || incoming.prevCursor === incoming.requestCursor) throw new Error('Replay predecessor does not continue the retained window');
    } else if (edge.nextCursor !== incoming.requestCursor || !edge.events[edge.events.length - 1]
      || !precedes(edge.events[edge.events.length - 1], first) || incoming.nextCursor === incoming.requestCursor) {
      throw new Error('Replay successor does not continue the retained window');
    }
  }

  const pages = direction === 'replace' ? [incoming] : direction === 'earlier' ? [incoming, ...previous] : [...previous, incoming];
  let retained = pages.reduce((count, page) => count + page.events.length, 0);
  let released = 0;
  while (retained > maximum) {
    const page = direction === 'earlier' ? pages.pop() : pages.shift();
    if (!page) break;
    retained -= page.events.length;
    released += page.events.length;
  }
  const first = pages[0];
  const last = pages[pages.length - 1];
  return {
    pages, released, events: pages.flatMap((page) => page.events),
    prevCursor: first?.prevCursor ?? null, nextCursor: last?.nextCursor ?? null,
    startKnown: first?.startKnown ?? false,
  };
}
