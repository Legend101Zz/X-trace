/** Result of appending one cursor page to a bounded in-memory window. */
export interface RetainedPage<T> {
  /** Newest retained values in their original order. */
  items: T[];
  /** Number of oldest values released from the viewer's memory. */
  released: number;
}

/** A bounded display window that keeps its independent server continuation. */
export interface RetainedCursorPage<T, Cursor> extends RetainedPage<T> {
  /** Cursor returned by the current server page, unaffected by row eviction. */
  nextCursor: Cursor | null;
}

/**
 * Appends a page while keeping long-lived viewer state bounded.
 *
 * The caller must retain the server cursor independently so paging can
 * continue after older display rows have been released.
 */
export function retainPage<T, Cursor>(
  previous: readonly T[],
  incoming: readonly T[],
  maximum: number,
  nextCursor: Cursor | null,
): RetainedCursorPage<T, Cursor> {
  const combined = [...previous, ...incoming];
  const released = Math.max(0, combined.length - maximum);
  return { items: combined.slice(released), released, nextCursor };
}
