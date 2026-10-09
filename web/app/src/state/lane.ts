import { useRef } from 'react';

/**
 * Stale-reply guard for one request lane. Each begin() supersedes the previous request:
 * it bumps the generation and aborts the previous in-flight fetch. A reply may only
 * change state while isCurrent(generation) still holds.
 */
export class Lane {
  private generation = 0;
  private controller: AbortController | null = null;

  /** Start a new request; returns its generation and an abort signal. */
  begin(): { generation: number; signal: AbortSignal } {
    this.controller?.abort();
    this.controller = new AbortController();
    this.generation += 1;
    return { generation: this.generation, signal: this.controller.signal };
  }

  /** Supersede any in-flight request without starting a new one. */
  invalidate(): void {
    this.controller?.abort();
    this.controller = null;
    this.generation += 1;
  }

  isCurrent(generation: number): boolean {
    return generation === this.generation;
  }
}

export function useLane(): Lane {
  const ref = useRef<Lane | null>(null);
  if (ref.current === null) ref.current = new Lane();
  return ref.current;
}
