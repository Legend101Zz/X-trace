import { routeFoldDiagnosticOffset } from "./transport.cjs";

export const finishProgressDiagnosticOffset = routeFoldDiagnosticOffset + BigUint64Array.BYTES_PER_ELEMENT;
const fields = { received: 0n, dispatched: 12n, submitted: 24n, written: 36n, staged: 48n } as const;
const mask = 0xfffn;
const overflow = 1n << 63n;
const workShift = 60n;
const workMask = 7n << workShift;
const work = ["idle", "start", "event", "route", "finish", "close", "route-start", "route-held-events"] as const;
export type FinishWork = typeof work[number];
export type RouteWork = Extract<FinishWork, `route${string}`>;
export type FinishBoundary = keyof typeof fields;

/** One worker writes; the app can read a coherent snapshot while that worker is still live. */
export function noteFinishProgress(view: BigUint64Array, boundary: FinishBoundary): void {
  const snapshot = Atomics.load(view, 0);
  if ((snapshot & overflow) !== 0n) return;
  const shift = fields[boundary];
  Atomics.store(view, 0, ((snapshot >> shift) & mask) === mask
    ? snapshot | overflow
    : snapshot + (1n << shift));
}

export function noteFinishWork(view: BigUint64Array, active: FinishWork): void {
  const snapshot = Atomics.load(view, 0);
  Atomics.store(view, 0, (snapshot & ~workMask) | (BigInt(work.indexOf(active)) << workShift));
}

export function readFinishProgress(view: BigUint64Array): (Record<FinishBoundary, number> & { active: FinishWork }) | null {
  const snapshot = Atomics.load(view, 0);
  if ((snapshot & overflow) !== 0n) return null;
  const read = (shift: bigint) => Number((snapshot >> shift) & mask);
  return {
    received: read(fields.received), dispatched: read(fields.dispatched), submitted: read(fields.submitted),
    written: read(fields.written), staged: read(fields.staged),
    active: work[Number((snapshot & workMask) >> workShift)]!,
  };
}
