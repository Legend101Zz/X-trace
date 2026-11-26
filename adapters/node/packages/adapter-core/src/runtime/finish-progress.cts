import { routeFoldDiagnosticOffset } from "./transport.cjs";

export const FINISH_PROGRESS_WORDS = 2;
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
const preparation = ["finish-release", "finish-digest", "finish-envelope"] as const;
export type FinishPreparation = typeof preparation[number];

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

/** The second word tags the phase with the current dispatch ordinal. */
export function noteFinishPreparation(view: BigUint64Array, phase: FinishPreparation | null): void {
  const dispatched = (Atomics.load(view, 0) >> fields.dispatched) & mask;
  Atomics.store(view, 1, phase === null ? 0n : (dispatched << 2n) | BigInt(preparation.indexOf(phase) + 1));
}

export function readFinishProgress(
  view: BigUint64Array,
): (Record<FinishBoundary, number> & { active: FinishWork | FinishPreparation }) | null {
  const snapshot = Atomics.load(view, 0);
  if ((snapshot & overflow) !== 0n) return null;
  const read = (shift: bigint) => Number((snapshot >> shift) & mask);
  const dispatched = read(fields.dispatched);
  const submitted = read(fields.submitted);
  let active: FinishWork | FinishPreparation = work[Number((snapshot & workMask) >> workShift)]!;
  if (active === "finish" && dispatched > submitted) {
    const taggedPhase = Atomics.load(view, 1);
    // Keep the original snapshot when a concurrent transition makes the
    // optional refinement ambiguous or leaves the previous dispatch's tag.
    if (Atomics.load(view, 0) === snapshot && (taggedPhase >> 2n) === BigInt(dispatched)) {
      active = preparation[Number(taggedPhase & 3n) - 1] ?? active;
    }
  }
  return {
    received: read(fields.received), dispatched, submitted,
    written: read(fields.written), staged: read(fields.staged),
    active,
  };
}
