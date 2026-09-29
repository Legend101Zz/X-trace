import { XtraceClientError } from "./errors.js";

/** Serializes a bounded number of pending protocol writes. A failed task poisons the queue. */
export class BoundedSendQueue {
  private tail: Promise<void> = Promise.resolve();
  private pending = 0;
  private failed = false;

  constructor(private readonly limit: number) {}

  /** Runs a write after earlier writes complete, without allowing an unbounded backlog. */
  enqueue<T>(task: () => Promise<T>): Promise<T> {
    if (this.failed) {
      return Promise.reject(new XtraceClientError("XTR-NODE-TRANSPORT", "XTP send queue has failed"));
    }
    if (this.pending >= this.limit) {
      return Promise.reject(new XtraceClientError("XTR-NODE-TRANSPORT", "XTP send queue is full"));
    }
    this.pending += 1;
    const result = this.tail.then(async () => {
      if (this.failed) throw new XtraceClientError("XTR-NODE-TRANSPORT", "XTP send queue has failed");
      try {
        return await task();
      } catch (error) {
        this.failed = true;
        throw error;
      }
    });
    this.tail = result.then(() => undefined, () => undefined);
    return result.finally(() => { this.pending -= 1; });
  }

  /** Resolves after accepted work has drained. */
  drain(): Promise<void> {
    return this.tail;
  }
}
