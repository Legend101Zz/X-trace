import { MAX_IN_FLIGHT_MESSAGES } from "./runtime/transport.cjs";
import { adjacentEvents, type InputMessage, type RecordingAssembler } from "./worker-core.js";

interface DeliveryHooks {
  staged(): void;
  close(): Promise<void>;
  fail(): void;
}

/** Drains the charged FIFO. Batching only uses work already waiting behind delivery. */
export function createWorkerDelivery(assembler: RecordingAssembler, hooks: DeliveryHooks) {
  const pending: InputMessage[] = [];
  let draining = false;
  let closing = false;
  let stopped = false;

  function stop(): void {
    stopped = true;
    pending.length = 0;
  }

  function credit(count: number): void {
    if (stopped) return;
    for (let index = 0; index < count; index += 1) hooks.staged();
  }

  async function drain(): Promise<void> {
    draining = true;
    try {
      while (pending.length > 0) {
        const message = pending.shift()!;
        if (message.type === "close") {
          await assembler.flushHeld();
          await hooks.close();
          return;
        }
        if (message.type === "event") {
          const events = [message];
          while (pending[0] && adjacentEvents(events[events.length - 1]!, pending[0])) {
            events.push(pending.shift()!);
          }
          await assembler.handleEvents(events, credit);
        } else {
          await assembler.handle(message);
          credit(1);
        }
      }
    } catch {
      stop();
      hooks.fail();
    } finally {
      draining = false;
    }
  }

  return {
    enqueue(message: InputMessage): void {
      if (closing || stopped) return;
      if (message.type === "close") closing = true;
      else if (pending.length >= MAX_IN_FLIGHT_MESSAGES) {
        stop();
        hooks.fail();
        return;
      }
      pending.push(message);
      if (!draining) void drain();
    },
    abort: stop,
  };
}
