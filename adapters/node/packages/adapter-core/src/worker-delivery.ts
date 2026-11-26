import { MAX_IN_FLIGHT_MESSAGES } from "./runtime/transport.cjs";
import type { FinishWork } from "./runtime/finish-progress.cjs";
import { adjacentEvents, type InputMessage, type RecordingAssembler } from "./worker-core.js";

interface DeliveryHooks {
  /** Takes the oldest already queued message from the same port, without waiting. */
  receivePending?(): InputMessage | undefined;
  finishProgress?(boundary: "received" | "dispatched"): void;
  activeWork?(type: FinishWork): void;
  staged(): void;
  routeFoldStaged?(events: number): void;
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

  function append(message: InputMessage): void {
    if (message.type === "close") closing = true;
    pending.push(message);
    if (message.type === "finish") hooks.finishProgress?.("received");
  }

  function peek(index: number): InputMessage | undefined {
    if (index === pending.length && index < MAX_IN_FLIGHT_MESSAGES && !closing && !stopped) {
      const message = hooks.receivePending?.();
      if (message) append(message);
    }
    return pending[index];
  }

  async function drain(): Promise<void> {
    draining = true;
    try {
      while (pending.length > 0) {
        const message = pending.shift()!;
        hooks.activeWork?.(message.type);
        if (message.type === "close") {
          await assembler.flushHeld();
          await hooks.close();
          return;
        }
        if (message.type === "event") {
          const events = [message];
          while (events.length < MAX_IN_FLIGHT_MESSAGES) {
            const next = peek(0);
            if (!next || !adjacentEvents(events[events.length - 1]!, next)) break;
            events.push(pending.shift()!);
          }
          await assembler.handleEvents(events, credit);
        } else if (message.type === "route") {
          let folded = 0;
          await assembler.handle(message, {
            ...(hooks.activeWork ? { activeWork: hooks.activeWork } : {}),
            peek,
            take(count) {
              pending.splice(0, count);
              folded += count;
            },
          });
          // The route and any folded events are still charged until the
          // combined wire batch is acknowledged.
          if (folded > 0) hooks.routeFoldStaged?.(folded);
          credit(1 + folded);
        } else {
          if (message.type === "finish") hooks.finishProgress?.("dispatched");
          await assembler.handle(message);
          credit(1);
        }
      }
    } catch {
      stop();
      hooks.fail();
    } finally {
      hooks.activeWork?.("idle");
      draining = false;
    }
  }

  return {
    enqueue(message: InputMessage): void {
      if (closing || stopped) return;
      if (message.type !== "close" && pending.length >= MAX_IN_FLIGHT_MESSAGES) {
        stop();
        hooks.fail();
        return;
      }
      append(message);
      if (!draining) void drain();
    },
    abort: stop,
  };
}
