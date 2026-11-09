package dev.xtrace.agent.runtime;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.concurrent.TimeUnit;

/** Fixed-slot and fixed-byte queue whose producers never wait for capacity. */
final class BoundedEventQueue {
  private static final int RESERVED_CONTROL_SLOTS = 8;
  private static final int RESERVED_CONTROL_BYTES = 2048;

  // Starts and finishes have their own bounded allowance. Each admitted recording owns at most
  // two lifecycle entries until the writer releases admission, regardless of event-queue pressure.
  static final int MAX_PENDING_RECORDINGS = 256;
  static final int MAX_METADATA_RECORDINGS = 256;
  private static final int LIFECYCLE_SLOTS =
      2 * (MAX_PENDING_RECORDINGS + MAX_METADATA_RECORDINGS);
  private static final int MAX_LIFECYCLE_BYTES = 4096;

  private record Entry(QueueSignal signal, boolean lifecycle) {}

  private final ArrayDeque<Entry> queue = new ArrayDeque<>();
  private final int slotCapacity;
  private final long byteCapacity;
  private int occupiedSlots;
  private long occupiedBytes;
  private int lifecycleSlots;
  private long lifecycleBytes;

  BoundedEventQueue(int slotCapacity, long byteCapacity) {
    if (slotCapacity < RESERVED_CONTROL_SLOTS * 2
        || byteCapacity < RESERVED_CONTROL_BYTES * 2L) {
      throw new IllegalArgumentException("queue capacity is too small");
    }
    this.slotCapacity = slotCapacity;
    this.byteCapacity = byteCapacity;
  }

  synchronized boolean offer(QueueSignal signal, boolean control) {
    int bytes = signal.estimatedBytes();
    if (bytes < 1 || bytes > byteCapacity) return false;
    int slotLimit = control ? slotCapacity : slotCapacity - RESERVED_CONTROL_SLOTS;
    long byteLimit = control ? byteCapacity : byteCapacity - RESERVED_CONTROL_BYTES;
    if (occupiedSlots >= slotLimit || occupiedBytes > byteLimit - bytes) return false;
    occupiedSlots++;
    occupiedBytes += bytes;
    queue.addLast(new Entry(signal, false));
    notifyAll();
    return true;
  }

  /** Only the admission owner may use this allowance, once for start and once for finish. */
  synchronized boolean offerLifecycle(QueueSignal signal) {
    if (!(signal instanceof QueueSignal.Start || signal instanceof QueueSignal.Finish)) {
      throw new IllegalArgumentException("lifecycle signal required");
    }
    int bytes = signal.estimatedBytes();
    if (bytes < 1 || bytes > MAX_LIFECYCLE_BYTES || lifecycleSlots >= LIFECYCLE_SLOTS) {
      return false;
    }
    lifecycleSlots++;
    lifecycleBytes += bytes;
    queue.addLast(new Entry(signal, true));
    notifyAll();
    return true;
  }

  synchronized QueueSignal poll(Duration timeout) throws InterruptedException {
    long remaining = timeout.toNanos();
    long started = System.nanoTime();
    while (queue.isEmpty() && remaining > 0) {
      TimeUnit.NANOSECONDS.timedWait(this, remaining);
      remaining = timeout.toNanos() - (System.nanoTime() - started);
    }
    Entry entry = queue.pollFirst();
    if (entry == null) return null;
    if (entry.lifecycle()) {
      lifecycleSlots--;
      lifecycleBytes -= entry.signal().estimatedBytes();
    } else {
      occupiedSlots--;
      occupiedBytes -= entry.signal().estimatedBytes();
    }
    return entry.signal();
  }

  synchronized boolean isEmpty() {
    return queue.isEmpty();
  }

  synchronized int size() {
    return occupiedSlots + lifecycleSlots;
  }

  synchronized long bytes() {
    return occupiedBytes + lifecycleBytes;
  }
}
