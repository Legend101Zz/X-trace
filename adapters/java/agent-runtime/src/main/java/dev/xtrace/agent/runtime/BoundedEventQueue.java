package dev.xtrace.agent.runtime;

import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Fixed-slot and fixed-byte queue whose producers never wait for capacity. */
final class BoundedEventQueue {
  private static final int RESERVED_CONTROL_SLOTS = 8;
  private static final int RESERVED_CONTROL_BYTES = 2048;

  private final ArrayBlockingQueue<QueueSignal> queue;
  private final int slotCapacity;
  private final long byteCapacity;
  private final AtomicInteger occupiedSlots = new AtomicInteger();
  private final AtomicLong occupiedBytes = new AtomicLong();

  BoundedEventQueue(int slotCapacity, long byteCapacity) {
    if (slotCapacity < RESERVED_CONTROL_SLOTS * 2
        || byteCapacity < RESERVED_CONTROL_BYTES * 2L) {
      throw new IllegalArgumentException("queue capacity is too small");
    }
    this.queue = new ArrayBlockingQueue<>(slotCapacity);
    this.slotCapacity = slotCapacity;
    this.byteCapacity = byteCapacity;
  }

  boolean offer(QueueSignal signal, boolean control) {
    int bytes = signal.estimatedBytes();
    if (bytes < 1 || bytes > byteCapacity) return false;
    int slotLimit = control ? slotCapacity : slotCapacity - RESERVED_CONTROL_SLOTS;
    long byteLimit = control ? byteCapacity : byteCapacity - RESERVED_CONTROL_BYTES;
    if (!reserveSlot(slotLimit)) return false;
    if (!reserveBytes(bytes, byteLimit)) {
      occupiedSlots.decrementAndGet();
      return false;
    }
    if (queue.offer(signal)) return true;
    occupiedBytes.addAndGet(-bytes);
    occupiedSlots.decrementAndGet();
    return false;
  }

  QueueSignal poll(Duration timeout) throws InterruptedException {
    QueueSignal signal = queue.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
    if (signal != null) {
      occupiedBytes.addAndGet(-signal.estimatedBytes());
      occupiedSlots.decrementAndGet();
    }
    return signal;
  }

  boolean isEmpty() {
    return queue.isEmpty();
  }

  int size() {
    return occupiedSlots.get();
  }

  long bytes() {
    return occupiedBytes.get();
  }

  private boolean reserveSlot(int limit) {
    int current = occupiedSlots.get();
    while (current < limit) {
      if (occupiedSlots.compareAndSet(current, current + 1)) return true;
      current = occupiedSlots.get();
    }
    return false;
  }

  private boolean reserveBytes(int bytes, long limit) {
    long current = occupiedBytes.get();
    while (current <= limit - bytes) {
      if (occupiedBytes.compareAndSet(current, current + bytes)) return true;
      current = occupiedBytes.get();
    }
    return false;
  }
}
