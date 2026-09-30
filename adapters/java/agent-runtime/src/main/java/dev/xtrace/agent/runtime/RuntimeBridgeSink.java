package dev.xtrace.agent.runtime;

import dev.xtrace.agent.bootstrap.BridgeSink;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Nonblocking bridge sink that accepts only bounded sanitized event fields. */
final class RuntimeBridgeSink implements BridgeSink {
  private static final int MAX_FIELD_BYTES = 256;
  private static final int MAX_ACTIVE_RECORDINGS = 8;

  private final BoundedEventQueue queue;
  private final AtomicBoolean acceptingStarts = new AtomicBoolean(true);
  private final AtomicBoolean acceptingExisting = new AtomicBoolean(true);
  private final AtomicInteger activeRecordings = new AtomicInteger();
  private final AtomicInteger inFlightStartAdmissions = new AtomicInteger();
  private final AtomicInteger incompleteKind = new AtomicInteger();
  private final Runnable afterStartIncrement;
  private final Runnable beforeStartDecrement;

  RuntimeBridgeSink(BoundedEventQueue queue) {
    this(queue, () -> {}, () -> {});
  }

  RuntimeBridgeSink(
      BoundedEventQueue queue, Runnable afterStartIncrement, Runnable beforeStartDecrement) {
    this.queue = queue;
    this.afterStartIncrement = afterStartIncrement;
    this.beforeStartDecrement = beforeStartDecrement;
  }

  @Override
  public boolean offerStart(String recordingId, long monotonicNs, String method, String route) {
    inFlightStartAdmissions.incrementAndGet();
    try {
      afterStartIncrement.run();
      if (!acceptingStarts.get()
          || !bounded(recordingId, method, route)
          || !reserveRecording()) return rejectStart();
      int bytes = estimate(recordingId, method, route);
      boolean accepted =
          queue.offer(new QueueSignal.Start(recordingId, monotonicNs, method, route, bytes), false);
      if (!accepted) {
        activeRecordings.decrementAndGet();
        return rejectStart();
      }
      return accepted;
    } finally {
      beforeStartDecrement.run();
      inFlightStartAdmissions.decrementAndGet();
    }
  }

  @Override
  public boolean offerEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail) {
    if (!acceptingExisting.get()
        || !bounded(recordingId, eventId, parentEventId, symbol)) return false;
    int bytes = estimate(recordingId, eventId, parentEventId, symbol);
    return queue.offer(
        new QueueSignal.Event(
            recordingId,
            eventId,
            parentEventId,
            kind,
            symbol,
            monotonicNs,
            detail,
            bytes),
        false);
  }

  @Override
  public boolean offerFinish(
      String recordingId,
      long startedMonotonicNs,
      long finishedMonotonicNs,
      int responseStatus,
      long droppedEvents) {
    try {
      if (!acceptingExisting.get() || !bounded(recordingId)) return false;
      int bytes = estimate(recordingId);
      return queue.offer(
          new QueueSignal.Finish(
              recordingId,
              startedMonotonicNs,
              finishedMonotonicNs,
              responseStatus,
              droppedEvents,
              bytes),
          true);
    } finally {
      activeRecordings.updateAndGet(current -> current > 0 ? current - 1 : 0);
    }
  }

  @Override
  public void reportIncomplete(int failureKind) {
    if (failureKind == INCOMPLETE_START_REJECTED
        || failureKind == INCOMPLETE_FINISH_REJECTED) {
      incompleteKind.accumulateAndGet(failureKind, Math::max);
    }
  }

  void stopStarting() {
    acceptingStarts.set(false);
  }

  void stopAccepting() {
    acceptingStarts.set(false);
    acceptingExisting.set(false);
  }

  int takeIncompleteKind() {
    return incompleteKind.getAndSet(0);
  }

  int activeRecordings() {
    return activeRecordings.get();
  }

  boolean startAdmissionsDrained() {
    return inFlightStartAdmissions.get() == 0;
  }

  private boolean rejectStart() {
    reportIncomplete(INCOMPLETE_START_REJECTED);
    return false;
  }

  private boolean reserveRecording() {
    int current = activeRecordings.get();
    while (current < MAX_ACTIVE_RECORDINGS) {
      if (activeRecordings.compareAndSet(current, current + 1)) return true;
      current = activeRecordings.get();
    }
    return false;
  }

  private static boolean bounded(String... values) {
    for (String value : values) {
      if (value == null || value.getBytes(StandardCharsets.UTF_8).length > MAX_FIELD_BYTES) {
        return false;
      }
    }
    return true;
  }

  private static int estimate(String... values) {
    int bytes = 64;
    for (String value : values) bytes += value.getBytes(StandardCharsets.UTF_8).length;
    return bytes;
  }
}
