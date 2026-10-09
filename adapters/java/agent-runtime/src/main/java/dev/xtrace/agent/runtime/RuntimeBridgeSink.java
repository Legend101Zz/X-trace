package dev.xtrace.agent.runtime;

import dev.xtrace.agent.bootstrap.BridgeSink;
import java.lang.reflect.Method;
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
  private volatile ApplicationScope scope = ApplicationScope.defaultScope();
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
    return offerSourceEvent(
        recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail,
        null, 0, 0, null, 0);
  }

  @Override
  public boolean offerSourceEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail,
      String sourcePath,
      int startLine,
      int endLine,
      byte[] sourceHash,
      int sourceBinding) {
    if (!acceptingExisting.get()
        || !bounded(recordingId, eventId, parentEventId, symbol)
        || (sourcePath != null && !bounded(sourcePath))
        || (sourceHash != null && sourceHash.length != 32)) return false;
    int bytes = estimate(recordingId, eventId, parentEventId, symbol);
    if (sourcePath != null) bytes += sourcePath.getBytes(StandardCharsets.UTF_8).length;
    if (sourceHash != null) bytes += sourceHash.length;
    return queue.offer(
        new QueueSignal.Event(
            recordingId,
            eventId,
            parentEventId,
            kind,
            symbol,
            monotonicNs,
            detail,
            sourcePath,
            startLine,
            endLine,
            sourceHash == null ? null : sourceHash.clone(),
            sourceBinding,
            bytes),
        false);
  }

  @Override
  public boolean offerMethodEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail,
      Method method) {
    SourceAttestation.SourceInfo source = method == null
        ? SourceAttestation.SourceInfo.unavailable(2)
        : SourceAttestation.lookup(method.getDeclaringClass().getClassLoader(), method);
    return offerSourceEvent(
        recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail,
        source.path(), source.startLine(), source.endLine(), source.hash(), source.binding());
  }

  @Override
  public boolean offerFrameEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail,
      Class<?> type,
      String method,
      String descriptor) {
    SourceAttestation.SourceInfo source = resolveSource(type, method, descriptor);
    return offerSourceEvent(
        recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail,
        source.path(), source.startLine(), source.endLine(), source.hash(), source.binding());
  }

  /** Build-attested source wins; otherwise the class is bound to the source file it names. */
  private static SourceAttestation.SourceInfo resolveSource(
      Class<?> type, String method, String descriptor) {
    ClassLoader loader = type == null ? null : type.getClassLoader();
    if (loader != null && type != null && SourceAttestation.hasEntry(type.getName())) {
      SourceAttestation.SourceInfo attested =
          SourceAttestation.lookup(loader, type.getName(), method, descriptor);
      if (attested.binding() == 1) return attested;
    }
    return SourceIdentity.lookup(type, method, descriptor);
  }

  @Override
  public int applicationScope(Class<?> type) {
    return scope.verdict(type);
  }

  void useScope(ApplicationScope scope) {
    this.scope = java.util.Objects.requireNonNull(scope, "scope");
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
