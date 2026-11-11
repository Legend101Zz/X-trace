package dev.xtrace.agent.runtime;

import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Nonblocking bridge sink that accepts only bounded sanitized event fields. */
final class RuntimeBridgeSink implements BridgeSink {
  private static final int MAX_FIELD_BYTES = 256;
  static final int DEFAULT_PENDING_RECORDINGS = 64;
  static final String PENDING_RECORDINGS_PROPERTY = "xtrace.agent.maxPendingRecordings";

  private final BoundedEventQueue queue;
  private final AtomicBoolean acceptingStarts = new AtomicBoolean(true);
  private final AtomicBoolean acceptingExisting = new AtomicBoolean(true);
  private final AtomicInteger activeRecordings = new AtomicInteger();
  private final AtomicInteger metadataRecordings = new AtomicInteger();
  private final java.util.Set<String> metadataOnly = ConcurrentHashMap.newKeySet();
  private final AtomicLong rejectedStarts = new AtomicLong();
  private final int maxPendingRecordings;
  private final int maxMetadataRecordings;
  private final AtomicInteger inFlightStartAdmissions = new AtomicInteger();
  private final AtomicInteger incompleteKind = new AtomicInteger();
  private volatile ApplicationScope scope = ApplicationScope.defaultScope();
  private volatile java.util.function.LongSupplier untransformed = () -> 0L;
  private final Runnable afterStartIncrement;
  private final Runnable beforeStartDecrement;

  RuntimeBridgeSink(BoundedEventQueue queue) {
    this(queue, () -> {}, () -> {});
  }

  RuntimeBridgeSink(
      BoundedEventQueue queue, Runnable afterStartIncrement, Runnable beforeStartDecrement) {
    this(queue, pendingRecordings(System.getProperty(PENDING_RECORDINGS_PROPERTY)),
        BoundedEventQueue.MAX_METADATA_RECORDINGS, afterStartIncrement, beforeStartDecrement);
  }

  RuntimeBridgeSink(BoundedEventQueue queue, int maxPendingRecordings, int maxMetadataRecordings) {
    this(queue, maxPendingRecordings, maxMetadataRecordings, () -> {}, () -> {});
  }

  private RuntimeBridgeSink(
      BoundedEventQueue queue, int maxPendingRecordings, int maxMetadataRecordings,
      Runnable afterStartIncrement, Runnable beforeStartDecrement) {
    if (maxPendingRecordings < 1
        || maxPendingRecordings > BoundedEventQueue.MAX_PENDING_RECORDINGS
        || maxMetadataRecordings < 0
        || maxMetadataRecordings > BoundedEventQueue.MAX_METADATA_RECORDINGS) {
      throw new IllegalArgumentException("recording capacity is out of bounds");
    }
    this.queue = queue;
    this.maxPendingRecordings = maxPendingRecordings;
    this.maxMetadataRecordings = maxMetadataRecordings;
    this.afterStartIncrement = afterStartIncrement;
    this.beforeStartDecrement = beforeStartDecrement;
  }

  @Override
  public boolean offerStart(String recordingId, long monotonicNs, String method, String route) {
    inFlightStartAdmissions.incrementAndGet();
    try {
      afterStartIncrement.run();
      if (!acceptingStarts.get()
          || !bounded(recordingId, method, route)) return rejectStart();
      boolean metadata = !reserve(activeRecordings, maxPendingRecordings);
      if (metadata) {
        if (!reserve(metadataRecordings, maxMetadataRecordings)) return rejectStart();
        metadataOnly.add(recordingId);
      }
      int bytes = estimate(recordingId, method, route);
      boolean accepted =
          queue.offerLifecycle(
              new QueueSignal.Start(recordingId, monotonicNs, method, route, bytes, metadata));
      if (!accepted) {
        if (metadata) {
          metadataOnly.remove(recordingId);
          metadataRecordings.decrementAndGet();
        } else {
          activeRecordings.decrementAndGet();
        }
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
        || metadataOnly.contains(recordingId)
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
  public boolean offerThrowEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      String symbol,
      long monotonicNs,
      String exceptionType,
      String exceptionMessage) {
    if (!acceptingExisting.get() || !bounded(recordingId, eventId, parentEventId, symbol)
        || metadataOnly.contains(recordingId)) {
      return false;
    }
    int bytes = estimate(recordingId, eventId, parentEventId, symbol) + 1600;
    return queue.offer(
        new QueueSignal.Event(
            recordingId, eventId, parentEventId, BridgeEventKind.FRAME_THROW, symbol,
            monotonicNs, 0, null, 0, 0, null, 0, bytes, exceptionType, exceptionMessage),
        false);
  }

  /** Offers a focused line cursor with bounded sanitized locals; never blocks. */
  boolean offerLineEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      String symbol,
      long monotonicNs,
      SourceAttestation.SourceInfo source,
      java.util.List<dev.xtrace.agent.runtime.line.ValueSnapshot> values) {
    if (!acceptingExisting.get()
        || source == null
        || source.path() == null
        || source.hash() == null
        || source.hash().length != 32
        || !bounded(recordingId, eventId, parentEventId, symbol, source.path())
        || metadataOnly.contains(recordingId)) {
      return false;
    }
    int bytes = estimate(recordingId, eventId, parentEventId, symbol)
        + source.path().getBytes(StandardCharsets.UTF_8).length + 32;
    for (dev.xtrace.agent.runtime.line.ValueSnapshot value : values) {
      bytes += 96 + (value.name() == null ? 0 : value.name().length() * 3)
          + (value.preview() == null ? 0 : value.preview().length() * 3);
    }
    return queue.offer(
        new QueueSignal.Event(
            recordingId, eventId, parentEventId, BridgeEventKind.LINE_CURSOR, symbol, monotonicNs,
            0, source.path(), source.startLine(), source.endLine(), source.hash().clone(),
            source.binding(), bytes, null, null, List.copyOf(values)),
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
    if (loader != null && type != null) {
      SourceAttestation.SourceInfo attested =
          SourceAttestation.attest(loader, type.getName(), method, descriptor);
      if (attested != null) return attested;
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

  /** Sampled on the request thread when Finish is produced, before asynchronous draining. */
  void untransformedCount(java.util.function.LongSupplier supplier) {
    untransformed = java.util.Objects.requireNonNull(supplier, "supplier");
  }

  @Override
  public boolean offerFinish(
      String recordingId,
      long startedMonotonicNs,
      long finishedMonotonicNs,
      int responseStatus,
      long droppedEvents) {
    return offerFinishWithOutcome(
        recordingId, startedMonotonicNs, finishedMonotonicNs, responseStatus, droppedEvents, null);
  }

  @Override
  public boolean offerFinishWithOutcome(
      String recordingId,
      long startedMonotonicNs,
      long finishedMonotonicNs,
      int responseStatus,
      long droppedEvents,
      Outcome outcome) {
    // The recording slot stays counted until the writer has written (or abandoned) it, so the
    // sink never admits more recordings than the writer can hold. A rejected finish keeps its
    // slot: the writer still holds the recording and the shortfall is reported as incomplete.
    {
      if (!acceptingExisting.get() || !bounded(recordingId)) return false;
      int bytes = estimate(recordingId) + (outcome == null ? 0 : 1800);
      return queue.offerLifecycle(
          new QueueSignal.Finish(
              recordingId,
              startedMonotonicNs,
              finishedMonotonicNs,
              responseStatus,
              droppedEvents,
              bytes,
              outcome,
              untransformed.getAsLong()));
    }
  }

  /** Called by the writer once a recording is written or abandoned; frees its admission slot. */
  void recordingClosed() {
    activeRecordings.updateAndGet(current -> current > 0 ? current - 1 : 0);
  }

  void recordingClosed(QueueSignal.Start start) {
    if (start.metadataOnly()) {
      metadataOnly.remove(start.recordingId());
      metadataRecordings.decrementAndGet();
    } else {
      recordingClosed();
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
    return activeRecordings.get() + metadataRecordings.get();
  }

  long rejectedStarts() {
    return rejectedStarts.get();
  }

  boolean startAdmissionsDrained() {
    return inFlightStartAdmissions.get() == 0;
  }

  private boolean rejectStart() {
    rejectedStarts.updateAndGet(current -> current == Long.MAX_VALUE ? current : current + 1);
    reportIncomplete(INCOMPLETE_START_REJECTED);
    return false;
  }

  private static boolean reserve(AtomicInteger counter, int limit) {
    int current = counter.get();
    while (current < limit) {
      if (counter.compareAndSet(current, current + 1)) return true;
      current = counter.get();
    }
    return false;
  }

  /** Invalid configuration falls back to the tested default; it cannot remove the hard bound. */
  static int pendingRecordings(String configured) {
    if (configured == null) return DEFAULT_PENDING_RECORDINGS;
    try {
      int value = Integer.parseInt(configured);
      return value > 0 && value <= BoundedEventQueue.MAX_PENDING_RECORDINGS
          ? value : DEFAULT_PENDING_RECORDINGS;
    } catch (NumberFormatException invalid) {
      return DEFAULT_PENDING_RECORDINGS;
    }
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
