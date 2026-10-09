package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;

/** JDK-only handoff from inlined advice to the private agent runtime. */
public interface BridgeSink {
  /** A complete request recording could not be admitted. */
  int INCOMPLETE_START_REJECTED = 1;

  /** An admitted recording could not enqueue its terminal marker. */
  int INCOMPLETE_FINISH_REJECTED = 2;

  /** Offers a recording start without waiting for queue capacity. */
  boolean offerStart(String recordingId, long monotonicNs, String method, String route);

  /** Offers one sanitized event without retaining application objects. */
  boolean offerEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail);

  /** Offers a method event with bounded compile-time source attestation facts. */
  default boolean offerSourceEvent(
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
    return offerEvent(recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail);
  }

  /** Offers a fixture frame and delegates manifest lookup to the private agent runtime. */
  default boolean offerMethodEvent(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail,
      Method method) {
    return offerEvent(recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail);
  }

  /**
   * Offers a method boundary identified by declaring class, method name and descriptor. The
   * runtime resolves source facts from its own class registry. Defaults to a plain event.
   */
  default boolean offerFrameEvent(
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
    return offerEvent(recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail);
  }

  /** Scope verdict for a handler type: 1 application, 0 not application, -1 scope unknown. */
  default int applicationScope(Class<?> type) {
    return 1;
  }

  /** Offers the bounded recording terminal marker and accumulated loss count. */
  boolean offerFinish(
      String recordingId,
      long startedMonotonicNs,
      long finishedMonotonicNs,
      int responseStatus,
      long droppedEvents);

  /** Reports process-level loss without blocking or performing transport on the caller thread. */
  void reportIncomplete(int failureKind);
}
