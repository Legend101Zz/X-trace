package dev.xtrace.agent.bootstrap;

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
