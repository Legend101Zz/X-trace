package dev.xtrace.agent.runtime;

sealed interface QueueSignal permits QueueSignal.Start, QueueSignal.Event, QueueSignal.Finish {
  int estimatedBytes();

  record Start(
      String recordingId,
      long monotonicNs,
      String method,
      String route,
      int estimatedBytes)
      implements QueueSignal {}

  record Event(
      String recordingId,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      long monotonicNs,
      int detail,
      String sourcePath,
      int sourceStartLine,
      int sourceEndLine,
      byte[] sourceHash,
      int sourceBinding,
      int estimatedBytes,
      String exceptionType,
      String exceptionMessage)
      implements QueueSignal {
    Event(
        String recordingId,
        String eventId,
        String parentEventId,
        int kind,
        String symbol,
        long monotonicNs,
        int detail,
        int estimatedBytes) {
      this(recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail,
          null, 0, 0, null, 0, estimatedBytes, null, null);
    }

    Event(
        String recordingId,
        String eventId,
        String parentEventId,
        int kind,
        String symbol,
        long monotonicNs,
        int detail,
        String sourcePath,
        int sourceStartLine,
        int sourceEndLine,
        byte[] sourceHash,
        int sourceBinding,
        int estimatedBytes) {
      this(recordingId, eventId, parentEventId, kind, symbol, monotonicNs, detail, sourcePath,
          sourceStartLine, sourceEndLine, sourceHash, sourceBinding, estimatedBytes, null, null);
    }
  }

  record Finish(
      String recordingId,
      long startedMonotonicNs,
      long finishedMonotonicNs,
      int responseStatus,
      long droppedEvents,
      int estimatedBytes,
      dev.xtrace.agent.bootstrap.BridgeSink.Outcome outcome)
      implements QueueSignal {
    Finish(
        String recordingId,
        long startedMonotonicNs,
        long finishedMonotonicNs,
        int responseStatus,
        long droppedEvents,
        int estimatedBytes) {
      this(recordingId, startedMonotonicNs, finishedMonotonicNs, responseStatus, droppedEvents,
          estimatedBytes, null);
    }
  }
}
