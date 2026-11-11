package dev.xtrace.agent.runtime;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.adapter.XtpSession;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.crypto.digests.Blake3Digest;
import xtp.agent.v1.CapabilityOuterClass.Capability;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.CapabilityOuterClass.SourceRange;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.ExceptionPayload;
import xtp.agent.v1.Recording.GapPayload;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.OutcomeKind;
import xtp.agent.v1.Recording.RecordingOutcome;
import xtp.agent.v1.Recording.Interaction;
import xtp.agent.v1.Recording.InteractionKind;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Recording.CapturedValue;
import xtp.agent.v1.Recording.SourceBinding;
import xtp.agent.v1.Recording.ValueBinding;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.Health;

/** Single owner of XTP session order, protobuf encoding, batching, and staged ACK validation. */
final class RecordingWriter implements AutoCloseable, Runnable {
  private static final Duration POLL_INTERVAL = Duration.ofMillis(25);
  private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(2);
  /** CONTRACTS 4.4: standard mode sends up to 16,384 events per recording. */
  static final int MAX_EVENTS_PER_RECORDING = 16_384;
  static final int MAX_FOCUSED_EVENTS_PER_RECORDING = 131_072;
  private static final int GAP_RESERVE = 4;
  static final long MAX_PENDING_EVENT_BYTES = 32L * 1024 * 1024;
  /** Event-cap slots reserved for closing events; gap space and the memory bound still apply. */
  static final int CLOSING_RESERVE = 64;
  static final String CAP_GAP_SYMBOL = "xtrace.capture.gap.recording-cap";
  /** Missing application coverage, from an entered skipped method or unavailable invocation probes. */
  static final String UNTRANSFORMED_GAP_SYMBOL = "xtrace.capture.gap.not-transformed";
  static final String ADMISSION_GAP_SYMBOL = "xtrace.capture.gap.recording-admission";
  static final String MEMORY_GAP_SYMBOL = "xtrace.capture.gap.writer-memory";
  static final String FRAME_GAP_SYMBOL = "xtrace.capture.gap.frame-limit";
  static final String START_FRAME_GAP_SYMBOL = FRAME_GAP_SYMBOL + ".started";
  static final String FINISH_FRAME_GAP_SYMBOL = FRAME_GAP_SYMBOL + ".finished";

  private final Transport session;
  private final BoundedEventQueue queue;
  private final RuntimeBridgeSink sink;
  private final Thread thread;
  private final Duration shutdownTimeout;
  private final AtomicBoolean stopping = new AtomicBoolean();
  private final AtomicBoolean shutdownRequested = new AtomicBoolean();
  private final AtomicBoolean incompleteReported = new AtomicBoolean();
  private final Map<String, PendingRecording> recordings = new HashMap<>();
  private final long maxPendingEventBytes;
  private long pendingEventBytes;
  private long reportedRejectedStarts;
  private volatile long shutdownStartedNs;
  private volatile String capturePolicyId = "";

  RecordingWriter(XtpSession session, BoundedEventQueue queue, RuntimeBridgeSink sink)
      throws ClientException {
    this(new SessionTransport(session), queue, sink, SHUTDOWN_TIMEOUT);
  }

  RecordingWriter(
      Transport session,
      BoundedEventQueue queue,
      RuntimeBridgeSink sink,
      Duration shutdownTimeout)
      throws ClientException {
    this(session, queue, sink, shutdownTimeout, MAX_PENDING_EVENT_BYTES);
  }

  RecordingWriter(
      Transport session, BoundedEventQueue queue, RuntimeBridgeSink sink,
      Duration shutdownTimeout, long maxPendingEventBytes) throws ClientException {
    if (shutdownTimeout.isZero() || shutdownTimeout.isNegative()) {
      throw new IllegalArgumentException("shutdown timeout must be positive");
    }
    if (maxPendingEventBytes < 1 || maxPendingEventBytes > MAX_PENDING_EVENT_BYTES) {
      throw new IllegalArgumentException("pending event byte capacity is out of bounds");
    }
    this.session = session;
    this.queue = queue;
    this.sink = sink;
    this.shutdownTimeout = shutdownTimeout;
    this.maxPendingEventBytes = maxPendingEventBytes;
    sendCapabilities();
    this.thread = new Thread(this, "xtrace-java-writer");
    this.thread.setDaemon(true);
  }

  void start() {
    thread.start();
  }

  boolean isStopping() {
    return stopping.get();
  }

  boolean incompleteWasReported() {
    return incompleteReported.get();
  }

  @Override
  public void run() {
    try {
      int signalsSinceFlush = 0;
      while (!stopping.get()) {
        observeIncompleteSignal();
        reportRejectedStarts();
        if (stopping.get() || shutdownDrained()) break;
        if (shutdownExpired()) {
          reportIncomplete();
          break;
        }
        QueueSignal signal = queue.poll(POLL_INTERVAL);
        if (signal != null) accept(signal);
        // A quiet request must not wait for Finish or for its own batch to fill. Bound the
        // drain too, so traffic from other requests cannot indefinitely delay its events.
        if (signal == null || ++signalsSinceFlush >= MAX_BATCH_EVENTS) {
          for (PendingRecording recording : recordings.values()) flush(recording, false);
          signalsSinceFlush = 0;
        }
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      if (!stopping.get()) reportIncomplete();
    } catch (ClientException | RuntimeException failure) {
      failClosed();
    } finally {
      sink.stopAccepting();
      observeIncompleteSignal();
      if (!sink.startAdmissionsDrained()
          || !recordings.isEmpty()
          || !queue.isEmpty()
          || sink.activeRecordings() > 0) {
        reportIncomplete();
      }
      BootstrapBridge.disable(sink);
      closeSessionQuietly();
    }
  }

  private void accept(QueueSignal signal) throws ClientException {
    if (signal instanceof QueueSignal.Start start) {
      if (recordings.containsKey(start.recordingId())) {
        throw new ClientException("XTR-JAVA-RECORDING", "recording identity is invalid");
      }
      if (recordings.size() >= BoundedEventQueue.MAX_PENDING_RECORDINGS
          + BoundedEventQueue.MAX_METADATA_RECORDINGS) {
        throw new ClientException("XTR-JAVA-RECORDING", "recording admission invariant violated");
      }
      PendingRecording recording = new PendingRecording(start);
      recordings.put(start.recordingId(), recording);
      sendStart(recording);
    } else if (signal instanceof QueueSignal.Event event) {
      PendingRecording recording = recordings.get(event.recordingId());
      if (recording == null) {
        throw new ClientException("XTR-JAVA-RECORDING", "event recording identity is unknown");
      }
      int cap = eventCap(capturePolicyId);
      int limit = closing(event.kind()) ? cap - GAP_RESERVE : cap - CLOSING_RESERVE;
      long bytes = Math.max(128, event.estimatedBytes());
      if (recording.start.metadataOnly() || recording.unrecoverable
          || recording.acceptedEvents >= limit) {
        recording.writerDrops = saturatingAdd(recording.writerDrops, 1);
      } else if (pendingEventBytes <= maxPendingEventBytes - bytes) {
        recording.events.add(event);
        if (event.kind() != BridgeEventKind.FRAME_THROW) recording.eventBytes += bytes;
        pendingEventBytes += bytes;
        recording.acceptedEvents++;
        // Retain only throw identities needed by terminal outcomes, charging their original
        // allocation against the same global budget even after their payloads are sent.
        if (event.kind() == BridgeEventKind.FRAME_THROW) {
          recording.throwEventIds.add(event.eventId());
          recording.retainedThrowBytes += bytes;
        }
        recording.batchBytes += toProto(event, 2).getSerializedSize() + 8;
        if (recording.events.size() >= MAX_BATCH_EVENTS
            || recording.batchBytes >= MAX_BATCH_BYTES) flush(recording, false);
      } else {
        recording.memoryDrops = saturatingAdd(recording.memoryDrops, 1);
      }
    } else if (signal instanceof QueueSignal.Finish finish) {
      PendingRecording recording = recordings.remove(finish.recordingId());
      if (recording == null) {
        throw new ClientException("XTR-JAVA-RECORDING", "finish recording identity is unknown");
      }
      try {
        write(recording, finish);
      } finally {
        pendingEventBytes -= recording.eventBytes + recording.retainedThrowBytes;
        sink.recordingClosed(recording.start);
      }
    }
  }

  static int eventCap(String policyId) {
    return "xtrace.focused.v1".equals(policyId)
        ? MAX_FOCUSED_EVENTS_PER_RECORDING : MAX_EVENTS_PER_RECORDING;
  }

  private static boolean closing(int kind) {
    return kind == BridgeEventKind.FRAME_EXIT
        || kind == BridgeEventKind.FRAME_THROW
        || kind == BridgeEventKind.RESPONSE;
  }

  /** Policy the recordings claim; the daemon grants focused only for a session armed focused. */
  void capturePolicy(String policyId) {
    this.capturePolicyId = policyId == null ? "" : policyId;
  }

  private void sendStart(PendingRecording pending) throws ClientException {
    UUID recordingId;
    try {
      recordingId = UUID.fromString(pending.start.recordingId());
    } catch (IllegalArgumentException invalid) {
      throw new ClientException("XTR-JAVA-RECORDING", "recording identity is invalid", invalid);
    }
    byte[] recordingBytes = uuidBytes(recordingId);
    pending.recordingId = recordingId;
    String messageId = pending.start.recordingId() + ":started";
    RecordingStarted.Builder start = RecordingStarted.newBuilder()
        .setRecordingId(ByteString.copyFrom(recordingBytes))
        .setRecordingSeq(1)
        .setMethod(pending.start.method())
        .setMatchedRouteTemplate(pending.start.route())
        .setUrlShape(pending.start.route())
        .setStartMonotonicNs(pending.start.monotonicNs())
        .setThreadOrTaskId("request-thread")
        .setCapturePolicyId(capturePolicyId);
    boolean reduced = !session.fitsEnvelope(messageId, pending.start.recordingId(), start.build());
    if (reduced) {
      // Prefer the observed route template to its duplicate URL shape. Never truncate a route
      // into a different route, or discard the method, clock or capture policy to make it fit.
      start.clearUrlShape();
      if (!session.fitsEnvelope(messageId, pending.start.recordingId(), start.build())) {
        start.clearMatchedRouteTemplate().clearThreadOrTaskId();
      }
      if (!session.fitsEnvelope(messageId, pending.start.recordingId(), start.build())) {
        abandon(pending, "RecordingStarted identity exceeds the frame limit");
        return;
      }
    }
    Ack started =
        session.send(
            messageId,
            pending.start.recordingId(),
            start.build());
    requireRecordingAck(started, recordingId, 1);
    pending.started = true;
    if (reduced) sendLifecycleGap(pending, "started", pending.start.monotonicNs(),
        START_FRAME_GAP_SYMBOL);
  }

  private void write(PendingRecording pending, QueueSignal.Finish finish) throws ClientException {
    if (pending.unrecoverable) return;
    pending.finishObserved = true;
    pending.queueDrops = finish.droppedEvents();
    long droppedEvents = saturatingAdd(
        finish.droppedEvents(), saturatingAdd(pending.writerDrops, pending.memoryDrops));
    // Metadata-only admission retains the actual identity and terminal observation, but none of
    // the request's event stream. Count at least its missing request observation, even for a
    // caller that supplies no shed count. No response, parent link or timing is reconstructed.
    if (pending.start.metadataOnly()) droppedEvents = Math.max(1, droppedEvents);
    long skippedTransforms = pending.start.metadataOnly() ? 0 : finish.untransformedCount();
    List<QueueSignal.Event> ordered =
        pending.start.metadataOnly()
            ? List.of(gap(pending.start.recordingId(), "",
                terminalMonotonic(pending.start.monotonicNs(), finish.finishedMonotonicNs()),
                droppedEvents, ":gap-admission", ADMISSION_GAP_SYMBOL))
            : withGap(
            pending.start.recordingId(),
            pending.events,
            finish.droppedEvents(),
            pending.writerDrops,
            skippedTransforms,
            pending.memoryDrops,
            pending.start.monotonicNs(),
            finish.finishedMonotonicNs());
    if (!pending.start.metadataOnly() && pending.events.isEmpty() && pending.sequence > 1) {
      // Preserve the same gap frontier even when its preceding event was already sent.
      ordered = new ArrayList<>();
      addGaps(ordered, pending.start.recordingId(), pending.lastEventId, pending.lastMonotonicNs,
          finish.droppedEvents(), pending.writerDrops, skippedTransforms, pending.memoryDrops);
    }
    pending.events.clear();
    pending.events.addAll(ordered);
    flush(pending, true);
    if (pending.unrecoverable) return;
    droppedEvents = saturatingAdd(droppedEvents, pending.frameDrops);
    if (pending.sequence == 1) {
      throw new ClientException("XTR-JAVA-RECORDING", "recording contains no accepted events");
    }
    byte[] digest = new byte[32];
    RecordingFinished.Builder terminal =
        RecordingFinished.newBuilder()
            .setRecordingId(ByteString.copyFrom(uuidBytes(pending.recordingId)))
            .setFinalRecordingSeq(pending.sequence)
            .setDurationNs(duration(finish.startedMonotonicNs(), finish.finishedMonotonicNs()))
            .setEventDigest(ByteString.copyFrom(digest));
    if (droppedEvents > 0) terminal.putDropCountsByPriority(1, droppedEvents);
    if (finish.outcome() != null) {
      RecordingOutcome outcome = outcomeProto(finish.outcome());
      String thrownFrom = outcome.getThrownFromEventId();
      if (!thrownFrom.isEmpty() && !pending.throwEventIds.contains(thrownFrom)) {
        // A throw's event identity belongs to the discarded stream, not to this gap marker.
        outcome = outcome.toBuilder().clearThrownFromEventId().build();
      }
      terminal.setOutcome(outcome);
    }
    String messageId = pending.start.recordingId() + ":finished";
    if (!session.fitsEnvelope(messageId, pending.start.recordingId(), terminal.build())) {
      // Keep the observed exception type and outcome kind. Omitted optional detail is named by
      // a digest-covered gap, never replaced with text that could look like an observed value.
      if (terminal.hasOutcome()) {
        RecordingOutcome.Builder outcome = terminal.getOutcome().toBuilder();
        if (outcome.hasException()) {
          outcome.setException(outcome.getException().toBuilder().clearSanitizedMessage());
        }
        terminal.setOutcome(outcome);
      }
      terminal.setFinalRecordingSeq(Math.addExact(pending.sequence, 1))
          .putDropCountsByPriority(1, saturatingAdd(droppedEvents, 1));
      if (!session.fitsEnvelope(messageId, pending.start.recordingId(), terminal.build())) {
        terminal.setOutcome(terminal.getOutcome().toBuilder().clearThrownFromEventId());
      }
      if (!session.fitsEnvelope(messageId, pending.start.recordingId(), terminal.build())) {
        abandon(pending, "RecordingFinished identity exceeds the frame limit");
        return;
      }
      if (!sendLifecycleGap(pending, "finished",
          terminalMonotonic(pending.start.monotonicNs(), finish.finishedMonotonicNs()),
          FINISH_FRAME_GAP_SYMBOL)) return;
    }
    pending.digest.doFinal(digest, 0);
    terminal.setEventDigest(ByteString.copyFrom(digest));
    Ack finished =
        session.send(
            messageId,
            pending.start.recordingId(),
            terminal.build());
    requireRecordingAck(finished, pending.recordingId, pending.sequence);
  }

  /** A lifecycle reduction consumes a real sequence and participates in terminal loss accounting. */
  private boolean sendLifecycleGap(
      PendingRecording pending, String stage, long monotonicNs, String symbol)
      throws ClientException {
    if (pending.sequence > eventCap(capturePolicyId)) {
      abandon(pending, "frame-limit " + stage + " marker exceeds the event limit");
      return false;
    }
    QueueSignal.Event gap = gap(pending.start.recordingId(), "", monotonicNs, 1,
        ":gap-frame-" + stage, symbol);
    long sequence = Math.addExact(pending.sequence, 1);
    EventBatch.Builder batch = newBatch(uuidBytes(pending.recordingId))
        .addEvents(toProto(gap, sequence));
    if (!fitsBatch(pending, batch)) {
      abandon(pending, "frame-limit " + stage + " marker could not be sent");
      return false;
    }
    sendChunk(pending, pending.recordingId, batch, pending.chunk++, sequence);
    pending.sequence = sequence;
    pending.lastEventId = gap.eventId();
    pending.lastMonotonicNs = monotonicNs;
    // A start marker consumes event capacity before the request's later observations arrive.
    pending.acceptedEvents++;
    byte[] id = gap.eventId().getBytes(StandardCharsets.UTF_8);
    pending.digest.update(id, 0, id.length);
    pending.frameDrops = saturatingAdd(pending.frameDrops, 1);
    return true;
  }

  private void abandon(PendingRecording pending, String reason) throws ClientException {
    if (pending.unrecoverable) return;
    pending.unrecoverable = true;
    incompleteReported.set(true);
    if (pending.started) {
      // An absent digest already seals the prefix as partial: total loss is unknown, including
      // observations that may arrive after abandonment. The wire counters are exact, so only
      // include them once Finish supplies the queue loss and closes the observation stream.
      // Omitted lifecycle detail is not a dropped event. Never invent a count to force Partial,
      // even when every event was sent and only the finish cannot fit.
      long knownDrops = saturatingAdd(pending.queueDrops, saturatingAdd(pending.writerDrops,
          saturatingAdd(pending.memoryDrops, pending.frameEventDrops)));
      RecordingFinished.Builder terminal = RecordingFinished.newBuilder()
          .setRecordingId(ByteString.copyFrom(uuidBytes(pending.recordingId)))
          .setFinalRecordingSeq(pending.sequence);
      if (pending.finishObserved && knownDrops > 0) {
        terminal.putDropCountsByPriority(1, knownDrops);
      }
      // A compact UUID message ID leaves room for even the widest exact counter and sequence
      // whenever the Start identity fitted; its lifecycle message IDs contain a suffix.
      String messageId = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(uuidBytes(pending.recordingId));
      Ack finished = session.send(messageId,
          pending.start.recordingId(), terminal.build());
      requireRecordingAck(finished, pending.recordingId, pending.sequence);
    }
    // Only fixed reasons and the validated UUID belong in diagnostics, never captured fields.
    System.err.println("{\"code\":\"XTR-JAVA-CAPTURE-INCOMPLETE\","
        + "\"message\":\"X-trace " + reason + "; affected recording remains incomplete\","
        + "\"recordingId\":\"" + pending.recordingId + "\"}");
  }

  /** Sends the buffered prefix; the response stays behind terminal gap accounting until Finish. */
  private void flush(PendingRecording pending, boolean finishing) throws ClientException {
    if (pending.unrecoverable) return;
    int count = pending.events.size();
    if (!finishing) {
      for (int i = 0; i < count; i++) {
        if (pending.events.get(i).kind() == BridgeEventKind.RESPONSE) {
          count = i;
          break;
        }
      }
    }
    if (count == 0) return;
    EventBatch.Builder batch = newBatch(uuidBytes(pending.recordingId));
    for (int index = 0; index < count; index++) {
      QueueSignal.Event event = pending.events.get(index);
      long sequence = Math.addExact(pending.sequence, 1);
      RecordingEvent proto = toProto(event, sequence);
      batch.addEvents(proto);
      if (!fitsBatch(pending, batch)) {
        batch.removeEvents(batch.getEventsCount() - 1);
        if (batch.getEventsCount() > 0) {
          sendChunk(pending, pending.recordingId, batch, pending.chunk++, pending.sequence);
        }
        batch = newBatch(uuidBytes(pending.recordingId));
        batch.addEvents(proto);
        if (!fitsBatch(pending, batch)) {
          // Keep this observation's identity, order and clock, but make none of its discarded
          // source/value/frame claims. Children still refer to the observed slot, now a gap.
          proto = toProto(new QueueSignal.Event(event.recordingId(), event.eventId(),
              event.parentEventId(), BridgeEventKind.GAP, FRAME_GAP_SYMBOL,
              event.monotonicNs(), 1, 128), sequence);
          batch.setEvents(0, proto);
          if (!fitsBatch(pending, batch)) {
            // The event identity cannot fit even as a GAP; retire only the accepted prefix.
            long discarded = pending.events.subList(index, pending.events.size()).stream()
                .filter(buffered -> buffered.kind() != BridgeEventKind.GAP).count();
            pending.frameEventDrops = saturatingAdd(pending.frameEventDrops, discarded);
            abandon(pending, "frame-limit gap could not be sent");
            batch.clearEvents();
            break;
          }
          pending.frameDrops = saturatingAdd(pending.frameDrops, 1);
          if (event.kind() != BridgeEventKind.GAP) {
            pending.frameEventDrops = saturatingAdd(pending.frameEventDrops, 1);
          }
          // A terminal exception must not claim this gap is an observed throw.
          pending.throwEventIds.remove(event.eventId());
        }
      }
      pending.sequence = sequence;
      pending.lastEventId = event.eventId();
      pending.lastMonotonicNs = event.monotonicNs();
      byte[] id = event.eventId().getBytes(StandardCharsets.UTF_8);
      pending.digest.update(id, 0, id.length);
    }
    if (batch.getEventsCount() > 0) {
      sendChunk(pending, pending.recordingId, batch, pending.chunk++, pending.sequence);
    }
    if (!finishing) {
      for (QueueSignal.Event event : pending.events.subList(0, count)) {
        if (event.kind() != BridgeEventKind.FRAME_THROW) {
          long bytes = Math.max(128, event.estimatedBytes());
          pending.eventBytes -= bytes;
          pendingEventBytes -= bytes;
        }
      }
    }
    pending.events.subList(0, count).clear();
    pending.batchBytes = 0;
  }

  /** Maps the bridge outcome to the wire outcome; sanitizes exception text off the app thread. */
  static RecordingOutcome outcomeProto(BridgeSink.Outcome outcome) {
    RecordingOutcome.Builder builder = RecordingOutcome.newBuilder();
    switch (outcome.kind()) {
      case BridgeSink.Outcome.RESPONDED -> {
        builder.setKind(OutcomeKind.OUTCOME_KIND_RESPONDED).setHttpStatus(outcome.httpStatus());
      }
      case BridgeSink.Outcome.EXCEPTION_PROPAGATED -> {
        builder.setKind(OutcomeKind.OUTCOME_KIND_EXCEPTION_PROPAGATED);
        ExceptionPayload.Builder exception = ExceptionPayload.newBuilder();
        String type = ExceptionSummary.type(outcome.exceptionType());
        exception.setExceptionType(type == null ? "" : type);
        String message = ExceptionSummary.message(outcome.exceptionMessage());
        if (message != null) exception.setSanitizedMessage(message);
        builder.setException(exception);
        if (outcome.thrownFromEventId() != null) {
          builder.setThrownFromEventId(outcome.thrownFromEventId());
        }
      }
      default -> builder.setKind(OutcomeKind.OUTCOME_KIND_UNOBSERVED);
    }
    return builder.build();
  }

  static List<QueueSignal.Event> withGap(
      String recordingId,
      List<QueueSignal.Event> events,
      long droppedEvents,
      long startedMonotonicNs,
      long finishedMonotonicNs) {
    return withGap(recordingId, events, droppedEvents, 0, startedMonotonicNs, finishedMonotonicNs);
  }

  /**
   * Queue sheds and per-recording cap overflow are separate causes with separate gap events
   * (QUEUE_FULL versus THROTTLE), both placed before the response.
   */
  static List<QueueSignal.Event> withGap(
      String recordingId,
      List<QueueSignal.Event> events,
      long queueDrops,
      long capDrops,
      long startedMonotonicNs,
      long finishedMonotonicNs) {
    return withGap(
        recordingId, events, queueDrops, capDrops, 0, startedMonotonicNs, finishedMonotonicNs);
  }

  /** As above, plus one CLASS_NOT_TRANSFORMED gap when {@code untransformed} classes or methods were skipped. */
  static List<QueueSignal.Event> withGap(
      String recordingId,
      List<QueueSignal.Event> events,
      long queueDrops,
      long capDrops,
      long untransformed,
      long startedMonotonicNs,
      long finishedMonotonicNs) {
    return withGap(recordingId, events, queueDrops, capDrops, untransformed, 0,
        startedMonotonicNs, finishedMonotonicNs);
  }

  private static List<QueueSignal.Event> withGap(
      String recordingId, List<QueueSignal.Event> events, long queueDrops, long capDrops,
      long untransformed, long memoryDrops, long startedMonotonicNs, long finishedMonotonicNs) {
    if (queueDrops <= 0 && capDrops <= 0 && untransformed <= 0 && memoryDrops <= 0) {
      return List.copyOf(events);
    }
    List<QueueSignal.Event> result = new ArrayList<>(events.size() + GAP_RESERVE);
    boolean inserted = false;
    for (QueueSignal.Event event : events) {
      if (!inserted && event.kind() == BridgeEventKind.RESPONSE) {
        addGaps(result, event.recordingId(), event.parentEventId(), event.monotonicNs(),
            queueDrops, capDrops, untransformed, memoryDrops);
        inserted = true;
      }
      result.add(event);
    }
    if (!inserted) {
      String parent = events.isEmpty() ? "" : events.get(events.size() - 1).eventId();
      long monotonicNs =
          events.isEmpty()
              ? terminalMonotonic(startedMonotonicNs, finishedMonotonicNs)
              : events.get(events.size() - 1).monotonicNs();
      addGaps(result, recordingId, parent, monotonicNs,
          queueDrops, capDrops, untransformed, memoryDrops);
    }
    return result;
  }

  private static void addGaps(
      List<QueueSignal.Event> out, String recordingId, String parent, long monotonicNs,
      long queueDrops, long capDrops, long untransformed, long memoryDrops) {
    String last = parent;
    if (queueDrops > 0) {
      QueueSignal.Event gap = gap(recordingId, last, monotonicNs, queueDrops, ":gap",
          "xtrace.capture.gap");
      out.add(gap);
      last = gap.eventId();
    }
    if (capDrops > 0) {
      QueueSignal.Event gap =
          gap(recordingId, last, monotonicNs, capDrops, ":gap-cap", CAP_GAP_SYMBOL);
      out.add(gap);
      last = gap.eventId();
    }
    if (untransformed > 0) {
      QueueSignal.Event gap = gap(recordingId, last, monotonicNs, untransformed,
          ":gap-untransformed", UNTRANSFORMED_GAP_SYMBOL);
      out.add(gap);
      last = gap.eventId();
    }
    if (memoryDrops > 0) {
      out.add(gap(recordingId, last, monotonicNs, memoryDrops, ":gap-memory", MEMORY_GAP_SYMBOL));
    }
  }

  private static QueueSignal.Event gap(
      String recordingId, String parent, long monotonicNs, long droppedEvents, String suffix,
      String symbol) {
    String eventId = recordingId + suffix;
    return new QueueSignal.Event(
        recordingId,
        eventId,
        parent,
        RecordingEventKind.RECORDING_EVENT_KIND_GAP.getNumber(),
        symbol,
        monotonicNs,
        Math.max(1, droppedEvents),
        128);
  }

  /** Conservative bounds under the daemon's advertised 256 events and 1 MiB envelope. */
  static final int MAX_BATCH_EVENTS = 200;

  static final int MAX_BATCH_BYTES = 256 * 1024;

  private boolean fitsBatch(PendingRecording pending, EventBatch.Builder batch)
      throws ClientException {
    EventBatch payload = batch.build();
    return payload.getEventsCount() <= MAX_BATCH_EVENTS
        && payload.getSerializedSize() <= MAX_BATCH_BYTES
        && session.fitsEnvelope(chunkId(pending, pending.chunk), pending.start.recordingId(), payload);
  }

  private static EventBatch.Builder newBatch(byte[] recordingBytes) {
    return EventBatch.newBuilder().setRecordingId(ByteString.copyFrom(recordingBytes));
  }

  private void sendChunk(
      PendingRecording pending, UUID recordingId, EventBatch.Builder batch, int chunk, long lastSeq)
      throws ClientException {
    String id = chunkId(pending, chunk);
    Ack ack = session.send(id, pending.start.recordingId(), batch.build());
    requireRecordingAck(ack, recordingId, lastSeq);
  }

  private static String chunkId(PendingRecording pending, int chunk) {
    return pending.start.recordingId() + ":events" + (chunk == 0 ? "" : ":" + chunk);
  }

  static RecordingEvent toProto(QueueSignal.Event event, long sequence)
      throws ClientException {
    RecordingEventKind kind = RecordingEventKind.forNumber(event.kind());
    if (kind == null || kind == RecordingEventKind.RECORDING_EVENT_KIND_UNSPECIFIED) {
      throw new ClientException("XTR-JAVA-EVENT", "recording event kind is invalid");
    }
    RecordingEvent.Builder builder =
        RecordingEvent.newBuilder()
            .setEventId(event.eventId())
            .setRecordingSeq(sequence)
            .setParentEventId(event.parentEventId())
            .setMonotonicNs(event.monotonicNs())
            .setPriority(1)
            .setKind(kind)
            .setSymbol(event.symbol());
    SourceBinding binding = SourceBinding.forNumber(event.sourceBinding());
    builder.setSourceBinding(
        binding == null ? SourceBinding.SOURCE_BINDING_ATTESTATION_MISSING : binding);
    if (event.sourcePath() != null && event.sourceHash() != null) {
      builder.setSource(
          SourceRange.newBuilder()
              .setPath(event.sourcePath())
              .setStartLine(event.sourceStartLine())
              .setEndLine(event.sourceEndLine())
              .setContentHash(ByteString.copyFrom(event.sourceHash())));
    }
    if (kind == RecordingEventKind.RECORDING_EVENT_KIND_GAP) {
      // A gap always states why and how much. Events shed by the bounded queue are QUEUE_FULL
      // with the shed count; an unresolvable handler is a lost correlation, count one.
      boolean handler = event.symbol().equals(BootstrapBridge.HANDLER_UNRESOLVED_SYMBOL);
      // The per-recording event cap has no dedicated reason: THROTTLE is the nearest accurate
      // one (events withheld by a configured limit); a dedicated reason is requested from C.
      boolean cap = event.symbol().equals(CAP_GAP_SYMBOL);
      boolean admission = event.symbol().equals(ADMISSION_GAP_SYMBOL);
      boolean memory = event.symbol().equals(MEMORY_GAP_SYMBOL);
      boolean frame = event.symbol().equals(FRAME_GAP_SYMBOL)
          || event.symbol().equals(START_FRAME_GAP_SYMBOL)
          || event.symbol().equals(FINISH_FRAME_GAP_SYMBOL);
      boolean lines = event.symbol().equals(BootstrapBridge.LINE_BUDGET_SYMBOL);
      boolean untransformed = event.symbol().equals(UNTRANSFORMED_GAP_SYMBOL);
      builder.setGap(
          GapPayload.newBuilder()
              .setReason(handler ? GapReason.GAP_REASON_CORRELATION_LOST
                  : lines ? GapReason.GAP_REASON_LINE_BUDGET
                  : untransformed ? GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED
                  : cap || admission || memory || frame
                      ? GapReason.GAP_REASON_THROTTLE : GapReason.GAP_REASON_QUEUE_FULL)
              .setCount(handler ? 1 : Math.max(1, event.detail())));
    }
    if (event.values() != null) {
      for (dev.xtrace.agent.runtime.line.ValueSnapshot value : event.values()) {
        builder.addBindings(binding(value));
      }
    }
    if (kind == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW
        && event.exceptionType() != null) {
      ExceptionPayload.Builder exception =
          ExceptionPayload.newBuilder().setExceptionType(ExceptionSummary.type(event.exceptionType()));
      String message = ExceptionSummary.message(event.exceptionMessage());
      if (message != null) exception.setSanitizedMessage(message);
      builder.setException(exception);
    }
    if (kind == RecordingEventKind.RECORDING_EVENT_KIND_REQUEST_UPDATE) {
      // The request event symbol is "http.request <METHOD> <route template>", both validated by
      // the bridge; nothing about the route is assumed here.
      String[] parts = event.symbol().split(" ", 3);
      boolean shaped = parts.length == 3 && parts[0].equals("http.request");
      builder.setInteraction(
          Interaction.newBuilder()
              .setKind(InteractionKind.INTERACTION_KIND_FRAMEWORK)
              .setDriver("spring-mvc")
              .setMethod(shaped ? parts[1] : "")
              .setPath(shaped ? parts[2] : ""));
    } else if (kind == RecordingEventKind.RECORDING_EVENT_KIND_RESPONSE) {
      builder.setInteraction(
          Interaction.newBuilder()
              .setKind(InteractionKind.INTERACTION_KIND_FRAMEWORK)
              .setDriver("spring-mvc")
              .setMethod("status")
              .setPath(event.detail() == 0 ? "unavailable" : Long.toString(event.detail())));
    } else if (kind == RecordingEventKind.RECORDING_EVENT_KIND_DATABASE_START
        || kind == RecordingEventKind.RECORDING_EVENT_KIND_DATABASE_END) {
      builder.setInteraction(
          Interaction.newBuilder()
              .setKind(InteractionKind.INTERACTION_KIND_DATABASE)
              .setDriver("h2")
              .setMethod("executeUpdate"));
    }
    return builder.build();
  }

  /** Wire binding for one sanitized local (CAPTURED, TRUNCATED, REDACTED or UNAVAILABLE). */
  static ValueBinding binding(dev.xtrace.agent.runtime.line.ValueSnapshot value) {
    CapturedValue.Builder captured = CapturedValue.newBuilder();
    xtp.agent.v1.Recording.ValueShape shape =
        xtp.agent.v1.Recording.ValueShape.valueOf("VALUE_SHAPE_" + value.shape().name());
    switch (value.state()) {
      case CAPTURED -> captured.setCaptured(
          xtp.agent.v1.Recording.CapturedValueCaptured.newBuilder()
              .setShape(shape)
              .setPreview(value.preview())
              .setContentHash(ByteString.copyFrom(value.contentHash())));
      case TRUNCATED -> captured.setTruncated(
          xtp.agent.v1.Recording.CapturedValueTruncated.newBuilder()
              .setPreview(value.preview())
              .setOriginalSizeLowerBound(value.originalSizeLowerBound())
              .setLimit(value.limit()));
      case REDACTED -> captured.setRedacted(
          xtp.agent.v1.Recording.CapturedValueRedacted.newBuilder()
              .setRuleId(value.ruleId())
              .setShapeHint(shape));
      default -> captured.setUnavailable(
          xtp.agent.v1.Recording.CapturedValueUnavailable.newBuilder()
              .setReason(
                  value.reason() == dev.xtrace.agent.runtime.line.ValueSnapshot.Reason.DEBUG_METADATA_ABSENT
                      ? xtp.agent.v1.Recording.UnavailableReason.UNAVAILABLE_REASON_DEBUG_METADATA_ABSENT
                      : xtp.agent.v1.Recording.UnavailableReason.UNAVAILABLE_REASON_UNSAFE_TO_RENDER));
    }
    return ValueBinding.newBuilder()
        .setName(value.name())
        .setRole(
            switch (value.role()) {
              case ARGUMENT -> xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_ARGUMENT;
              case RETURN -> xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_RETURN;
              case LOCAL -> xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_LOCAL;
              case EXCEPTION -> xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_EXCEPTION;
              case RECEIVER -> xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_RECEIVER;
            })
        .setNameOrigin(
            value.nameOrigin() == dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin.DECLARED
                ? xtp.agent.v1.Recording.NameOrigin.NAME_ORIGIN_DECLARED
                : xtp.agent.v1.Recording.NameOrigin.NAME_ORIGIN_SYNTHESIZED)
        .setValue(captured)
        .build();
  }

  private void sendCapabilities() throws ClientException {
    Capability frames =
        Capability.newBuilder()
            .setName("method_frames")
            .putConfig("scope", "application_scope")
            .build();
    Capability database =
        Capability.newBuilder().setName("database").putConfig("driver", "h2").build();
    session.send(
        "java-premain-capabilities",
        "",
        CapabilitySet.newBuilder().addCapabilities(frames).addCapabilities(database).build());
  }

  static long duration(long start, long finish) {
    long elapsed = finish - start;
    return elapsed > 0 ? elapsed : 1;
  }

  private static long terminalMonotonic(long start, long finish) {
    return finish - start > 0 ? finish : start;
  }

  static long saturatingAdd(long left, long right) {
    if (left < 0 || right < 0 || left > Long.MAX_VALUE - right) return Long.MAX_VALUE;
    return left + right;
  }

  private static byte[] uuidBytes(UUID value) {
    java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(16);
    buffer.putLong(value.getMostSignificantBits());
    buffer.putLong(value.getLeastSignificantBits());
    return buffer.array();
  }

  private static void requireRecordingAck(Ack ack, UUID recordingId, long expected)
      throws ClientException {
    if (ack.getHighestContiguousRecordingSeqOrDefault(recordingId.toString(), 0) != expected) {
      throw new ClientException("XTR-JAVA-ACK", "recording acknowledgement is invalid");
    }
  }

  private void failClosed() {
    stopIncomplete();
  }

  void stopIncomplete() {
    sink.stopAccepting();
    BootstrapBridge.disable(sink);
    stopping.set(true);
    if (thread.isAlive() && Thread.currentThread() != thread) thread.interrupt();
    reportIncomplete();
  }

  private void reportIncomplete() {
    if (incompleteReported.compareAndSet(false, true)) {
      System.err.println(
          "{\"code\":\"XTR-JAVA-CAPTURE-INCOMPLETE\",\"message\":\"X-trace recording transport stopped; application continues\"}");
    }
  }

  private void observeIncompleteSignal() {
    int failureKind = sink.takeIncompleteKind();
    if (failureKind == BridgeSink.INCOMPLETE_FINISH_REJECTED) {
      stopIncomplete();
    } else if (failureKind == BridgeSink.INCOMPLETE_START_REJECTED) {
      reportIncomplete();
    }
  }

  private void reportRejectedStarts() throws ClientException {
    long rejected = sink.rejectedStarts();
    if (rejected == reportedRejectedStarts) return;
    try {
      session.send("java-rejected-starts:" + rejected, "", Health.newBuilder()
          .setMonotonicNs(System.nanoTime())
          .setQueueDepthBatches(queue.size())
          .setResidentBytes(queue.bytes() + pendingEventBytes)
          .setStatus("recording-starts-rejected=" + rejected)
          .build());
    } catch (ClientException failure) {
      if (!"XTR-JAVA-ENVELOPE".equals(failure.code())) throw failure;
      // Local preflight rejection writes nothing and leaves the session usable. Health has no
      // recording sequence: report the loss once for this count and let active streams finish.
      System.err.println(
          "{\"code\":\"XTR-JAVA-ENVELOPE\",\"message\":\"X-trace health payload was not sent; recording capture continues\"}");
    }
    reportedRejectedStarts = rejected;
  }

  private boolean shutdownDrained() {
    return shutdownRequested.get()
        && sink.startAdmissionsDrained()
        && queue.isEmpty()
        && recordings.isEmpty()
        && sink.activeRecordings() == 0;
  }

  private boolean shutdownExpired() {
    return shutdownRequested.get()
        && System.nanoTime() - shutdownStartedNs >= shutdownTimeout.toNanos();
  }

  @Override
  public void close() {
    sink.stopStarting();
    shutdownStartedNs = System.nanoTime();
    shutdownRequested.set(true);
    if (thread.getState() == Thread.State.NEW) {
      if (!sink.startAdmissionsDrained() || !queue.isEmpty() || sink.activeRecordings() > 0) {
        reportIncomplete();
      }
      sink.stopAccepting();
      closeSessionQuietly();
      return;
    }
    try {
      thread.join(shutdownTimeout.toMillis() + POLL_INTERVAL.toMillis() + 250);
      if (thread.isAlive()) stopIncomplete();
      thread.join(250);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      stopIncomplete();
    }
    if (!thread.isAlive()) {
      closeSessionQuietly();
    }
  }

  private void closeSessionQuietly() {
    try {
      session.close();
    } catch (ClientException ignored) {
      // Capture shutdown remains fail-open and never changes application termination.
    }
  }

  private static final class PendingRecording {
    private final QueueSignal.Start start;
    private final List<QueueSignal.Event> events = new ArrayList<>();
    private final Set<String> throwEventIds = new HashSet<>();
    private final Blake3Digest digest = new Blake3Digest(256);
    private UUID recordingId;
    private long sequence = 1;
    private String lastEventId = "";
    private long lastMonotonicNs;
    private int chunk;
    private int acceptedEvents;
    private long batchBytes;
    private long writerDrops;
    private long memoryDrops;
    private long frameDrops;
    private long queueDrops;
    private boolean finishObserved;
    // Actual lost observations, excluding synthetic lifecycle and coalesced gap markers.
    private long frameEventDrops;
    private boolean unrecoverable;
    private boolean started;
    // Buffered non-throw allocations and retained throw allocations are disjoint charges.
    private long eventBytes;
    private long retainedThrowBytes;

    private PendingRecording(QueueSignal.Start start) {
      this.start = start;
    }
  }

  interface Transport {
    Ack send(String messageId, String correlationToken, Message payload) throws ClientException;

    boolean fitsEnvelope(String messageId, String correlationToken, Message payload)
        throws ClientException;

    void close() throws ClientException;
  }

  private record SessionTransport(XtpSession session) implements Transport {
    private SessionTransport {
      java.util.Objects.requireNonNull(session, "session");
    }

    @Override
    public Ack send(String messageId, String correlationToken, Message payload)
        throws ClientException {
      return session.send(messageId, correlationToken, payload);
    }

    @Override
    public boolean fitsEnvelope(String messageId, String correlationToken, Message payload)
        throws ClientException {
      return session.fitsEnvelope(messageId, correlationToken, payload);
    }

    @Override
    public void close() throws ClientException {
      session.close();
    }
  }
}
