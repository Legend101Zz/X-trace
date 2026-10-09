package dev.xtrace.agent.runtime;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.adapter.XtpSession;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
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
import xtp.agent.v1.Recording.SourceBinding;
import xtp.agent.v1.Transport.Ack;

/** Single owner of XTP session order, protobuf encoding, batching, and staged ACK validation. */
final class RecordingWriter implements AutoCloseable, Runnable {
  private static final Duration POLL_INTERVAL = Duration.ofMillis(25);
  private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(2);
  private static final int MAX_EVENTS_PER_RECORDING = 128;

  private final Transport session;
  private final BoundedEventQueue queue;
  private final RuntimeBridgeSink sink;
  private final Thread thread;
  private final Duration shutdownTimeout;
  private final AtomicBoolean stopping = new AtomicBoolean();
  private final AtomicBoolean shutdownRequested = new AtomicBoolean();
  private final AtomicBoolean incompleteReported = new AtomicBoolean();
  private final Map<String, PendingRecording> recordings = new HashMap<>();
  private volatile long shutdownStartedNs;

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
    if (shutdownTimeout.isZero() || shutdownTimeout.isNegative()) {
      throw new IllegalArgumentException("shutdown timeout must be positive");
    }
    this.session = session;
    this.queue = queue;
    this.sink = sink;
    this.shutdownTimeout = shutdownTimeout;
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
      while (!stopping.get()) {
        observeIncompleteSignal();
        if (stopping.get() || shutdownDrained()) break;
        if (shutdownExpired()) {
          reportIncomplete();
          break;
        }
        QueueSignal signal = queue.poll(POLL_INTERVAL);
        if (signal != null) accept(signal);
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
      if (recordings.size() >= 8 || recordings.containsKey(start.recordingId())) {
        throw new ClientException(
            "XTR-JAVA-RECORDING", "recording writer capacity or identity is invalid");
      }
      recordings.put(start.recordingId(), new PendingRecording(start));
    } else if (signal instanceof QueueSignal.Event event) {
      PendingRecording recording = recordings.get(event.recordingId());
      if (recording == null) {
        throw new ClientException("XTR-JAVA-RECORDING", "event recording identity is unknown");
      }
      if (recording.events.size() < MAX_EVENTS_PER_RECORDING) {
        recording.events.add(event);
      } else {
        recording.writerDrops++;
      }
    } else if (signal instanceof QueueSignal.Finish finish) {
      PendingRecording recording = recordings.remove(finish.recordingId());
      if (recording == null) {
        throw new ClientException("XTR-JAVA-RECORDING", "finish recording identity is unknown");
      }
      write(recording, finish);
    }
  }

  private void write(PendingRecording pending, QueueSignal.Finish finish) throws ClientException {
    UUID recordingId;
    try {
      recordingId = UUID.fromString(pending.start.recordingId());
    } catch (IllegalArgumentException invalid) {
      throw new ClientException("XTR-JAVA-RECORDING", "recording identity is invalid", invalid);
    }
    byte[] recordingBytes = uuidBytes(recordingId);
    Ack started =
        session.send(
            pending.start.recordingId() + ":started",
            pending.start.recordingId(),
            RecordingStarted.newBuilder()
                .setRecordingId(ByteString.copyFrom(recordingBytes))
                .setRecordingSeq(1)
                .setMethod(pending.start.method())
                .setMatchedRouteTemplate(pending.start.route())
                .setUrlShape(pending.start.route())
                .setStartMonotonicNs(pending.start.monotonicNs())
                .setThreadOrTaskId("request-thread")
                .build());
    requireRecordingAck(started, recordingId, 1);

    long droppedEvents = saturatingAdd(finish.droppedEvents(), pending.writerDrops);
    List<QueueSignal.Event> ordered =
        withGap(
            pending.start.recordingId(),
            pending.events,
            droppedEvents,
            pending.start.monotonicNs(),
            finish.finishedMonotonicNs());
    EventBatch.Builder batch =
        EventBatch.newBuilder().setRecordingId(ByteString.copyFrom(recordingBytes));
    List<String> eventIds = new ArrayList<>(ordered.size());
    long sequence = 1;
    for (QueueSignal.Event event : ordered) {
      sequence = Math.addExact(sequence, 1);
      batch.addEvents(toProto(event, sequence));
      eventIds.add(event.eventId());
    }
    if (ordered.isEmpty()) {
      throw new ClientException("XTR-JAVA-RECORDING", "recording contains no accepted events");
    }
    Ack events =
        session.send(
            pending.start.recordingId() + ":events", pending.start.recordingId(), batch.build());
    requireRecordingAck(events, recordingId, sequence);

    RecordingFinished.Builder terminal =
        RecordingFinished.newBuilder()
            .setRecordingId(ByteString.copyFrom(recordingBytes))
            .setFinalRecordingSeq(sequence)
            .setDurationNs(duration(finish.startedMonotonicNs(), finish.finishedMonotonicNs()))
            .setEventDigest(ByteString.copyFrom(EventDigest.compute(eventIds)));
    if (droppedEvents > 0) terminal.putDropCountsByPriority(1, droppedEvents);
    if (finish.outcome() != null) terminal.setOutcome(outcomeProto(finish.outcome()));
    Ack finished =
        session.send(
            pending.start.recordingId() + ":finished",
            pending.start.recordingId(),
            terminal.build());
    requireRecordingAck(finished, recordingId, sequence);
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
    if (droppedEvents <= 0) return List.copyOf(events);
    List<QueueSignal.Event> result = new ArrayList<>(events.size() + 1);
    boolean inserted = false;
    for (QueueSignal.Event event : events) {
      if (!inserted && event.kind() == BridgeEventKind.RESPONSE) {
        result.add(
            gap(event.recordingId(), event.parentEventId(), event.monotonicNs(), droppedEvents));
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
      result.add(gap(recordingId, parent, monotonicNs, droppedEvents));
    }
    return result;
  }

  private static QueueSignal.Event gap(
      String recordingId, String parent, long monotonicNs, long droppedEvents) {
    String eventId = recordingId + ":gap";
    return new QueueSignal.Event(
        recordingId,
        eventId,
        parent,
        RecordingEventKind.RECORDING_EVENT_KIND_GAP.getNumber(),
        "xtrace.capture.gap",
        monotonicNs,
        (int) Math.min(Integer.MAX_VALUE, Math.max(1, droppedEvents)),
        128);
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
      builder.setGap(
          GapPayload.newBuilder()
              .setReason(handler ? GapReason.GAP_REASON_CORRELATION_LOST : GapReason.GAP_REASON_QUEUE_FULL)
              .setCount(handler ? 1 : Math.max(1, event.detail())));
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
              .setPath(event.detail() == 0 ? "unavailable" : Integer.toString(event.detail())));
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
    private long writerDrops;

    private PendingRecording(QueueSignal.Start start) {
      this.start = start;
    }
  }

  interface Transport {
    Ack send(String messageId, String correlationToken, Message payload) throws ClientException;

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
    public void close() throws ClientException {
      session.close();
    }
  }
}
