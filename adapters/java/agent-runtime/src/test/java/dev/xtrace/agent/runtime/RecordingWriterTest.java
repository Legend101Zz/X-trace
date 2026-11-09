package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import dev.xtrace.agent.runtime.line.ValueSanitizer;
import dev.xtrace.agent.runtime.line.ValueSnapshot;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.InteractionKind;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;
import xtp.agent.v1.Transport.Health;

class RecordingWriterTest {
  @Test
  void insertsSupportedGapBeforeResponseAndPreservesSanitizedIdentity() throws Exception {
    QueueSignal.Event request = event("r:1", "", BridgeEventKind.REQUEST_UPDATE, "http.request POST /orders", 0);
    QueueSignal.Event response =
        event("r:2", "r:1", BridgeEventKind.RESPONSE, "http.response 201", 201);
    List<QueueSignal.Event> events =
        RecordingWriter.withGap(
            "00000000-0000-4000-8000-000000000001",
            List.of(request, response),
            3,
            1,
            2);
    assertEquals(3, events.size());
    assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_GAP.getNumber(), events.get(1).kind());
    var requestProto = RecordingWriter.toProto(events.get(0), 2);
    var responseProto = RecordingWriter.toProto(events.get(2), 4);
    assertEquals("POST", requestProto.getInteraction().getMethod());
    assertEquals("/orders", requestProto.getInteraction().getPath());
    assertEquals(InteractionKind.INTERACTION_KIND_FRAMEWORK, requestProto.getInteraction().getKind());
    assertEquals("201", responseProto.getInteraction().getPath());
  }

  @Test
  void databaseMetadataIsCoarseAndContainsNoSqlIdentity() throws Exception {
    QueueSignal.Event database =
        event("r:5", "r:4", BridgeEventKind.DATABASE_START, "h2.executeUpdate", 0);
    var proto = RecordingWriter.toProto(database, 6);
    assertEquals(InteractionKind.INTERACTION_KIND_DATABASE, proto.getInteraction().getKind());
    assertEquals("h2", proto.getInteraction().getDriver());
    assertEquals("executeUpdate", proto.getInteraction().getMethod());
    assertEquals("", proto.getInteraction().getTable());
    assertEquals("", proto.getInteraction().getSchema());
  }

  @Test
  void durationAndDropArithmeticRemainBoundedAcrossLongWrap() {
    assertEquals(50, RecordingWriter.duration(100, 150));
    assertEquals(11, RecordingWriter.duration(Long.MAX_VALUE - 5, Long.MIN_VALUE + 5));
    assertEquals(1, RecordingWriter.duration(5, 4));
    assertEquals(Long.MAX_VALUE, RecordingWriter.saturatingAdd(Long.MAX_VALUE - 1, 5));
  }

  @Test
  void appendedGapUsesAcceptedMonotonicBoundsWithoutInventingAnEarlierTimestamp() {
    String recordingId = "00000000-0000-4000-8000-000000000001";
    QueueSignal.Event preceding =
        new QueueSignal.Event(
            recordingId, "r:1", "", BridgeEventKind.FRAME_ENTER, "frame", 30, 0, 128);
    List<QueueSignal.Event> afterEvent =
        RecordingWriter.withGap(recordingId, List.of(preceding), 1, 10, 40);
    assertEquals(30, afterEvent.get(1).monotonicNs());
    assertTrue(afterEvent.get(1).monotonicNs() >= preceding.monotonicNs());

    long startAcrossWrap = Long.MAX_VALUE - 1;
    long finishAcrossWrap = Long.MIN_VALUE + 5;
    List<QueueSignal.Event> emptyAcrossWrap =
        RecordingWriter.withGap(recordingId, List.of(), 1, startAcrossWrap, finishAcrossWrap);
    assertEquals(7, RecordingWriter.duration(startAcrossWrap, emptyAcrossWrap.get(0).monotonicNs()));

    List<QueueSignal.Event> invalidBackwardBounds =
        RecordingWriter.withGap(recordingId, List.of(), 1, 20, 10);
    assertEquals(20, invalidBackwardBounds.get(0).monotonicNs());
  }

  @Test
  void gracefulShutdownDrainsAnAdmittedFinishWithoutFalseIncompleteDiagnostic()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    String recordingId = "00000000-0000-4000-8000-000000000001";
    assertTrue(sink.offerStart(recordingId, 1, "POST", "/orders"));
    assertTrue(
        sink.offerEvent(
            recordingId, recordingId + ":1", "", BridgeEventKind.REQUEST_UPDATE, "request", 2, 0));
    assertTrue(sink.offerFinish(recordingId, 1, 3, 201, 0));
    writer.start();
    writer.close();

    assertFalse(writer.incompleteWasReported());
    assertTrue(transport.closed.get());
  }

  @Test
  void gracefulShutdownReportsAnActiveRecordingThatNeverEnqueuesFinish() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(40));
    String recordingId = "00000000-0000-4000-8000-000000000002";
    assertTrue(sink.offerStart(recordingId, 1, "POST", "/orders"));
    assertTrue(
        sink.offerEvent(
            recordingId, recordingId + ":1", "", BridgeEventKind.REQUEST_UPDATE, "request", 2, 0));
    writer.start();
    writer.close();

    assertTrue(writer.incompleteWasReported());
    assertTrue(transport.closed.get());
  }

  @Test
  void rejectedTerminalSignalFailsTheWriterClosedAndReportsIncomplete() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    sink.reportIncomplete(BridgeSink.INCOMPLETE_FINISH_REJECTED);
    writer.start();
    writer.close();

    assertTrue(writer.isStopping());
    assertTrue(writer.incompleteWasReported());
    assertTrue(transport.closed.get());
  }

  @Test
  void rejectedStartSignalReportsIncompleteWithoutStoppingHealthyWriter() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    sink.reportIncomplete(BridgeSink.INCOMPLETE_START_REJECTED);
    writer.start();
    writer.close();

    assertFalse(writer.isStopping());
    assertTrue(writer.incompleteWasReported());
    assertTrue(transport.closed.get());
  }

  private static final String REC = "00000000-0000-4000-8000-0000000000aa";

  @Test
  void unfinishedQuietRequestSendsItsStartAndEventsWithoutWaitingForABatchOrFinish()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    try {
      writer.start();
      assertTrue(sink.offerStart(REC, 1, "GET", "/waiting"));
      RecordingStarted start = transport.await(RecordingStarted.class);
      assertEquals(1, start.getRecordingSeq());
      assertEquals("/waiting", start.getMatchedRouteTemplate());
      // The start itself must be sent even before the first event is enqueued.
      assertTrue(transport.batches.isEmpty());
      assertTrue(sink.offerEvent(REC, "request", "", BridgeEventKind.REQUEST_UPDATE,
          "http.request GET /waiting", 2, 0));
      EventBatch batch = transport.await(EventBatch.class);
      assertEquals(start.getRecordingId(), batch.getRecordingId());
      assertEquals(1, batch.getEventsCount());
      assertEquals("request", batch.getEvents(0).getEventId());
      assertEquals(2, batch.getEvents(0).getRecordingSeq());
      assertTrue(transport.finishes.isEmpty());
      assertEquals(1, sink.activeRecordings(), "streaming must not release admission");
    } finally {
      writer.stopIncomplete();
      writer.close();
    }
  }

  @Test
  void interruptionLeavesAnOpenStreamWithObservedEventsAndNoInventedTerminalEvidence()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(1024, 1024L * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    offerTree(sink, 450);
    try {
      writer.start();
      transport.await(RecordingStarted.class);
      int seen = 0;
      while (seen < 451) seen += transport.await(EventBatch.class).getEventsCount();
      writer.stopIncomplete();
    } finally {
      writer.close();
    }
    assertTrue(transport.closed.get());
    assertTrue(writer.incompleteWasReported());
    assertEquals(1, transport.starts.size());
    assertTrue(transport.finishes.isEmpty(), "recovery must receive no digest or complete outcome");
    var events = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertEquals(451, events.size());
    for (int i = 0; i < events.size(); i++) {
      assertEquals(i + 2, events.get(i).getRecordingSeq());
      assertEquals(i == 0 ? "" : REC + ":0", events.get(i).getParentEventId());
      assertEquals(i == 0 ? REC + ":0" : REC + ":e" + i, events.get(i).getEventId());
      assertFalse(events.get(i).getKind() == RecordingEventKind.RECORDING_EVENT_KIND_RESPONSE);
    }
    assertTrue(transport.batches.size() > 2);
  }

  @Test
  void unfinishedValueHeavyRequestStreamsBatchesBelowTheByteBound() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(128, 4L * 1024 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    writer.capturePolicy("xtrace.focused.v1");
    List<ValueSnapshot> values = new java.util.ArrayList<>();
    for (int i = 0; i < 24; i++) {
      values.add(ValueSanitizer.ofRef("field" + i, ValueSnapshot.NameOrigin.DECLARED,
          "x ".repeat(256), ValueSnapshot.Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }
    var source = new SourceAttestation.SourceInfo("src/Handler.java", 10, 10, new byte[32], 2);
    assertTrue(sink.offerStart(REC, 1, "GET", "/values"));
    for (int i = 0; i < 50; i++) {
      assertTrue(sink.offerLineEvent(REC, "line" + i, "", "handler", i + 2, source, values));
    }
    try {
      writer.start();
      int seen = 0;
      while (seen < 50) seen += transport.await(EventBatch.class).getEventsCount();
      assertTrue(transport.finishes.isEmpty());
      assertTrue(transport.batches.size() >= 3, "byte bound must split fewer than 200 events");
      assertTrue(transport.batches.stream().allMatch(b -> b.getEventsCount() < 50));
      assertTrue(sink.offerFinish(REC, 1, 52, 0, 0));
      writer.close();
    } finally {
      writer.close();
    }
    var all = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertEquals(50, all.size());
    for (int i = 0; i < all.size(); i++) assertEquals(i + 2, all.get(i).getRecordingSeq());
    assertArrayEquals(EventDigest.compute(all.stream().map(e -> e.getEventId()).toList()),
        transport.finishes.get(0).getEventDigest().toByteArray());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void finishAfterStreamingKeepsDigestThrowIdentityAndGapsBeforeTheResponse() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    try {
      assertTrue(sink.offerStart(REC, 1, "GET", "/error"));
      assertTrue(sink.offerThrowEvent(REC, "throw", "", "handler", 2,
          "java.lang.IllegalStateException", "password=private"));
      writer.start();
      transport.await(EventBatch.class);
      assertTrue(sink.offerEvent(REC, "response", "", BridgeEventKind.RESPONSE,
          "http.response 500", 3, 500));
      assertTrue(sink.offerFinishWithOutcome(REC, 1, 4, 500, 7,
          new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
              "java.lang.IllegalStateException", "password=private", "throw")));
      writer.close();
    } finally {
      writer.close();
    }
    var all = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertEquals(List.of("throw", REC + ":gap", "response"),
        all.stream().map(e -> e.getEventId()).toList());
    for (int i = 0; i < all.size(); i++) assertEquals(i + 2, all.get(i).getRecordingSeq());
    assertEquals(7, all.get(1).getGap().getCount());
    assertFalse(all.get(0).getException().getSanitizedMessage().contains("private"));
    var finish = transport.finishes.get(0);
    assertEquals("throw", finish.getOutcome().getThrownFromEventId());
    assertEquals(7, finish.getDropCountsByPriorityOrDefault(1, 0));
    assertEquals(4, finish.getFinalRecordingSeq());
    assertArrayEquals(EventDigest.compute(all.stream().map(e -> e.getEventId()).toList()),
        finish.getEventDigest().toByteArray());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void finishWithAnAlreadyStreamedTailUsesItsSequenceAndDigestWithoutAnEmptyBatch()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    try {
      assertTrue(sink.offerStart(REC, 1, "GET", "/waiting"));
      assertTrue(sink.offerEvent(REC, "request", "", BridgeEventKind.REQUEST_UPDATE,
          "http.request GET /waiting", 2, 0));
      writer.start();
      transport.await(EventBatch.class);
      assertTrue(sink.offerFinish(REC, 1, 3, 0, 0));
      writer.close();
    } finally {
      writer.close();
    }
    assertEquals(1, transport.batches.size());
    assertEquals(1, transport.finishes.size());
    assertEquals(2, transport.finishes.get(0).getFinalRecordingSeq());
    assertArrayEquals(EventDigest.compute(List.of("request")),
        transport.finishes.get(0).getEventDigest().toByteArray());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void streamingReleasesBufferedMemoryBeforeFinishAndKeepsTheGapFrontier() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100), 256);
    try {
      assertTrue(sink.offerStart(REC, 1, "GET", "/waiting"));
      writer.start();
      for (int i = 0; i < 3; i++) {
        assertTrue(sink.offerEvent(REC, "event" + i, "", BridgeEventKind.FRAME_ENTER,
            "handler", 2 + i, 0));
        assertEquals("event" + i, transport.await(EventBatch.class).getEvents(0).getEventId());
      }
      assertTrue(sink.offerFinish(REC, 1, 5, 0, 1));
      writer.close();
    } finally {
      writer.close();
    }
    var all = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertEquals(List.of("event0", "event1", "event2", REC + ":gap"),
        all.stream().map(e -> e.getEventId()).toList());
    assertEquals("event2", all.get(3).getParentEventId());
    assertEquals(4, all.get(3).getMonotonicNs());
    var finish = transport.finishes.get(0);
    assertEquals(1, finish.getDropCountsByPriorityOrDefault(1, 0));
    assertArrayEquals(EventDigest.compute(all.stream().map(e -> e.getEventId()).toList()),
        finish.getEventDigest().toByteArray());
    assertFalse(writer.incompleteWasReported());
  }

  private static void offerTree(RuntimeBridgeSink sink, int frames) {
    assertTrue(sink.offerStart(REC, 1, "GET", "/big"));
    assertTrue(sink.offerEvent(REC, REC + ":0", "", BridgeEventKind.REQUEST_UPDATE,
        "http.request GET /big", 2, 0));
    for (int i = 1; i <= frames; i++) {
      assertTrue(sink.offerEvent(REC, REC + ":e" + i, REC + ":0",
          BridgeEventKind.FRAME_ENTER, "app.F.m" + i, 3, 0));
    }
  }

  @Test
  void aRecordingOfMoreThanTwoHundredFramesKeepsItsTailAndResponse() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(4096, 4L * 1024 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    offerTree(sink, 300);
    for (int i = 300; i >= 1; i--) {
      assertTrue(sink.offerEvent(REC, REC + ":x" + i, REC + ":e" + i,
          BridgeEventKind.FRAME_EXIT, "app.F.m" + i, 4, 0));
    }
    assertTrue(sink.offerEvent(REC, REC + ":resp", REC + ":0", BridgeEventKind.RESPONSE,
        "http.response 200", 5, 200));
    assertTrue(sink.offerFinish(REC, 1, 6, 200, 0));
    writer.start();
    writer.close();
    assertTrue(transport.batches.size() > 1, "602 events must be split into bounded batches");
    int total = transport.batches.stream().mapToInt(EventBatch::getEventsCount).sum();
    assertEquals(2 + 300 + 300, total);
    EventBatch lastBatch = transport.batches.get(transport.batches.size() - 1);
    assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_RESPONSE,
        lastBatch.getEvents(lastBatch.getEventsCount() - 1).getKind());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void perRecordingCapOverflowDropsMiddleEventsButNeverTheClosingEventsAndSaysWhy()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(20_000, 32L * 1024 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(10));
    int enters = RecordingWriter.MAX_EVENTS_PER_RECORDING + 100;
    offerTree(sink, enters);
    for (int i = 1; i <= 10; i++) {
      assertTrue(sink.offerEvent(REC, REC + ":x" + i, REC + ":e" + i,
          BridgeEventKind.FRAME_EXIT, "app.F.m" + i, 4, 0));
    }
    assertTrue(sink.offerEvent(REC, REC + ":resp", REC + ":0", BridgeEventKind.RESPONSE,
        "http.response 500", 5, 500));
    assertTrue(sink.offerFinish(REC, 1, 6, 500, 0));
    writer.start();
    writer.close();
    assertTrue(transport.batches.size() > 1, "a capped recording is still split into bounded batches");
    List<xtp.agent.v1.Recording.RecordingEvent> all = new java.util.ArrayList<>();
    long expectedSeq = 2;
    for (EventBatch b : transport.batches) {
      for (var e : b.getEventsList()) {
        assertEquals(expectedSeq++, e.getRecordingSeq(), "contiguous recording_seq across batches");
        all.add(e);
      }
    }
    var last = all.get(all.size() - 1);
    assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_RESPONSE, last.getKind());
    var gap = all.get(all.size() - 2);
    assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_GAP, gap.getKind());
    assertEquals(xtp.agent.v1.Recording.GapReason.GAP_REASON_THROTTLE, gap.getGap().getReason());
    int kept = RecordingWriter.MAX_EVENTS_PER_RECORDING - RecordingWriter.CLOSING_RESERVE;
    assertEquals(enters + 1 - kept, gap.getGap().getCount());
    assertTrue(gap.getGap().getCount() > 0);
    long exits = all.stream()
        .filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT).count();
    assertEquals(10, exits);
  }

  @Test
  void sinkNeverAdmitsMoreRecordingsThanTheWriterHoldsAndRecoversAfterTheWriteCompletes()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(256, 1024L * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue, 8, 0);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    for (int i = 0; i < 8; i++) {
      String id = String.format("00000000-0000-4000-8000-%012d", i);
      assertTrue(sink.offerStart(id, 1, "GET", "/x"));
      assertTrue(sink.offerEvent(id, id + ":0", "", BridgeEventKind.REQUEST_UPDATE,
          "http.request GET /x", 2, 0));
      assertTrue(sink.offerFinish(id, 1, 3, 200, 0));
    }
    // All eight finishes are queued, none written: a ninth recording must be refused.
    assertFalse(sink.offerStart("00000000-0000-4000-8000-000000000099", 1, "GET", "/x"));
    writer.start();
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (sink.activeRecordings() > 0 && System.nanoTime() < deadline) Thread.onSpinWait();
    assertEquals(0, sink.activeRecordings());
    assertTrue(sink.offerStart("00000000-0000-4000-8000-000000000098", 1, "GET", "/x"));
    assertFalse(writer.isStopping());
    writer.close();
  }

  @Test
  void fiftyConcurrentRequestsTraverseSinkAdmissionAndWriterWithoutLoss() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(1024, 1024L * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    var producers = Executors.newFixedThreadPool(10);
    CountDownLatch submitted = new CountDownLatch(50);
    List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
    try {
      // Delay draining until every start is admitted. This deterministically exercises more
      // than eight unwritten recordings, independently of transport or machine speed.
      for (int i = 0; i < 50; i++) {
        final int index = i;
        futures.add(producers.submit(() -> {
          String id = id(index);
          assertTrue(sink.offerStart(id, 1, index < 30 ? "GET" : "POST",
              index < 30 ? "/owners/{id}" : "/owners/new"));
          assertTrue(sink.offerEvent(id, id + ":0", "", BridgeEventKind.REQUEST_UPDATE,
              "request", 2, 0));
          submitted.countDown();
        }));
      }
      assertTrue(submitted.await(5, TimeUnit.SECONDS));
      for (var future : futures) future.get(5, TimeUnit.SECONDS);
      assertEquals(50, sink.activeRecordings());
      futures.clear();
      for (int i = 0; i < 50; i++) {
        final int index = i;
        futures.add(producers.submit(() -> {
          assertTrue(sink.offerFinish(id(index), 1, 3, 200, 0));
        }));
      }
      for (var future : futures) future.get(5, TimeUnit.SECONDS);
      writer.start();
      writer.close();
    } finally {
      producers.shutdownNow();
      writer.close();
    }
    assertEquals(50, transport.starts.size());
    assertEquals(50, transport.finishes.size());
    assertEquals(50, transport.starts.stream().map(RecordingStarted::getRecordingId).distinct().count());
    assertEquals(50, transport.batches.stream().mapToInt(EventBatch::getEventsCount).sum());
    assertTrue(transport.finishes.stream().allMatch(f -> f.getDropCountsByPriorityCount() == 0));
    assertEquals(0, sink.activeRecordings());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void forcedAdmissionDropsKeepEachIdentityRouteAndObservedTerminalWithADurableGap()
      throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue, 1, 2);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    assertTrue(sink.offerStart(id(0), 10, "GET", "/first"));
    assertTrue(sink.offerEvent(id(0), id(0) + ":0", "", BridgeEventKind.REQUEST_UPDATE,
        "request", 11, 0));
    for (int i = 1; i <= 2; i++) {
      assertTrue(sink.offerStart(id(i), 10, "POST", "/owners/new"));
      assertFalse(sink.offerEvent(id(i), id(i) + ":0", "", BridgeEventKind.REQUEST_UPDATE,
          "request", 11, 0));
      assertTrue(sink.offerFinishWithOutcome(id(i), 10, 20, 302, i,
          new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 302, null, null, null)));
    }
    assertTrue(sink.offerFinish(id(0), 10, 20, 200, 0));
    writer.start();
    writer.close();
    assertEquals(3, transport.starts.size());
    assertEquals(3, transport.finishes.size());
    for (int i = 1; i <= 2; i++) {
      final String recordingId = id(i);
      var start = transport.starts.stream()
          .filter(s -> FakeTransport.uuid(s.getRecordingId().toByteArray()).equals(recordingId))
          .findFirst().orElseThrow();
      assertEquals("POST", start.getMethod());
      assertEquals("/owners/new", start.getMatchedRouteTemplate());
      var batch = transport.batches.stream()
          .filter(b -> b.getRecordingId().equals(start.getRecordingId())).findFirst().orElseThrow();
      assertEquals(1, batch.getEventsCount());
      var gap = batch.getEvents(0);
      assertEquals(RecordingWriter.ADMISSION_GAP_SYMBOL, gap.getSymbol());
      assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_GAP, gap.getKind());
      assertEquals(xtp.agent.v1.Recording.GapReason.GAP_REASON_THROTTLE, gap.getGap().getReason());
      assertEquals(i, gap.getGap().getCount());
      assertEquals("", gap.getParentEventId());
      var finish = transport.finishes.stream()
          .filter(f -> f.getRecordingId().equals(start.getRecordingId())).findFirst().orElseThrow();
      assertEquals(i, finish.getDropCountsByPriorityOrDefault(1, 0));
      assertEquals(302, finish.getOutcome().getHttpStatus());
      assertEquals(10, finish.getDurationNs());
      assertArrayEquals(EventDigest.compute(List.of(gap.getEventId())), finish.getEventDigest().toByteArray());
    }
    assertFalse(writer.incompleteWasReported());
    assertEquals(0, sink.activeRecordings());
  }

  @Test
  void writerMemoryPressureIsCountedAndCapacityIsReusedAfterDraining() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(128, 65536);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5), 256);
    for (int i = 0; i < 3; i++) {
      assertTrue(sink.offerStart(id(i), 1, "GET", "/x"));
      for (int e = 0; e < 3; e++) {
        assertTrue(sink.offerEvent(id(i), id(i) + ":" + e, "", BridgeEventKind.REQUEST_UPDATE,
            "request", 2, 0));
      }
      // Recording one must share the global budget with zero. Once both are drained, two
      // must be able to retain an event again, proving the budget is released after writing.
      if (i == 1) {
        assertTrue(sink.offerFinish(id(0), 1, 3, 200, 0));
        assertTrue(sink.offerFinish(id(1), 1, 3, 200, 0));
      } else if (i == 2) {
        assertTrue(sink.offerFinish(id(2), 1, 3, 200, 0));
      }
    }
    writer.start();
    writer.close();
    assertEquals(3, transport.finishes.size());
    for (var batch : List.of(transport.batches.get(0), transport.batches.get(2))) {
      assertEquals(2, batch.getEventsCount());
      assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_REQUEST_UPDATE, batch.getEvents(0).getKind());
      assertEquals(2, batch.getEvents(1).getGap().getCount());
      assertEquals(RecordingWriter.MEMORY_GAP_SYMBOL, batch.getEvents(1).getSymbol());
    }
    var middle = transport.batches.get(1);
    assertEquals(1, middle.getEventsCount());
    assertEquals(3, middle.getEvents(0).getGap().getCount());
    assertEquals(RecordingWriter.MEMORY_GAP_SYMBOL, middle.getEvents(0).getSymbol());
    assertEquals(2, transport.finishes.get(0).getDropCountsByPriorityOrDefault(1, 0));
    assertEquals(3, transport.finishes.get(1).getDropCountsByPriorityOrDefault(1, 0));
    assertEquals(2, transport.finishes.get(2).getDropCountsByPriorityOrDefault(1, 0));
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void focusedCaptureUsesItsOwnCapAndReservesSpaceForEveryGap() throws Exception {
    int cap = RecordingWriter.MAX_FOCUSED_EVENTS_PER_RECORDING;
    BoundedEventQueue queue = new BoundedEventQueue(cap + 128, 64L * 1024 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    writer.capturePolicy("xtrace.focused.v1");
    writer.untransformedCount(() -> 1);
    assertTrue(sink.offerStart(id(0), 1, "GET", "/focused"));
    // Closing events can fill the closing reserve, but must leave space for generated gaps.
    for (int i = 0; i < cap + 10; i++) {
      assertTrue(sink.offerEvent(id(0), "e" + i, "", BridgeEventKind.FRAME_EXIT, "exit", 2, 0));
    }
    assertTrue(sink.offerFinish(id(0), 1, 3, 200, 1));
    writer.start();
    writer.close();
    var all = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    long exits = all.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT).count();
    assertEquals(cap - 4, exits);
    assertEquals(cap - 1, all.size());
    assertEquals(1, all.stream().filter(e -> e.getSymbol().equals(RecordingWriter.CAP_GAP_SYMBOL)).count());
    assertEquals(14, all.stream().filter(e -> e.getSymbol().equals(RecordingWriter.CAP_GAP_SYMBOL))
        .findFirst().orElseThrow().getGap().getCount());
    assertEquals(15, transport.finishes.get(0).getDropCountsByPriorityOrDefault(1, 0));
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void metadataOnlyExceptionsDoNotReferToDiscardedThrowEvents() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue, 1, 1);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    assertTrue(sink.offerStart(id(0), 1, "GET", "/first"));
    assertTrue(sink.offerStart(id(1), 1, "GET", "/error"));
    assertTrue(sink.offerFinishWithOutcome(id(1), 1, 3, 0, 0,
        new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
            "java.lang.IllegalStateException", "password=private", "discarded:throw")));
    assertTrue(sink.offerFinish(id(0), 1, 3, 200, 1));
    writer.start();
    writer.close();
    var finish = transport.finishes.get(0);
    assertEquals(xtp.agent.v1.Recording.OutcomeKind.OUTCOME_KIND_EXCEPTION_PROPAGATED,
        finish.getOutcome().getKind());
    assertEquals("", finish.getOutcome().getThrownFromEventId());
    assertFalse(finish.getOutcome().getException().getSanitizedMessage().contains("private"));
    assertEquals(1, finish.getDropCountsByPriorityOrDefault(1, 0));
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void exhaustionOfBothAdmissionBoundsCountsEveryRejectedStartInHealth() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue, 1, 1);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5));
    assertTrue(sink.offerStart(id(0), 1, "GET", "/first"));
    assertTrue(sink.offerStart(id(1), 1, "GET", "/metadata"));
    for (int i = 2; i < 12; i++) assertFalse(sink.offerStart(id(i), 1, "GET", "/rejected"));
    assertEquals(2, sink.activeRecordings());
    assertEquals(10, sink.rejectedStarts());
    assertTrue(sink.offerFinish(id(0), 1, 3, 200, 1));
    assertTrue(sink.offerFinish(id(1), 1, 3, 200, 1));
    writer.start();
    writer.close();
    assertEquals(2, transport.finishes.size());
    assertEquals("recording-starts-rejected=10", transport.health.get(0).getStatus());
    assertTrue(writer.incompleteWasReported());
    assertFalse(writer.isStopping());
  }

  @Test
  void memoryShedThrowHasNoDanglingOutcomeLink() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    FakeTransport transport = new FakeTransport();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(5), 1);
    assertTrue(sink.offerStart(id(0), 1, "GET", "/error"));
    assertTrue(sink.offerThrowEvent(id(0), "throw", "", "handler", 2,
        "java.lang.IllegalStateException", "password=private"));
    assertTrue(sink.offerFinishWithOutcome(id(0), 1, 3, 0, 0,
        new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
            "java.lang.IllegalStateException", "password=private", "throw")));
    writer.start();
    writer.close();
    assertEquals(1, transport.finishes.size());
    assertEquals("", transport.finishes.get(0).getOutcome().getThrownFromEventId());
    assertEquals(1, transport.finishes.get(0).getDropCountsByPriorityOrDefault(1, 0));
    assertEquals(1, transport.batches.get(0).getEventsCount());
    assertEquals(RecordingWriter.MEMORY_GAP_SYMBOL, transport.batches.get(0).getEvents(0).getSymbol());
    assertFalse(writer.incompleteWasReported());
  }

  @Test
  void gapCountsDoNotTruncateAtTheSignedIntegerBoundary() throws Exception {
    long drops = (long) Integer.MAX_VALUE + 7;
    var gap = RecordingWriter.withGap(id(0), List.of(), drops, 1, 2).get(0);
    assertEquals(drops, RecordingWriter.toProto(gap, 2).getGap().getCount());
  }

  private static String id(int index) {
    return String.format("00000000-0000-4000-8000-%012d", index);
  }

  private static QueueSignal.Event event(
      String id, String parent, int kind, String symbol, int detail) {
    return new QueueSignal.Event(
        "00000000-0000-4000-8000-000000000001",
        id,
        parent,
        kind,
        symbol,
        1,
        detail,
        128);
  }

  private static final class FakeTransport implements RecordingWriter.Transport {
    private final AtomicBoolean closed = new AtomicBoolean();
    private final List<EventBatch> batches = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final List<RecordingStarted> starts = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final List<RecordingFinished> finishes = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final List<Health> health = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final LinkedBlockingQueue<Message> sent = new LinkedBlockingQueue<>();
    private final java.util.Set<String> messageIds = new java.util.HashSet<>();

    private <T extends Message> T await(Class<T> type) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      Message payload;
      while ((payload = sent.poll(Math.max(0, deadline - System.nanoTime()),
          TimeUnit.NANOSECONDS)) != null) {
        if (type.isInstance(payload)) return type.cast(payload);
      }
      throw new AssertionError("writer did not send " + type.getSimpleName());
    }

    @Override
    public Ack send(String messageId, String correlationToken, Message payload)
        throws ClientException {
      assertTrue(messageIds.add(messageId), "each streamed batch needs a distinct message identity");
      Ack.Builder ack =
          Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(1);
      if (payload instanceof RecordingStarted started) {
        starts.add(started);
        ack.putHighestContiguousRecordingSeq(uuid(started.getRecordingId().toByteArray()), 1);
      } else if (payload instanceof EventBatch batch) {
        // Daemon-advertised limits: 256 events per batch, 1 MiB per envelope.
        assertTrue(batch.getEventsCount() <= 256, "batch event bound");
        assertTrue(batch.getSerializedSize() <= 1024 * 1024 - 4096, "batch byte bound");
        assertTrue(batch.getEventsCount() <= RecordingWriter.MAX_BATCH_EVENTS);
        assertTrue(batch.getSerializedSize() <= RecordingWriter.MAX_BATCH_BYTES);
        batches.add(batch);
        long sequence = batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq();
        ack.putHighestContiguousRecordingSeq(uuid(batch.getRecordingId().toByteArray()), sequence);
      } else if (payload instanceof RecordingFinished finished) {
        finishes.add(finished);
        ack.putHighestContiguousRecordingSeq(
            uuid(finished.getRecordingId().toByteArray()), finished.getFinalRecordingSeq());
      } else if (payload instanceof Health status) {
        health.add(status);
      } else if (!(payload instanceof CapabilitySet)) {
        throw new ClientException("XTR-JAVA-TEST", "unexpected payload");
      }
      sent.add(payload);
      return ack.build();
    }

    @Override
    public void close() {
      closed.set(true);
    }

    private static String uuid(byte[] bytes) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes);
      return new UUID(buffer.getLong(), buffer.getLong()).toString();
    }
  }
}
