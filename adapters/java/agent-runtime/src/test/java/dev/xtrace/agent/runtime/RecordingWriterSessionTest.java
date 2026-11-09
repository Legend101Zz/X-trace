package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.adapter.Framing;
import dev.xtrace.adapter.XtpSession;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Handshake.DaemonHello;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;
import xtp.agent.v1.Transport.Health;

@ResourceLock(Resources.SYSTEM_ERR)
final class RecordingWriterSessionTest {
  private static final String FIRST = "00000000-0000-4000-8000-000000000001";
  private static final String LATER = "00000000-0000-4000-8000-000000000002";
  private static final String COMPANION = "00000000-0000-4000-8000-000000000003";

  @Test
  void rejectedStartHealthCrossesTheRealSessionAndLaterRecordingsComplete() throws Exception {
    exerciseWriter(false);
  }

  @Test
  void unsupportedHealthIsReportedOnceAndUnrelatedRecordingsStillComplete() throws Exception {
    ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
    PrintStream previous = System.err;
    try (PrintStream capture = new PrintStream(diagnostics, true, StandardCharsets.UTF_8)) {
      System.setErr(capture);
      exerciseWriter(true);
    } finally {
      System.setErr(previous);
    }
    String output = diagnostics.toString(StandardCharsets.UTF_8);
    assertTrue(output.contains("\"code\":\"XTR-JAVA-ENVELOPE\""));
    assertTrue(output.contains("health payload was not sent; recording capture continues"));
    assertEquals(1, output.lines().filter(line -> line.contains("XTR-JAVA-ENVELOPE")).count());
    assertFalse(output.contains("private-canary"));
  }

  @Test
  void oversizedBatchSplitsIntoTwoIndividuallyAcknowledgedOrderedFrames() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    AcknowledgingSocket peer = new AcknowledgingSocket(512);
    RecordingWriter writer = new RecordingWriter(peer.session(), queue, sink);
    try {
      assertTrue(sink.offerStart(FIRST, 1, "GET", "/split"));
      for (int i = 0; i < 2; i++) {
        assertTrue(sink.offerEvent(FIRST, "event-" + i, "", BridgeEventKind.FRAME_ENTER,
            "m".repeat(200), 2 + i, 0));
      }
      assertTrue(sink.offerFinish(FIRST, 1, 4, 0, 0));
      writer.start();
      peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED);
      assertFalse(peer.closed, "the session stays open after both batch ACKs and Finish");
    } finally {
      writer.close();
    }
    assertFalse(writer.isStopping());
    assertFalse(writer.incompleteWasReported());
    var batches = peer.frames.stream().filter(AgentEnvelope::hasEventBatch).toList();
    assertEquals(2, batches.size());
    assertEquals(List.of(FIRST + ":events", FIRST + ":events:1"),
        batches.stream().map(AgentEnvelope::getMessageId).toList());
    assertEquals(List.of(3L, 4L), batches.stream().map(AgentEnvelope::getSessionSeq).toList());
    assertEquals(List.of("event-0", "event-1"), batches.stream()
        .flatMap(frame -> frame.getEventBatch().getEventsList().stream())
        .map(event -> event.getEventId()).toList());
    assertEquals(List.of(2L, 3L), batches.stream()
        .flatMap(frame -> frame.getEventBatch().getEventsList().stream())
        .map(event -> event.getRecordingSeq()).toList());
    // The payload alone fits: envelope overhead is what requires splitting it.
    EventBatch combined = batches.get(0).getEventBatch().toBuilder()
        .addAllEvents(batches.get(1).getEventBatch().getEventsList()).build();
    assertTrue(combined.getSerializedSize() <= 512);
    assertTrue(batches.get(0).toBuilder().setEventBatch(combined).build().getSerializedSize() > 512);
    var finish = peer.frames.stream().filter(AgentEnvelope::hasRecordingFinished)
        .findFirst().orElseThrow().getRecordingFinished();
    assertEquals(3, finish.getFinalRecordingSeq());
    assertEquals(0, finish.getDropCountsByPriorityCount());
    assertArrayEquals(EventDigest.compute(List.of("event-0", "event-1")),
        finish.getEventDigest().toByteArray());
  }

  @Test
  void oversizedSingleEventBecomesAnExplicitGapWhileAnotherRecordingCompletes() throws Exception {
    exerciseOversizedEvent(false);
  }

  @Test
  void oversizedThrowBecomesAGapAndTheOutcomeDoesNotClaimAnObservedThrow() throws Exception {
    exerciseOversizedEvent(true);
  }

  @Test
  void oversizedStartRecordsItsReductionAndKeepsActiveAndSubsequentRecordingsUsable()
      throws Exception {
    exerciseOversizedLifecycle(true, false);
  }

  @Test
  void oversizedFinishRecordsItsReductionAndKeepsActiveAndSubsequentRecordingsUsable()
      throws Exception {
    exerciseOversizedLifecycle(false, false);
  }

  @Test
  void startIdentityThatCannotFitAbandonsOnlyThatRecording() throws Exception {
    exerciseOversizedLifecycle(true, true);
  }

  @Test
  void finishIdentityThatCannotFitAbandonsOnlyThatRecording() throws Exception {
    exerciseOversizedLifecycle(false, true);
  }

  @Test
  void aStartReductionMarkerThatCannotFitLeavesOnlyThatRecordingIncomplete() throws Exception {
    exerciseOversizedLifecycle(true, false, 256);
  }

  @Test
  void aFinishReductionMarkerThatCannotFitLeavesOnlyThatRecordingIncomplete() throws Exception {
    exerciseOversizedLifecycle(false, false, 256);
  }

  private static void exerciseOversizedLifecycle(boolean started, boolean identityTooLarge)
      throws Exception {
    exerciseOversizedLifecycle(started, identityTooLarge, identityTooLarge ? 256 : 512);
  }

  private static void exerciseOversizedLifecycle(
      boolean started, boolean identityTooLarge, int frameLimit)
      throws Exception {
    boolean incomplete = identityTooLarge || frameLimit == 256;
    boolean startAccepted = !(started && identityTooLarge);
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    AcknowledgingSocket peer = new AcknowledgingSocket(frameLimit);
    RecordingWriter writer = new RecordingWriter(peer.session(), queue, sink);
    ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
    PrintStream previous = System.err;
    String route = started ? "/private-canary/" + "r".repeat(240) : "/first";
    String method = started && identityTooLarge ? "M".repeat(256) : "GET";
    String exceptionType = identityTooLarge ? "E".repeat(256) : "java.lang.IllegalStateException";
    try (PrintStream capture = new PrintStream(diagnostics, true, StandardCharsets.UTF_8)) {
      System.setErr(capture);
      try {
        assertTrue(sink.offerStart(COMPANION, 1, "GET", "/companion"));
        writer.start();
        peer.await(AgentEnvelope.PayloadCase.RECORDING_STARTED);
        assertTrue(sink.offerStart(FIRST, 2, method, route));
        assertTrue(sink.offerEvent(FIRST, "first-response", "", BridgeEventKind.RESPONSE,
            "http.response 500", 3, 500));
        BridgeSink.Outcome outcome = started
            ? new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 500, "", "", "")
            : new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
                exceptionType, "private-canary " + "sanitized ".repeat(50), "");
        assertTrue(sink.offerFinishWithOutcome(FIRST, 2, 4, 500, 0, outcome));
        assertTrue(sink.offerEvent(COMPANION, "companion-response", "", BridgeEventKind.RESPONSE,
            "http.response 200", 5, 200));
        assertTrue(sink.offerFinishWithOutcome(COMPANION, 1, 6, 200, 0,
            new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 200, "", "", "")));
        if (startAccepted) {
          assertEquals(FIRST, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
              .getRecordingFinished().getRecordingId()));
        }
        assertEquals(COMPANION, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
            .getRecordingFinished().getRecordingId()));
        assertFalse(peer.closed, "lifecycle size rejection must leave an active companion usable");
        assertFalse(writer.isStopping());
        // Admission and completion after the oversized lifecycle prove this is still a live session.
        assertTrue(sink.offerStart(LATER, 7, "GET", "/later"));
        assertTrue(sink.offerEvent(LATER, "later-response", "", BridgeEventKind.RESPONSE,
            "http.response 201", 8, 201));
        assertTrue(sink.offerFinishWithOutcome(LATER, 7, 9, 201, 0,
            new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 201, "", "", "")));
        assertEquals(LATER, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
            .getRecordingFinished().getRecordingId()));
        assertFalse(peer.closed);
      } finally {
        writer.close();
      }
    } finally {
      System.setErr(previous);
    }
    assertFalse(writer.isStopping());
    assertEquals(incomplete, writer.incompleteWasReported());
    assertEquals(0, sink.activeRecordings(), "abandoned recordings must release their admission");
    var finishes = peer.frames.stream().filter(AgentEnvelope::hasRecordingFinished)
        .map(AgentEnvelope::getRecordingFinished).toList();
    assertEquals(startAccepted ? List.of(FIRST, COMPANION, LATER) : List.of(COMPANION, LATER),
        finishes.stream().map(finish -> uuid(finish.getRecordingId())).toList());
    assertEquals(startAccepted, peer.frames.stream().filter(AgentEnvelope::hasRecordingStarted)
        .anyMatch(frame -> uuid(frame.getRecordingStarted().getRecordingId()).equals(FIRST)),
        "an unsendable start never reserves daemon capacity");
    if (incomplete && startAccepted) {
      assertMinimalFinish(finishes.get(0), started ? 1 : 2);
    }
    for (var finish : finishes) {
      String id = uuid(finish.getRecordingId());
      if (id.equals(FIRST)) continue;
      assertEquals(2, finish.getFinalRecordingSeq());
      assertEquals(0, finish.getDropCountsByPriorityCount());
      assertEquals(id.equals(COMPANION) ? 200 : 201, finish.getOutcome().getHttpStatus());
      assertArrayEquals(EventDigest.compute(List.of(id.equals(COMPANION)
          ? "companion-response" : "later-response")), finish.getEventDigest().toByteArray());
    }
    String output = diagnostics.toString(StandardCharsets.UTF_8);
    assertFalse(output.contains("private-canary"));
    if (incomplete) {
      assertEquals(1, output.lines().count());
      assertTrue(output.contains("\"code\":\"XTR-JAVA-CAPTURE-INCOMPLETE\""));
      assertTrue(output.contains("\"recordingId\":\"" + FIRST + "\""));
      assertTrue(output.contains(identityTooLarge
          ? (started ? "RecordingStarted" : "RecordingFinished") + " identity exceeds the frame limit"
          : "frame-limit " + (started ? "started" : "finished") + " marker could not be sent"));
      assertTrue(peer.frames.stream().filter(AgentEnvelope::hasEventBatch)
          .noneMatch(frame -> started && uuid(frame.getEventBatch().getRecordingId()).equals(FIRST)),
          "an unsent start must not be followed by orphaned events");
    } else {
      assertEquals("", output);
      var finish = finishes.get(0);
      assertEquals(3, finish.getFinalRecordingSeq());
      assertEquals(1, finish.getDropCountsByPriorityOrDefault(1, 0));
      var events = peer.frames.stream().filter(AgentEnvelope::hasEventBatch)
          .filter(frame -> uuid(frame.getEventBatch().getRecordingId()).equals(FIRST))
          .flatMap(frame -> frame.getEventBatch().getEventsList().stream()).toList();
      assertEquals(2, events.size());
      var gap = events.get(started ? 0 : 1);
      assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_GAP, gap.getKind());
      assertEquals(started ? RecordingWriter.START_FRAME_GAP_SYMBOL
          : RecordingWriter.FINISH_FRAME_GAP_SYMBOL, gap.getSymbol());
      assertEquals(GapReason.GAP_REASON_THROTTLE, gap.getGap().getReason());
      assertEquals(1, gap.getGap().getCount());
      assertEquals(started ? 2 : 4, gap.getMonotonicNs());
      assertEquals(started ? 2 : 3, gap.getRecordingSeq());
      assertArrayEquals(EventDigest.compute(events.stream().map(event -> event.getEventId()).toList()),
          finish.getEventDigest().toByteArray());
      if (started) {
        var start = peer.frames.stream().filter(AgentEnvelope::hasRecordingStarted)
            .map(AgentEnvelope::getRecordingStarted)
            .filter(value -> uuid(value.getRecordingId()).equals(FIRST)).findFirst().orElseThrow();
        assertEquals(route, start.getMatchedRouteTemplate());
        assertEquals("", start.getUrlShape());
        assertEquals(method, start.getMethod());
        assertEquals(500, finish.getOutcome().getHttpStatus());
      } else {
        assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, finish.getOutcome().getKindValue());
        assertEquals(exceptionType, finish.getOutcome().getException().getExceptionType());
        assertEquals("", finish.getOutcome().getException().getSanitizedMessage());
      }
    }
  }

  private static void exerciseOversizedEvent(boolean thrown) throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    AcknowledgingSocket peer = new AcknowledgingSocket(512);
    RecordingWriter writer = new RecordingWriter(peer.session(), queue, sink);
    String message = "sanitized ".repeat(20);
    try {
      assertTrue(sink.offerStart(FIRST, 1, "GET", "/oversized"));
      if (!thrown) assertTrue(sink.offerStart(LATER, 2, "GET", "/later"));
      if (thrown) {
        assertTrue(sink.offerThrowEvent(FIRST, "oversized", "", "m".repeat(256), 3,
            "java.lang.IllegalStateException", message));
      } else {
        assertTrue(sink.offerSourceEvent(FIRST, "oversized", "", BridgeEventKind.FRAME_ENTER,
            "m".repeat(256), 3, 0, "src/" + "p".repeat(240) + ".java",
            1, 2, new byte[32], 1));
      }
      writer.start();
      // Flush before Finish to cover drop accounting across streamed batches.
      AgentEnvelope gapFrame = peer.await(AgentEnvelope.PayloadCase.EVENT_BATCH);
      var gap = gapFrame.getEventBatch().getEvents(0);
      assertEquals(RecordingEventKind.RECORDING_EVENT_KIND_GAP, gap.getKind());
      assertEquals(RecordingWriter.FRAME_GAP_SYMBOL, gap.getSymbol());
      assertEquals(GapReason.GAP_REASON_THROTTLE, gap.getGap().getReason());
      assertEquals(1, gap.getGap().getCount());
      assertEquals("oversized", gap.getEventId());
      assertEquals(2, gap.getRecordingSeq());
      assertEquals(3, gap.getMonotonicNs());
      assertFalse(gap.hasSource());
      assertFalse(gap.hasException());
      assertEquals(0, gap.getBindingsCount());
      assertFalse(peer.closed);
      assertTrue(sink.offerEvent(FIRST, "first-response", "oversized", BridgeEventKind.RESPONSE,
          "http.response 500", 4, 500));
      BridgeSink.Outcome outcome = thrown
          ? new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
              "java.lang.IllegalStateException", message, "oversized")
          : new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 500, "", "", "");
      assertTrue(sink.offerFinishWithOutcome(FIRST, 1, 5, 500, 0, outcome));
      peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED);
      assertFalse(peer.closed);
      if (thrown) assertTrue(sink.offerStart(LATER, 2, "GET", "/later"));
      assertTrue(sink.offerEvent(LATER, "later-response", "", BridgeEventKind.RESPONSE,
          "http.response 201", 6, 201));
      assertTrue(sink.offerFinishWithOutcome(LATER, 2, 7, 201, 0,
          new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 201, "", "", "")));
      peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED);
      assertFalse(peer.closed, "an oversized event must not close the session");
    } finally {
      writer.close();
    }
    assertFalse(writer.isStopping());
    assertFalse(writer.incompleteWasReported(), "only the affected recording has a gap");
    assertEquals(0, sink.activeRecordings());
    var finishes = peer.frames.stream().filter(AgentEnvelope::hasRecordingFinished)
        .map(AgentEnvelope::getRecordingFinished).toList();
    assertEquals(List.of(FIRST, LATER), finishes.stream()
        .map(finish -> uuid(finish.getRecordingId())).toList());
    assertEquals(1, finishes.get(0).getDropCountsByPriorityOrDefault(1, 0));
    assertEquals(3, finishes.get(0).getFinalRecordingSeq());
    assertEquals("", finishes.get(0).getOutcome().getThrownFromEventId());
    assertArrayEquals(EventDigest.compute(List.of("oversized", "first-response")),
        finishes.get(0).getEventDigest().toByteArray());
    assertEquals(0, finishes.get(1).getDropCountsByPriorityCount());
    assertEquals(2, finishes.get(1).getFinalRecordingSeq());
    assertEquals(201, finishes.get(1).getOutcome().getHttpStatus());
    assertArrayEquals(EventDigest.compute(List.of("later-response")),
        finishes.get(1).getEventDigest().toByteArray());
    assertEquals(1, peer.frames.stream().filter(AgentEnvelope::hasEventBatch)
        .flatMap(frame -> frame.getEventBatch().getEventsList().stream())
        .filter(event -> event.hasGap()).count());
  }

  @Test
  void aLimitTooSmallForTheGapFinishesOnlyThatRecordingAsIncompleteAndReportsWhy() throws Exception {
    ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
    PrintStream previous = System.err;
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    AcknowledgingSocket peer = new AcknowledgingSocket(256);
    RecordingWriter writer = new RecordingWriter(peer.session(), queue, sink);
    try (PrintStream capture = new PrintStream(diagnostics, true, StandardCharsets.UTF_8)) {
      System.setErr(capture);
      try {
        assertTrue(sink.offerStart(FIRST, 1, "GET", "/first"));
        assertTrue(sink.offerEvent(FIRST, "e".repeat(256), "p".repeat(256),
            BridgeEventKind.FRAME_ENTER, "private-canary", 2, 0));
        assertTrue(sink.offerFinish(FIRST, 1, 3, 0, 0));
        assertTrue(sink.offerStart(LATER, 4, "GET", "/later"));
        assertTrue(sink.offerEvent(LATER, "later-response", "", BridgeEventKind.RESPONSE,
            "http.response 201", 5, 201));
        assertTrue(sink.offerFinish(LATER, 4, 6, 201, 0));
        writer.start();
        assertEquals(FIRST, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
            .getRecordingFinished().getRecordingId()));
        peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED);
        assertFalse(peer.closed);
      } finally {
        writer.close();
      }
    } finally {
      System.setErr(previous);
    }
    assertFalse(writer.isStopping());
    assertTrue(writer.incompleteWasReported());
    assertEquals(0, sink.activeRecordings());
    var finishes = peer.frames.stream().filter(AgentEnvelope::hasRecordingFinished).toList();
    assertEquals(2, finishes.size());
    assertMinimalFinish(finishes.get(0).getRecordingFinished(), 1);
    assertEquals(LATER, uuid(finishes.get(1).getRecordingFinished().getRecordingId()));
    assertEquals(0, finishes.get(1).getRecordingFinished().getDropCountsByPriorityCount());
    String output = diagnostics.toString(StandardCharsets.UTF_8);
    assertTrue(output.contains("frame-limit gap could not be sent"));
    assertTrue(output.contains("\"recordingId\":\"" + FIRST + "\""));
    assertEquals(1, output.lines().count());
    assertFalse(output.contains("private-canary"));
  }

  private static void assertMinimalFinish(RecordingFinished finish, long sequence) {
    assertEquals(RecordingFinished.newBuilder()
        .setRecordingId(finish.getRecordingId())
        .setFinalRecordingSeq(sequence)
        .putDropCountsByPriority(1, 1)
        .build(), finish, "an abandoned recording sends only identity, watermark and loss marker");
  }

  @Test
  void repeatedAbandonmentReleasesPeerCapacityWhileACompanionRemainsActive() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    AcknowledgingSocket peer = new AcknowledgingSocket(256, 2);
    RecordingWriter writer = new RecordingWriter(peer.session(), queue, sink);
    ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
    PrintStream previous = System.err;
    try (PrintStream capture = new PrintStream(diagnostics, true, StandardCharsets.UTF_8)) {
      System.setErr(capture);
      try {
        assertTrue(sink.offerStart(COMPANION, 1, "GET", "/companion"));
        writer.start();
        peer.await(AgentEnvelope.PayloadCase.RECORDING_STARTED);
        // Cross the real validator's 2,000,000 / 16,384 digest commitment boundary too.
        for (int i = 0; i < 130; i++) {
          String id = new UUID(0, 100 + i).toString();
          boolean reducedStart = i % 4 == 0;
          boolean unsendableEvent = i % 4 == 3;
          assertTrue(sink.offerStart(id, 2, "GET", reducedStart
              ? "/private-canary/" + "r".repeat(240) : "/first"));
          assertTrue(sink.offerEvent(id, unsendableEvent ? "e".repeat(256) : "response",
              "", unsendableEvent ? BridgeEventKind.FRAME_ENTER : BridgeEventKind.RESPONSE,
              "http.response 500", 3, 500));
          assertTrue(sink.offerFinishWithOutcome(id, 2, 4, 500, 0,
              new BridgeSink.Outcome(BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0,
                  i % 4 == 2 ? "E".repeat(256) : "java.lang.IllegalStateException",
                  "private-canary " + "sanitized ".repeat(50), "")));
          var terminal = peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED);
          var finish = terminal.getRecordingFinished();
          assertEquals(id, uuid(finish.getRecordingId()));
          assertMinimalFinish(finish, reducedStart || unsendableEvent ? 1 : 2);
          // Compare the actual terminal envelope at the widest sequences with a start that
          // contains only identity. Optional start fields can only increase this allowance.
          var widestTerminal = terminal.toBuilder().setSessionSeq(Long.MAX_VALUE)
              .setRecordingFinished(finish.toBuilder()
                  .setFinalRecordingSeq(RecordingWriter.MAX_FOCUSED_EVENTS_PER_RECORDING + 1))
              .build();
          var smallestStart = terminal.toBuilder().setSessionSeq(Long.MAX_VALUE)
              .setMessageId(id + ":started")
              .setRecordingStarted(RecordingStarted.newBuilder()
                  .setRecordingId(finish.getRecordingId()).setRecordingSeq(1))
              .build();
          assertTrue(widestTerminal.getSerializedSize() <= smallestStart.getSerializedSize(),
              "the minimal finish must fit whenever the start identity fit");
          assertFalse(peer.closed);
          assertFalse(writer.isStopping());
        }
        assertTrue(sink.offerStart(LATER, 5, "GET", "/later"));
        assertTrue(sink.offerEvent(LATER, "later-response", "", BridgeEventKind.RESPONSE,
            "http.response 201", 6, 201));
        assertTrue(sink.offerFinish(LATER, 5, 7, 201, 0));
        assertEquals(LATER, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
            .getRecordingFinished().getRecordingId()));
        assertTrue(sink.offerEvent(COMPANION, "companion-response", "", BridgeEventKind.RESPONSE,
            "http.response 200", 8, 200));
        assertTrue(sink.offerFinish(COMPANION, 1, 9, 200, 0));
        assertEquals(COMPANION, uuid(peer.await(AgentEnvelope.PayloadCase.RECORDING_FINISHED)
            .getRecordingFinished().getRecordingId()));
      } finally {
        writer.close();
      }
    } finally {
      System.setErr(previous);
    }
    assertFalse(writer.isStopping());
    assertTrue(writer.incompleteWasReported());
    assertEquals(0, sink.activeRecordings());
    assertTrue(peer.activeRecordings.isEmpty());
    assertEquals(130, diagnostics.toString(StandardCharsets.UTF_8).lines().count());
    assertFalse(diagnostics.toString(StandardCharsets.UTF_8).contains("private-canary"));
  }

  private static void exerciseWriter(boolean unsupportedHealth) throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue, 2, 0);
    AcknowledgingSocket peer = new AcknowledgingSocket();
    XtpSession session = peer.session();
    AtomicInteger healthAttempts = new AtomicInteger();
    RecordingWriter writer;
    if (unsupportedHealth) {
      writer = new RecordingWriter(new RecordingWriter.Transport() {
        @Override
        public Ack send(String messageId, String correlationToken, Message payload)
            throws ClientException {
          if (payload instanceof Health) {
            healthAttempts.incrementAndGet();
            // Exercise the real session's preflight rejection, before any bytes or ACK read.
            payload = DaemonHello.newBuilder().setManifestDigest("private-canary").build();
          }
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
      }, queue, sink, Duration.ofSeconds(5));
    } else {
      // Use the production SessionTransport, not the permissive FakeTransport in writer unit tests.
      writer = new RecordingWriter(session, queue, sink);
    }
    try {
      assertTrue(sink.offerStart(FIRST, 1, "GET", "/first"));
      assertFalse(sink.offerStart("rejected", 1, "GET", "/" + "x".repeat(256)));
      assertEquals(1, sink.rejectedStarts());
      writer.start();
      // The writer reports Health before draining Start; this is also an observable barrier.
      peer.await(AgentEnvelope.PayloadCase.RECORDING_STARTED);
      assertFalse(peer.closed);
      assertTrue(sink.offerStart(LATER, 4, "GET", "/later"));
      assertTrue(sink.offerEvent(FIRST, "first-response", "", BridgeEventKind.RESPONSE,
          "http.response 200", 5, 200));
      assertTrue(sink.offerFinishWithOutcome(FIRST, 1, 6, 200, 0,
          new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 200, "", "", "")));
      assertTrue(sink.offerEvent(LATER, "later-response", "", BridgeEventKind.RESPONSE,
          "http.response 201", 7, 201));
      assertTrue(sink.offerFinishWithOutcome(LATER, 4, 8, 201, 0,
          new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 201, "", "", "")));
    } finally {
      writer.close();
    }
    assertFalse(writer.isStopping());
    // The rejected request remains visible even though both admitted streams finish normally.
    assertTrue(writer.incompleteWasReported());
    assertTrue(peer.closed);
    assertEquals(0, sink.activeRecordings());
    var health = peer.frames.stream().filter(AgentEnvelope::hasHealth).toList();
    if (unsupportedHealth) {
      assertEquals(1, healthAttempts.get(), "a rejected health report must not be retried");
      assertTrue(health.isEmpty());
    } else {
      assertEquals(1, health.size());
      assertEquals("recording-starts-rejected=1", health.get(0).getHealth().getStatus());
      assertEquals(2, health.get(0).getSessionSeq());
    }
    var finishes = peer.frames.stream().filter(AgentEnvelope::hasRecordingFinished)
        .map(AgentEnvelope::getRecordingFinished).toList();
    assertEquals(List.of(FIRST, LATER), finishes.stream()
        .map(finish -> uuid(finish.getRecordingId())).toList());
    assertEquals(List.of(200, 201), finishes.stream()
        .map(finish -> finish.getOutcome().getHttpStatus()).toList());
    assertArrayEquals(EventDigest.compute(List.of("first-response")),
        finishes.get(0).getEventDigest().toByteArray());
    assertArrayEquals(EventDigest.compute(List.of("later-response")),
        finishes.get(1).getEventDigest().toByteArray());
    assertTrue(finishes.stream().allMatch(finish -> finish.getDropCountsByPriorityCount() == 0));
    assertEquals(2, peer.frames.stream().filter(AgentEnvelope::hasEventBatch)
        .flatMap(frame -> frame.getEventBatch().getEventsList().stream())
        .filter(event -> event.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_RESPONSE).count());
  }

  private static String uuid(ByteString bytes) {
    ByteBuffer buffer = bytes.asReadOnlyByteBuffer();
    return new UUID(buffer.getLong(), buffer.getLong()).toString();
  }

  /** Synchronous framed peer: every write produces the exact staged session/recording ACK. */
  private static final class AcknowledgingSocket extends Socket {
    private final int limit;
    private final int maxActiveRecordings;
    private final Set<String> activeRecordings = new HashSet<>();
    private final List<AgentEnvelope> frames = new ArrayList<>();
    private final Map<String, Long> recordingSequences = new HashMap<>();
    private final Set<String> messageIds = new HashSet<>();
    private final LinkedBlockingQueue<AgentEnvelope> sent = new LinkedBlockingQueue<>();
    private ByteArrayInputStream response = new ByteArrayInputStream(new byte[0]);
    private boolean closed;
    private final ByteArrayOutputStream outgoing = new ByteArrayOutputStream() {
      @Override
      public void flush() throws IOException {
        try {
          AgentEnvelope frame = Framing.read(new ByteArrayInputStream(toByteArray()), limit);
          reset();
          assertEquals(frames.size() + 1L, frame.getSessionSeq());
          assertTrue(messageIds.add(frame.getMessageId()));
          frames.add(frame);
          Ack.Builder ack = Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(frame.getSessionSeq());
          if (frame.hasRecordingStarted()) {
            var start = frame.getRecordingStarted();
            assertEquals(1, start.getRecordingSeq());
            assertTrue(activeRecordings.add(uuid(start.getRecordingId())));
            assertTrue(activeRecordings.size() <= maxActiveRecordings,
                "unfinished recordings exhausted peer capacity");
            recordingSequences.put(uuid(start.getRecordingId()), 1L);
            ack.putHighestContiguousRecordingSeq(uuid(start.getRecordingId()), start.getRecordingSeq());
          } else if (frame.hasEventBatch()) {
            var batch = frame.getEventBatch();
            String recordingId = uuid(batch.getRecordingId());
            assertTrue(activeRecordings.contains(recordingId), "no events after a terminal marker");
            long sequence = recordingSequences.get(recordingId);
            for (var event : batch.getEventsList()) {
              assertEquals(++sequence, event.getRecordingSeq());
            }
            recordingSequences.put(recordingId, sequence);
            ack.putHighestContiguousRecordingSeq(uuid(batch.getRecordingId()),
                batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq());
          } else if (frame.hasRecordingFinished()) {
            var finish = frame.getRecordingFinished();
            assertTrue(activeRecordings.remove(uuid(finish.getRecordingId())));
            assertEquals(recordingSequences.get(uuid(finish.getRecordingId())).longValue(),
                finish.getFinalRecordingSeq());
            ack.putHighestContiguousRecordingSeq(uuid(finish.getRecordingId()), finish.getFinalRecordingSeq());
          }
          AgentEnvelope reply = AgentEnvelope.newBuilder()
              .setProtocolMajor(frame.getProtocolMajor()).setProtocolMinor(frame.getProtocolMinor())
              .setRuntimeSessionId(frame.getRuntimeSessionId()).setSessionSeq(frames.size())
              .setMessageId("ack-" + frames.size()).setAck(ack).build();
          ByteArrayOutputStream encoded = new ByteArrayOutputStream();
          Framing.write(encoded, reply, limit);
          response = new ByteArrayInputStream(encoded.toByteArray());
          sent.add(frame);
        } catch (ClientException failure) {
          throw new IOException("invalid outgoing test frame", failure);
        }
      }
    };

    private AcknowledgingSocket() {
      this(1024 * 1024);
    }

    private AcknowledgingSocket(int limit) {
      this(limit, Integer.MAX_VALUE);
    }

    private AcknowledgingSocket(int limit, int maxActiveRecordings) {
      this.limit = limit;
      this.maxActiveRecordings = maxActiveRecordings;
    }

    private XtpSession session() throws Exception {
      // Construct only the post-authentication transport; TLS/bootstrap admission is unchanged.
      var constructor = XtpSession.class.getDeclaredConstructor(
          Socket.class, byte[].class, int.class, int.class, int.class);
      constructor.setAccessible(true);
      return constructor.newInstance(this, new byte[16], 1, 0, limit);
    }

    private AgentEnvelope await(AgentEnvelope.PayloadCase type) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      AgentEnvelope frame;
      while ((frame = sent.poll(Math.max(0, deadline - System.nanoTime()),
          TimeUnit.NANOSECONDS)) != null) {
        if (frame.getPayloadCase() == type) return frame;
      }
      throw new AssertionError("writer did not send " + type);
    }

    @Override
    public InputStream getInputStream() {
      return new InputStream() {
        @Override
        public int read() {
          return response.read();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) {
          return response.read(bytes, offset, length);
        }
      };
    }

    @Override
    public OutputStream getOutputStream() {
      return outgoing;
    }

    @Override
    public void close() {
      closed = true;
    }
  }
}
