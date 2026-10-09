package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
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

    @Override
    public Ack send(String messageId, String correlationToken, Message payload)
        throws ClientException {
      Ack.Builder ack =
          Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(1);
      if (payload instanceof RecordingStarted started) {
        ack.putHighestContiguousRecordingSeq(uuid(started.getRecordingId().toByteArray()), 1);
      } else if (payload instanceof EventBatch batch) {
        long sequence = batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq();
        ack.putHighestContiguousRecordingSeq(uuid(batch.getRecordingId().toByteArray()), sequence);
      } else if (payload instanceof RecordingFinished finished) {
        ack.putHighestContiguousRecordingSeq(
            uuid(finished.getRecordingId().toByteArray()), finished.getFinalRecordingSeq());
      } else if (!(payload instanceof CapabilitySet)) {
        throw new ClientException("XTR-JAVA-TEST", "unexpected payload");
      }
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
