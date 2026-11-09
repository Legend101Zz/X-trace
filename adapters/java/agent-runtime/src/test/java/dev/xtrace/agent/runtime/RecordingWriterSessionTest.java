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
import java.util.List;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Handshake.DaemonHello;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;
import xtp.agent.v1.Transport.Health;

@ResourceLock(Resources.SYSTEM_ERR)
final class RecordingWriterSessionTest {
  private static final String FIRST = "00000000-0000-4000-8000-000000000001";
  private static final String LATER = "00000000-0000-4000-8000-000000000002";

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
    private static final int LIMIT = 1024 * 1024;
    private final List<AgentEnvelope> frames = new ArrayList<>();
    private final LinkedBlockingQueue<AgentEnvelope> sent = new LinkedBlockingQueue<>();
    private ByteArrayInputStream response = new ByteArrayInputStream(new byte[0]);
    private boolean closed;
    private final ByteArrayOutputStream outgoing = new ByteArrayOutputStream() {
      @Override
      public void flush() throws IOException {
        try {
          AgentEnvelope frame = Framing.read(new ByteArrayInputStream(toByteArray()), LIMIT);
          reset();
          assertEquals(frames.size() + 1L, frame.getSessionSeq());
          frames.add(frame);
          Ack.Builder ack = Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(frame.getSessionSeq());
          if (frame.hasRecordingStarted()) {
            var start = frame.getRecordingStarted();
            ack.putHighestContiguousRecordingSeq(uuid(start.getRecordingId()), start.getRecordingSeq());
          } else if (frame.hasEventBatch()) {
            var batch = frame.getEventBatch();
            ack.putHighestContiguousRecordingSeq(uuid(batch.getRecordingId()),
                batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq());
          } else if (frame.hasRecordingFinished()) {
            var finish = frame.getRecordingFinished();
            ack.putHighestContiguousRecordingSeq(uuid(finish.getRecordingId()), finish.getFinalRecordingSeq());
          }
          AgentEnvelope reply = AgentEnvelope.newBuilder()
              .setProtocolMajor(frame.getProtocolMajor()).setProtocolMinor(frame.getProtocolMinor())
              .setRuntimeSessionId(frame.getRuntimeSessionId()).setSessionSeq(frames.size())
              .setMessageId("ack-" + frames.size()).setAck(ack).build();
          ByteArrayOutputStream encoded = new ByteArrayOutputStream();
          Framing.write(encoded, reply, LIMIT);
          response = new ByteArrayInputStream(encoded.toByteArray());
          sent.add(frame);
        } catch (ClientException failure) {
          throw new IOException("invalid outgoing test frame", failure);
        }
      }
    };

    private XtpSession session() throws Exception {
      // Construct only the post-authentication transport; TLS/bootstrap admission is unchanged.
      var constructor = XtpSession.class.getDeclaredConstructor(
          Socket.class, byte[].class, int.class, int.class, int.class);
      constructor.setAccessible(true);
      return constructor.newInstance(this, new byte[16], 1, 0, LIMIT);
    }

    private void await(AgentEnvelope.PayloadCase type) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      AgentEnvelope frame;
      while ((frame = sent.poll(Math.max(0, deadline - System.nanoTime()),
          TimeUnit.NANOSECONDS)) != null) {
        if (frame.getPayloadCase() == type) return;
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
