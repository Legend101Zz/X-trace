package dev.xtrace.adapter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Handshake.DaemonHello;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;
import xtp.agent.v1.Transport.Health;
import xtp.agent.v1.Transport.RejectedMessage;

final class XtpSessionTest {
  private static final byte[] SESSION = Identifiers.uuidBytes(
      java.util.UUID.fromString("00000000-0000-4000-8000-000000000001"));
  private static final int LIMIT = 4096;

  @Test
  void healthUsesNormalFramingSequenceAndStagedAcknowledgement() throws Exception {
    Health health = Health.newBuilder()
        .setMonotonicNs(123456789)
        .setQueueDepthBatches(7)
        .setResidentBytes(9876543210L)
        .setStatus("recording-starts-rejected=12")
        .build();
    // Daemon health consumes its own sequence, independently of the outgoing stream.
    MemorySocket socket = new MemorySocket(
        daemon(1).setHealth(Health.newBuilder().setStatus("ok")).build(),
        daemon(2).setAck(staged(1)).build(),
        daemon(3).setAck(staged(2)).build());
    try (XtpSession session = session(socket)) {
      assertEquals(staged(1), session.send("health", "", health));
      assertEquals(staged(2), session.send("capabilities", "next", CapabilitySet.getDefaultInstance()));
      ByteArrayInputStream frames = new ByteArrayInputStream(socket.written.toByteArray());
      AgentEnvelope sent = Framing.read(frames, LIMIT);
      assertEquals(AgentEnvelope.PayloadCase.HEALTH, sent.getPayloadCase());
      assertEquals(health, sent.getHealth());
      assertEquals(1, sent.getProtocolMajor());
      assertEquals(0, sent.getProtocolMinor());
      assertEquals(ByteString.copyFrom(SESSION), sent.getRuntimeSessionId());
      assertEquals(1, sent.getSessionSeq());
      assertEquals("health", sent.getMessageId());
      assertEquals("", sent.getCorrelationToken());
      AgentEnvelope next = Framing.read(frames, LIMIT);
      assertEquals(2, next.getSessionSeq());
      assertEquals(AgentEnvelope.PayloadCase.CAPABILITY_SET, next.getPayloadCase());
      assertEquals("next", next.getCorrelationToken());
      assertEquals(0, frames.available());
    }
    assertTrue(socket.closed);
  }

  @Test
  void unsupportedPayloadIsVisibleWritesNothingAndLeavesTheNextSequenceUsable() throws Exception {
    MemorySocket socket = new MemorySocket(daemon(1).setAck(staged(1)).build());
    try (XtpSession session = session(socket)) {
      ClientException failure = assertThrows(ClientException.class,
          () -> session.send("unsupported", "", DaemonHello.getDefaultInstance()));
      assertEquals("XTR-JAVA-ENVELOPE", failure.code());
      assertEquals("outgoing payload type is unsupported", failure.getMessage());
      assertEquals(0, socket.written.size());
      assertFalse(socket.closed);
      assertEquals(staged(1), session.send("health", "", Health.getDefaultInstance()));
      assertEquals(1, Framing.read(
          new ByteArrayInputStream(socket.written.toByteArray()), LIMIT).getSessionSeq());
    }
  }

  @Test
  void oversizedSupportedPayloadWritesNothingAndLeavesTheNextSequenceUsable() throws Exception {
    MemorySocket socket = new MemorySocket(daemon(1).setAck(staged(1)).build());
    Health oversized = Health.newBuilder().setStatus("x".repeat(LIMIT)).build();
    try (XtpSession session = session(socket)) {
      assertFalse(session.fitsEnvelope("oversized", "", oversized));
      ClientException failure = assertThrows(ClientException.class,
          () -> session.send("oversized", "", oversized));
      assertEquals("XTR-JAVA-FRAME", failure.code());
      assertEquals(0, socket.written.size());
      assertFalse(socket.closed);
      assertTrue(session.fitsEnvelope("health", "", Health.getDefaultInstance()));
      assertEquals(staged(1), session.send("health", "", Health.getDefaultInstance()));
      ByteArrayInputStream frames = new ByteArrayInputStream(socket.written.toByteArray());
      AgentEnvelope sent = Framing.read(frames, LIMIT);
      assertEquals(1, sent.getSessionSeq());
      assertEquals("health", sent.getMessageId());
      assertEquals(0, frames.available());
    }
  }

  @Test
  void envelopeOverheadAloneCanExceedTheNegotiatedLimitWithoutClosingTheSession() throws Exception {
    MemorySocket socket = new MemorySocket(daemon(1).setAck(staged(1)).build());
    try (XtpSession session = session(socket)) {
      Health payload = Health.newBuilder().setStatus("x".repeat(LIMIT - 16)).build();
      assertTrue(payload.getSerializedSize() < LIMIT);
      assertFalse(session.fitsEnvelope("oversized", "correlation", payload));
      assertEquals("XTR-JAVA-FRAME", assertThrows(ClientException.class,
          () -> session.send("oversized", "correlation", payload)).code());
      assertFalse(socket.closed);
      assertEquals(0, socket.written.size());
      assertEquals(staged(1), session.send("health", "", Health.getDefaultInstance()));
    }
  }

  @Test
  void healthRejectsWrongSequenceDurabilityAndRejectionsJustLikeOtherPayloads() throws Exception {
    for (Ack invalid : new Ack[] {
        staged(2),
        staged(1).toBuilder().setDurability(AckDurability.ACK_DURABILITY_COMMITTED).build(),
        staged(1).toBuilder().addRejected(RejectedMessage.newBuilder()
            .setMessageId("health").setReasonCode("rejected")).build()
    }) {
      MemorySocket socket = new MemorySocket(daemon(1).setAck(invalid).build());
      try (XtpSession session = session(socket)) {
        ClientException failure = assertThrows(ClientException.class,
            () -> session.send("health", "", Health.getDefaultInstance()));
        assertEquals("XTR-JAVA-ACK", failure.code());
        assertTrue(socket.closed, "delivery ambiguity must still fail closed");
        int bytesWritten = socket.written.size();
        assertThrows(ClientException.class,
            () -> session.send("later", "", Health.getDefaultInstance()));
        assertEquals(bytesWritten, socket.written.size());
      }
    }
  }

  private static XtpSession session(MemorySocket socket) throws Exception {
    return new XtpSession(socket, SESSION, 1, 0, LIMIT);
  }

  private static AgentEnvelope.Builder daemon(long sequence) {
    return AgentEnvelope.newBuilder()
        .setProtocolMajor(1)
        .setRuntimeSessionId(ByteString.copyFrom(SESSION))
        .setSessionSeq(sequence)
        .setMessageId("daemon-" + sequence);
  }

  private static Ack staged(long sequence) {
    return Ack.newBuilder().setHighestContiguousSessionSeq(sequence)
        .setDurability(AckDurability.ACK_DURABILITY_STAGED).build();
  }

  private static final class MemorySocket extends Socket {
    private final ByteArrayOutputStream written = new ByteArrayOutputStream();
    private final InputStream responses;
    private boolean closed;

    private MemorySocket(AgentEnvelope... envelopes) throws ClientException {
      ByteArrayOutputStream frames = new ByteArrayOutputStream();
      for (AgentEnvelope envelope : envelopes) Framing.write(frames, envelope, LIMIT);
      responses = new ByteArrayInputStream(frames.toByteArray());
    }

    @Override
    public InputStream getInputStream() {
      return responses;
    }

    @Override
    public OutputStream getOutputStream() {
      return written;
    }

    @Override
    public void close() {
      closed = true;
    }
  }
}
