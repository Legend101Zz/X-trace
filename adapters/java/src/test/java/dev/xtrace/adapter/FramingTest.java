package dev.xtrace.adapter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Transport.Health;

final class FramingTest {
  @Test
  void decodesAFrameAcrossFragmentedReads() throws Exception {
    AgentEnvelope expected =
        AgentEnvelope.newBuilder()
            .setProtocolMajor(1)
            .setSessionSeq(1)
            .setMessageId("fragmented")
            .setHealth(Health.newBuilder().setStatus("ok"))
            .build();
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    Framing.write(bytes, expected, 1024);
    InputStream fragmented =
        new ByteArrayInputStream(bytes.toByteArray()) {
          @Override
          public synchronized int read(byte[] buffer, int offset, int length) {
            return super.read(buffer, offset, Math.min(length, 1));
          }
        };
    assertEquals(expected, Framing.read(fragmented, 1024));
  }

  @Test
  void rejectsZeroOversizeTruncationAndMalformedProtobuf() {
    assertThrows(
        ClientException.class, () -> Framing.read(new ByteArrayInputStream(new byte[4]), 0));
    assertThrows(
        ClientException.class,
        () ->
            Framing.write(
                new ByteArrayOutputStream(),
                AgentEnvelope.getDefaultInstance(),
                Framing.ABSOLUTE_MAX_ENVELOPE_BYTES + 1));
    assertThrows(
        ClientException.class, () -> Framing.read(new ByteArrayInputStream(new byte[4]), 1024));
    byte[] oversize = ByteBuffer.allocate(4).putInt(1025).array();
    assertThrows(
        ClientException.class, () -> Framing.read(new ByteArrayInputStream(oversize), 1024));
    byte[] truncated = ByteBuffer.allocate(5).putInt(2).put((byte) 1).array();
    assertThrows(
        ClientException.class, () -> Framing.read(new ByteArrayInputStream(truncated), 1024));
    byte[] malformed = ByteBuffer.allocate(5).putInt(1).put((byte) 0xff).array();
    assertThrows(
        ClientException.class, () -> Framing.read(new ByteArrayInputStream(malformed), 1024));
  }

  @Test
  void readTimeoutIsReportedDistinctlyFromEof() {
    InputStream timingOut =
        new InputStream() {
          @Override
          public int read() throws java.io.IOException {
            throw new java.net.SocketTimeoutException("Read timed out");
          }

          @Override
          public int read(byte[] buffer, int offset, int length) throws java.io.IOException {
            throw new java.net.SocketTimeoutException("Read timed out");
          }
        };
    ClientException timeout =
        assertThrows(ClientException.class, () -> Framing.read(timingOut, 1024));
    assertEquals("XTR-JAVA-FRAME", timeout.code());
    assertEquals("incoming frame length read timed out", timeout.getMessage());
    assertEquals(java.net.SocketTimeoutException.class, timeout.getCause().getClass());
    ClientException eof =
        assertThrows(
            ClientException.class, () -> Framing.read(new ByteArrayInputStream(new byte[0]), 1024));
    assertEquals("XTR-JAVA-FRAME", eof.code());
    assertEquals("incoming frame length was truncated", eof.getMessage());
    assertEquals(java.io.EOFException.class, eof.getCause().getClass());
  }

  @Test
  void certificatePinRejectsWrongDigest() throws Exception {
    String actual =
        java.util.HexFormat.of()
            .formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(new byte[] {1, 2, 3}));
    XtpSession.verifyCertificatePin(actual, new byte[] {1, 2, 3});
    assertThrows(
        ClientException.class,
        () -> XtpSession.verifyCertificatePin("0".repeat(64), new byte[] {1, 2, 3}));
    assertThrows(
        ClientException.class,
        () -> XtpSession.verifyCertificatePin(actual.toUpperCase(), new byte[] {1, 2, 3}));
  }
}
