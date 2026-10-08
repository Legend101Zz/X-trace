package dev.xtrace.adapter;

import com.google.protobuf.InvalidProtocolBufferException;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import xtp.agent.v1.Envelope.AgentEnvelope;

/** Four-byte big-endian, length-delimited XTP protobuf framing. */
public final class Framing {
  /** Absolute defense-in-depth ceiling accepted from a negotiated daemon. */
  public static final int ABSOLUTE_MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;

  /** Pre-negotiation envelope ceiling. */
  public static final int HELLO_MAX_ENVELOPE_BYTES = 1024 * 1024;

  private Framing() {}

  /** Writes one bounded envelope and flushes it as a single logical frame. */
  public static void write(OutputStream output, AgentEnvelope envelope, int limit)
      throws ClientException {
    validateLimit(limit);
    byte[] body = envelope.toByteArray();
    if (body.length == 0 || body.length > limit) {
      throw new ClientException("XTR-JAVA-FRAME", "outgoing envelope length is invalid");
    }
    try {
      output.write(ByteBuffer.allocate(Integer.BYTES).putInt(body.length).array());
      output.write(body);
      output.flush();
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-TRANSPORT", "daemon write failed", error);
    }
  }

  /**
   * Reads one complete bounded frame and rejects zero, truncated, oversized, or malformed input.
   */
  public static AgentEnvelope read(InputStream input, int limit) throws ClientException {
    validateLimit(limit);
    byte[] prefix = readExact(input, Integer.BYTES, "frame length");
    long length = Integer.toUnsignedLong(ByteBuffer.wrap(prefix).getInt());
    if (length == 0 || length > limit || length > ABSOLUTE_MAX_ENVELOPE_BYTES) {
      throw new ClientException("XTR-JAVA-FRAME", "incoming envelope length is invalid");
    }
    byte[] body = readExact(input, (int) length, "frame body");
    try {
      return AgentEnvelope.parseFrom(body);
    } catch (InvalidProtocolBufferException error) {
      throw new ClientException("XTR-JAVA-FRAME", "incoming envelope protobuf is invalid", error);
    }
  }

  private static void validateLimit(int limit) throws ClientException {
    if (limit < 1 || limit > ABSOLUTE_MAX_ENVELOPE_BYTES) {
      throw new ClientException("XTR-JAVA-FRAME", "envelope limit is invalid");
    }
  }

  private static byte[] readExact(InputStream input, int length, String part)
      throws ClientException {
    byte[] result = new byte[length];
    int offset = 0;
    try {
      while (offset < length) {
        int count = input.read(result, offset, length - offset);
        if (count < 0) throw new EOFException(part + " was truncated");
        if (count == 0) continue;
        offset += count;
      }
      return result;
    } catch (SocketTimeoutException error) {
      throw new ClientException("XTR-JAVA-FRAME", "incoming " + part + " read timed out", error);
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-FRAME", "incoming " + part + " was truncated", error);
    }
  }
}
