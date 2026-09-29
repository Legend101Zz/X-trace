package dev.xtrace.adapter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Canonical XTP HMAC-SHA256 transcript encoding and verification. */
public final class TranscriptProof {
  private static final byte[] LABEL = "xtrace-handshake-v1".getBytes(StandardCharsets.US_ASCII);

  private TranscriptProof() {}

  static byte[] zeroNonce() {
    return new byte[32];
  }

  /** Computes the exact length-prefixed XTP handshake proof. */
  public static byte[] compute(
      byte[] secret,
      byte[] exporter,
      byte[] sessionId,
      byte[] clientNonce,
      byte[] serverNonce,
      byte[] manifestDigest)
      throws ClientException {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret, "HmacSHA256"));
      mac.update(LABEL);
      for (byte[] field :
          new byte[][] {exporter, sessionId, clientNonce, serverNonce, manifestDigest}) {
        mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(field.length).array());
        mac.update(field);
      }
      return mac.doFinal();
    } catch (GeneralSecurityException error) {
      throw new ClientException(
          "XTR-JAVA-HANDSHAKE", "transcript proof could not be computed", error);
    }
  }

  /** Verifies a 32-byte daemon proof in constant time. */
  public static void verify(byte[] expected, byte[] actual) throws ClientException {
    if (expected.length != 32 || actual.length != 32 || !MessageDigest.isEqual(expected, actual)) {
      throw new ClientException("XTR-JAVA-HANDSHAKE", "daemon transcript proof is invalid");
    }
  }
}
