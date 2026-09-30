package dev.xtrace.agent.runtime;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.crypto.digests.Blake3Digest;

/** Deterministic BLAKE3 digest over emitted event identifiers in order. */
final class EventDigest {
  private EventDigest() {}

  static byte[] compute(List<String> eventIds) {
    Blake3Digest digest = new Blake3Digest(256);
    for (String eventId : eventIds) {
      byte[] bytes = eventId.getBytes(StandardCharsets.UTF_8);
      digest.update(bytes, 0, bytes.length);
    }
    byte[] output = new byte[32];
    digest.doFinal(output, 0);
    return output;
  }
}
