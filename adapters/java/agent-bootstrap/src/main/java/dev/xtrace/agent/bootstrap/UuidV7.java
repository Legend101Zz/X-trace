package dev.xtrace.agent.bootstrap;

import java.security.SecureRandom;
import java.util.UUID;

/** Creates RFC 9562 UUIDv7 values using only JDK classes visible to the bootstrap loader. */
final class UuidV7 {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final long TIMESTAMP_MASK = 0x0000ffffffffffffL;

  private UuidV7() {}

  static UUID random() {
    byte[] entropy = new byte[16];
    RANDOM.nextBytes(entropy);
    long mostSignificantBits = 0;
    long leastSignificantBits = 0;
    for (int index = 0; index < 8; index++) {
      mostSignificantBits = (mostSignificantBits << 8) | (entropy[index] & 0xffL);
      leastSignificantBits = (leastSignificantBits << 8) | (entropy[index + 8] & 0xffL);
    }

    long timestamp = System.currentTimeMillis() & TIMESTAMP_MASK;
    mostSignificantBits = (timestamp << 16) | (mostSignificantBits & 0x0fffL);
    mostSignificantBits = (mostSignificantBits & 0xffffffffffff0fffL) | 0x7000L;
    leastSignificantBits = (leastSignificantBits & 0x3fffffffffffffffL) | 0x8000000000000000L;
    return new UUID(mostSignificantBits, leastSignificantBits);
  }
}
