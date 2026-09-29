package dev.xtrace.adapter;

import java.nio.ByteBuffer;
import java.util.UUID;

final class Identifiers {
  private Identifiers() {}

  static byte[] uuidBytes(UUID value) {
    return ByteBuffer.allocate(16)
        .putLong(value.getMostSignificantBits())
        .putLong(value.getLeastSignificantBits())
        .array();
  }
}
