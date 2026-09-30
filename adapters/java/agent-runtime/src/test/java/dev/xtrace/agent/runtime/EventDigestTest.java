package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class EventDigestTest {
  @Test
  void matchesSharedOrderedEventIdGolden() {
    byte[] expected =
        HexFormat.of()
            .parseHex("1a83620c401707b511e6de72dcfc14bb994340261103f3df91870c07b65fa0e5");
    assertArrayEquals(expected, EventDigest.compute(List.of("event-1", "event-2")));
    assertFalse(
        java.util.Arrays.equals(expected, EventDigest.compute(List.of("event-2", "event-1"))));
  }
}
