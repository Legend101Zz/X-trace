package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ExceptionSummaryTest {
  @Test
  void messageRedactedAndBounded() {
    String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl";
    String message =
        "login failed for token="
            + jwt
            + " using Bearer abcdefghijklmnop and key AKIAABCDEFGHIJKLMNOP"
            + " url https://user:hunter2@db.internal/x password: s3cr3t!"
            + " hash "
            + "a".repeat(40)
            + " tail";
    String clean = ExceptionSummary.message(message);
    for (String secret :
        new String[] {jwt, "abcdefghijklmnop", "AKIAABCDEFGHIJKLMNOP", "hunter2", "s3cr3t", "a".repeat(40)}) {
      assertFalse(clean.contains(secret), secret + " leaked in: " + clean);
    }
    assertTrue(clean.contains(ExceptionSummary.REDACTED));
    assertTrue(clean.getBytes(StandardCharsets.UTF_8).length <= ExceptionSummary.MAX_MESSAGE_BYTES);
    assertTrue(ExceptionSummary.wasRedacted(message, clean));
  }

  @Test
  void pemBlockIsDroppedFromTheBeginMarker() {
    String clean =
        ExceptionSummary.message("bad key -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END");
    assertEquals("bad key [redacted]", clean);
  }

  @Test
  void plainMessageIsKeptAndCleanedOfControlCharacters() {
    assertEquals("Owner 7 not found", ExceptionSummary.message("Owner 7 not found"));
    assertEquals("a b c", ExceptionSummary.message("a\nb\u0000c"));
    assertNull(ExceptionSummary.message(null));
    assertEquals("", ExceptionSummary.message(""));
  }

  @Test
  void truncationNeverSplitsMultibyteOrSurrogateSequences() {
    String text = "é".repeat(400);
    String cut = ExceptionSummary.message(text);
    assertEquals(256, cut.length());
    assertTrue(cut.getBytes(StandardCharsets.UTF_8).length <= 512);
    String emoji = "😀".repeat(200);
    String cutEmoji = ExceptionSummary.message(emoji);
    assertTrue(cutEmoji.getBytes(StandardCharsets.UTF_8).length <= 512);
    assertEquals(cutEmoji, new String(cutEmoji.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));
  }

  @Test
  void typeNameIsBounded() {
    assertEquals(256, ExceptionSummary.type("x".repeat(1000)).length());
    assertNull(ExceptionSummary.type(null));
  }
}
