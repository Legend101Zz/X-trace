package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.util.List;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.OutcomeKind;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.SourceBinding;

class WireMappingTest {
  private static QueueSignal.Event plain(int kind, String symbol, int detail) {
    return new QueueSignal.Event("r", "r:1", "", kind, symbol, 5, detail, 128);
  }

  @Test
  void queueShedGapStatesReasonAndCount() throws Exception {
    List<QueueSignal.Event> events =
        RecordingWriter.withGap(
            "00000000-0000-4000-8000-000000000001",
            List.of(plain(BridgeEventKind.REQUEST_UPDATE, "http.request GET /a", 0)),
            7, 1, 2);
    RecordingEvent gap = RecordingWriter.toProto(events.get(1), 3);
    assertTrue(gap.hasGap());
    assertEquals(GapReason.GAP_REASON_QUEUE_FULL, gap.getGap().getReason());
    assertEquals(7, gap.getGap().getCount());
  }

  @Test
  void untransformedClassesAreAClassNotTransformedGapBeforeTheResponse() throws Exception {
    String id = "00000000-0000-4000-8000-000000000001";
    List<QueueSignal.Event> events =
        RecordingWriter.withGap(
            id,
            List.of(
                plain(BridgeEventKind.REQUEST_UPDATE, "http.request GET /a", 0),
                plain(BridgeEventKind.RESPONSE, "http.response 200", 200)),
            0, 0, 3, 1, 2);
    assertEquals(3, events.size());
    assertEquals(BridgeEventKind.RESPONSE, events.get(2).kind());
    RecordingEvent gap = RecordingWriter.toProto(events.get(1), 3);
    assertEquals(GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED, gap.getGap().getReason());
    assertEquals(3, gap.getGap().getCount());
    // Nothing skipped, nothing added.
    assertEquals(1, RecordingWriter.withGap(id, events.subList(0, 1), 0, 0, 0, 1, 2).size());
  }

  @Test
  void handlerUnresolvedIsALostCorrelationNotAFabricatedHandler() throws Exception {
    RecordingEvent gap =
        RecordingWriter.toProto(
            plain(BridgeEventKind.GAP, BootstrapBridge.HANDLER_UNRESOLVED_SYMBOL, 0), 2);
    assertEquals(GapReason.GAP_REASON_CORRELATION_LOST, gap.getGap().getReason());
    assertEquals(1, gap.getGap().getCount());
  }

  @Test
  void respondedOutcomeCarriesTheObservedStatusOnly() {
    var outcome =
        RecordingWriter.outcomeProto(
            new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, 404, null, null, null));
    assertEquals(OutcomeKind.OUTCOME_KIND_RESPONDED, outcome.getKind());
    assertEquals(404, outcome.getHttpStatus());
    assertFalse(outcome.hasException());
  }

  @Test
  void propagatedOutcomeCarriesSanitizedExceptionAndThrowingFrame() {
    var outcome =
        RecordingWriter.outcomeProto(
            new BridgeSink.Outcome(
                BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0, "java.lang.IllegalStateException",
                "token=abc123secret failed", "r:4"));
    assertEquals(OutcomeKind.OUTCOME_KIND_EXCEPTION_PROPAGATED, outcome.getKind());
    assertEquals(0, outcome.getHttpStatus());
    assertEquals("java.lang.IllegalStateException", outcome.getException().getExceptionType());
    assertFalse(outcome.getException().getSanitizedMessage().contains("abc123secret"));
    assertEquals("r:4", outcome.getThrownFromEventId());
  }

  @Test
  void unobservedOutcomeHasNoStatusAndNoException() {
    var outcome =
        RecordingWriter.outcomeProto(
            new BridgeSink.Outcome(BridgeSink.Outcome.UNOBSERVED, 0, null, null, null));
    assertEquals(OutcomeKind.OUTCOME_KIND_UNOBSERVED, outcome.getKind());
    assertEquals(0, outcome.getHttpStatus());
    assertFalse(outcome.hasException());
  }

  @Test
  void observedUnattestedEventCarriesSourceRangeAndHash() throws Exception {
    byte[] hash = new byte[32];
    hash[0] = 7;
    QueueSignal.Event event =
        new QueueSignal.Event(
            "r", "r:2", "r:1", BridgeEventKind.FRAME_ENTER, "OwnerController.show", 9, 0,
            "src/main/java/a/OwnerController.java", 40, 58, hash,
            SourceIdentity.OBSERVED_UNATTESTED, 256);
    RecordingEvent proto = RecordingWriter.toProto(event, 3);
    assertEquals(SourceBinding.SOURCE_BINDING_OBSERVED_UNATTESTED, proto.getSourceBinding());
    assertEquals("src/main/java/a/OwnerController.java", proto.getSource().getPath());
    assertEquals(40, proto.getSource().getStartLine());
    assertEquals(58, proto.getSource().getEndLine());
    assertEquals(32, proto.getSource().getContentHash().size());
  }

  @Test
  void throwEventCarriesBoundedSanitizedException() throws Exception {
    QueueSignal.Event event =
        new QueueSignal.Event(
            "r", "r:3", "r:2", BridgeEventKind.FRAME_THROW, "S.place", 9, 0, null, 0, 0, null, 0,
            256, "java.lang.IllegalArgumentException", "Bearer abcdefghijklmnop rejected");
    RecordingEvent proto = RecordingWriter.toProto(event, 4);
    assertEquals(
        "java.lang.IllegalArgumentException", proto.getException().getExceptionType());
    assertFalse(proto.getException().getSanitizedMessage().contains("abcdefghijklmnop"));
    assertEquals(0, proto.getException().getStackFramesCount());
  }

  @Test
  void requestEventInteractionComesFromTheValidatedSymbol() throws Exception {
    RecordingEvent proto =
        RecordingWriter.toProto(
            plain(BridgeEventKind.REQUEST_UPDATE, "http.request GET /owners/{ownerId}", 0), 2);
    assertEquals("GET", proto.getInteraction().getMethod());
    assertEquals("/owners/{ownerId}", proto.getInteraction().getPath());
  }
}
