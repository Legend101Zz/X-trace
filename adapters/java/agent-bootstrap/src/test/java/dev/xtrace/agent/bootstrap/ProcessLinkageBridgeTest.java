package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ProcessLinkageBridgeTest {
  private ReactorContextBridgeTest.RecordingTestSink sink;

  @BeforeEach
  void setUp() {
    BootstrapBridge.resetForTest();
    sink = new ReactorContextBridgeTest.RecordingTestSink();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void tearDown() {
    BootstrapBridge.resetForTest();
  }

  @Test
  void uninstrumentedProcessStartEmitsChildProcessNotInstrumentedGapInsideActiveRequest() {
    assertTrue(BootstrapBridge.requestStart("POST", "/jobs"));
    ProcessLinkageBridge.onProcessBuilderStart();
    BootstrapBridge.requestEnd(202, false);

    assertEquals(1, sink.recordings.size());
    var rec = sink.recordings.values().iterator().next();
    assertTrue(
        rec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.CHILD_PROCESS_NOT_INSTRUMENTED_SYMBOL.equals(e.symbol)
                    && e.detail == 1));

    var links = ProcessLinkageBridge.recordedLinks();
    assertEquals(1, links.size());
    var link = links.get(0);
    assertEquals(ProcessLinkageBridge.SpawnKind.JVM_FORK, link.spawnKind());
    assertEquals(ProcessLinkageBridge.LinkStatus.UNINSTRUMENTED_GAP, link.status());
    assertEquals("child_process_not_instrumented", link.gapReason());
    assertEquals(rec.recordingId, link.parentRecordingId());
    assertNull(link.childSessionId());
    assertNull(link.correlationTokenHash());
  }

  @Test
  void optInChildLinkEmitsJvmForkLinkWithHashedTokenAndFailsClosedOnReuseOrMismatch() {
    String secretToken = "raw-java-child-secret-canary";
    String childSessionId = "01900000-0000-7000-8000-000000000101";
    String childRecordingId = "01900000-0000-7000-8000-000000000102";

    assertTrue(BootstrapBridge.requestStart("POST", "/fork"));
    try (var ignored =
        ProcessLinkageBridge.withOptInChildLink(
            childSessionId, childRecordingId, secretToken, secretToken)) {
      ProcessLinkageBridge.onProcessBuilderStart();
      // Second spawn in the same single-use scope must fail closed with bootstrap_consumed.
      ProcessLinkageBridge.onProcessBuilderStart();
    }

    // Mismatched token fails closed to correlation_lost.
    assertFalse(
        ProcessLinkageBridge.registerChildSessionLink(
            "01900000-0000-7000-8000-000000000103",
            null,
            "wrong-token",
            secretToken));

    // Control-character token or missing child session fails closed without leaking token.
    assertFalse(
        ProcessLinkageBridge.registerChildSessionLink(
            "01900000-0000-7000-8000-000000000104",
            null,
            "bad\ntoken",
            null));
    assertFalse(
        ProcessLinkageBridge.registerChildSessionLink(null, null, secretToken, secretToken));

    BootstrapBridge.requestEnd(200, false);

    var rec = sink.recordings.values().iterator().next();
    assertTrue(
        rec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.ASYNC_LINK
                    && BootstrapBridge.PROCESS_LINK_SYMBOL.equals(e.symbol)));
    assertTrue(
        rec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.BOOTSTRAP_CONSUMED_SYMBOL.equals(e.symbol)));
    assertTrue(
        rec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.CORRELATION_LOST_SYMBOL.equals(e.symbol)));

    var links = ProcessLinkageBridge.recordedLinks();
    assertEquals(5, links.size());
    assertEquals(ProcessLinkageBridge.LinkStatus.LINKED, links.get(0).status());
    assertEquals(childSessionId, links.get(0).childSessionId());
    assertEquals(childRecordingId, links.get(0).childRecordingId());
    assertNotNull(links.get(0).correlationTokenHash());
    assertTrue(links.get(0).correlationTokenHash().startsWith("sha256:"));
    assertFalse(links.get(0).correlationTokenHash().contains(secretToken));

    assertEquals(ProcessLinkageBridge.LinkStatus.UNINSTRUMENTED_GAP, links.get(1).status());
    assertEquals("bootstrap_consumed", links.get(1).gapReason());

    assertEquals(ProcessLinkageBridge.LinkStatus.CORRELATION_LOST, links.get(2).status());
    assertEquals("correlation_lost", links.get(2).gapReason());
    assertEquals(ProcessLinkageBridge.LinkStatus.CORRELATION_LOST, links.get(3).status());
    assertEquals(ProcessLinkageBridge.LinkStatus.CORRELATION_LOST, links.get(4).status());
  }

  @Test
  void noBridgeSinkInstalledLeavesProcessStartAsNoOp() {
    BootstrapBridge.disable(sink);
    ProcessLinkageBridge.onProcessBuilderStart();
    assertEquals(0, ProcessLinkageBridge.recordedLinks().size());
    assertEquals(0, ProcessLinkageBridge.gapCount());
    assertEquals(0, ProcessLinkageBridge.linkedCount());
  }
}
