package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class XTraceAgentTest {
  @AfterEach
  void resetBridge() {
    BootstrapBridge.resetForTest();
  }

  @Test
  void premainArgumentIsOnlyTheBootstrapPath() {
    assertEquals("/private/bootstrap.json", XTraceAgent.parseBootstrapPath("/private/bootstrap.json"));
    assertThrows(IllegalArgumentException.class, () -> XTraceAgent.parseBootstrapPath(null));
    assertThrows(IllegalArgumentException.class, () -> XTraceAgent.parseBootstrapPath("  "));
    assertThrows(IllegalArgumentException.class, () -> XTraceAgent.parseBootstrapPath("bad\0path"));
  }

  @Test
  void uuidV7EncodesUnixMillisecondsRfcBitsAndUniqueValues() {
    long before = System.currentTimeMillis();
    HashSet<UUID> identifiers = new HashSet<>();
    for (int index = 0; index < 10_000; index++) {
      UUID identifier = UuidV7.random();
      assertEquals(7, identifier.version());
      assertEquals(2, identifier.variant());
      long timestamp = identifier.getMostSignificantBits() >>> 16;
      assertTrue(timestamp >= before);
      assertTrue(timestamp <= System.currentTimeMillis());
      assertTrue(identifiers.add(identifier), "UUIDv7 collision");
    }
  }

  @Test
  void bridgeEmitsDeterministicParentsAndClearsNormalContext() {
    CapturingSink sink = new CapturingSink();
    assertTrue(BootstrapBridge.install(sink));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.frameEnter("OrderController.create");
    BootstrapBridge.frameEnter("OrderService.place");
    BootstrapBridge.frameEnter("OrderRepository.save");
    BootstrapBridge.databaseStart();
    BootstrapBridge.databaseEnd(false);
    BootstrapBridge.frameExit("OrderRepository.save", false);
    BootstrapBridge.frameExit("OrderService.place", false);
    BootstrapBridge.frameExit("OrderController.create", false);
    BootstrapBridge.requestEnd(201, false);

    assertFalse(BootstrapBridge.hasContext());
    assertEquals(10, sink.events.size());
    Captured request = sink.events.get(0);
    Captured controller = sink.events.get(1);
    Captured service = sink.events.get(2);
    Captured repository = sink.events.get(3);
    Captured databaseStart = sink.events.get(4);
    Captured databaseEnd = sink.events.get(5);
    Captured repositoryExit = sink.events.get(6);
    Captured serviceExit = sink.events.get(7);
    Captured controllerExit = sink.events.get(8);
    Captured response = sink.events.get(9);
    assertEquals("", request.parent);
    assertEquals(request.id, controller.parent);
    assertEquals(controller.id, service.parent);
    assertEquals(service.id, repository.parent);
    assertEquals(repository.id, databaseStart.parent);
    assertEquals(databaseStart.id, databaseEnd.parent);
    assertEquals(repository.id, repositoryExit.parent);
    assertEquals(service.id, serviceExit.parent);
    assertEquals(controller.id, controllerExit.parent);
    assertEquals(request.id, response.parent);
    assertEquals(201, response.detail);
    assertEquals(0, sink.finishedDrops);
  }

  @Test
  void thrownRequestClearsContextAndSinkFailureNeverEscapes() {
    CapturingSink sink = new CapturingSink();
    assertTrue(BootstrapBridge.install(sink));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.frameEnter("OrderController.create");
    BootstrapBridge.frameExit("OrderController.create", true);
    BootstrapBridge.requestEnd(500, true);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeEventKind.FRAME_THROW, sink.events.get(2).kind);

    BootstrapBridge.resetForTest();
    BridgeSink failing =
        new BridgeSink() {
          @Override
          public boolean offerStart(String id, long ns, String method, String route) {
            return true;
          }

          @Override
          public boolean offerEvent(
              String id, String event, String parent, int kind, String symbol, long ns, int detail) {
            throw new IllegalStateException("test-only sink failure");
          }

          @Override
          public boolean offerFinish(
              String id, long started, long finished, int status, long dropped) {
            throw new IllegalStateException("test-only sink failure");
          }

          @Override
          public void reportIncomplete(int failureKind) {}
        };
    assertTrue(BootstrapBridge.install(failing));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.requestEnd(201, false);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void rejectedEventsAreReportedInTheTerminalDropCount() {
    CapturingSink sink = new CapturingSink();
    sink.rejectSymbol = "OrderService.place";
    assertTrue(BootstrapBridge.install(sink));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.frameEnter("OrderController.create");
    BootstrapBridge.frameEnter("OrderService.place");
    BootstrapBridge.frameExit("OrderService.place", false);
    BootstrapBridge.frameExit("OrderController.create", false);
    BootstrapBridge.requestEnd(201, false);
    assertTrue(sink.finishedDrops >= 2);
  }

  @Test
  void rejectedEventsNeverBecomeParentsOfLaterAcceptedEvents() {
    CapturingSink sink = new CapturingSink();
    sink.rejectSymbol = "OrderRepository.save";
    assertTrue(BootstrapBridge.install(sink));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.frameEnter("OrderController.create");
    BootstrapBridge.frameEnter("OrderService.place");
    BootstrapBridge.frameEnter("OrderRepository.save");
    BootstrapBridge.databaseStart();
    BootstrapBridge.databaseEnd(false);
    BootstrapBridge.frameExit("OrderRepository.save", false);
    BootstrapBridge.frameExit("OrderService.place", false);
    BootstrapBridge.frameExit("OrderController.create", false);
    BootstrapBridge.requestEnd(201, false);

    HashSet<String> emitted = new HashSet<>();
    for (Captured event : sink.events) emitted.add(event.id);
    for (Captured event : sink.events) {
      assertTrue(event.parent.isEmpty() || emitted.contains(event.parent));
    }
    assertTrue(sink.finishedDrops >= 2);
  }

  @Test
  void startAndTerminalRejectionsReportBoundedProcessIncompleteness() {
    CapturingSink rejectedStart = new CapturingSink();
    rejectedStart.acceptStart = false;
    assertTrue(BootstrapBridge.install(rejectedStart));
    assertFalse(BootstrapBridge.requestStart("POST", "/orders"));
    assertEquals(List.of(BridgeSink.INCOMPLETE_START_REJECTED), rejectedStart.incompleteKinds);

    BootstrapBridge.resetForTest();
    CapturingSink rejectedFinish = new CapturingSink();
    rejectedFinish.acceptFinish = false;
    assertTrue(BootstrapBridge.install(rejectedFinish));
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    BootstrapBridge.requestEnd(201, false);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(List.of(BridgeSink.INCOMPLETE_FINISH_REJECTED), rejectedFinish.incompleteKinds);
  }

  private static final class CapturingSink implements BridgeSink {
    private final List<Captured> events = new ArrayList<>();
    private final List<Integer> incompleteKinds = new ArrayList<>();
    private String rejectSymbol;
    private long finishedDrops;
    private boolean acceptStart = true;
    private boolean acceptFinish = true;

    @Override
    public boolean offerStart(String id, long ns, String method, String route) {
      return acceptStart;
    }

    @Override
    public boolean offerEvent(
        String id, String event, String parent, int kind, String symbol, long ns, int detail) {
      if (symbol.equals(rejectSymbol)) return false;
      events.add(new Captured(event, parent, kind, symbol, detail));
      return true;
    }

    @Override
    public boolean offerFinish(
        String id, long started, long finished, int status, long dropped) {
      finishedDrops = dropped;
      return acceptFinish;
    }

    @Override
    public void reportIncomplete(int failureKind) {
      incompleteKinds.add(failureKind);
    }
  }

  private record Captured(String id, String parent, int kind, String symbol, int detail) {}
}
