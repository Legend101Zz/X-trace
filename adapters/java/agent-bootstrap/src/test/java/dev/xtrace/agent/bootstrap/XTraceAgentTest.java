package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import dev.xtrace.agent.runtime.AgentRuntime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class XTraceAgentTest {
  @TempDir Path temporaryDirectory;

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
  void permanentPremainFailurePreventsUnsafeAttachRetry() throws Exception {
    assertPremainFailureBlocksRetry("permanent-bootstrap.json", true);
  }

  @Test
  void postAppendBootstrapLoadFailurePreventsUnsafeAttachRetry() throws Exception {
    assertPremainFailureBlocksRetry("post-append-bootstrap.json", false);
  }

  @Test
  void identityMismatchFailurePreventsUnsafeAttachRetry() throws Exception {
    assertPremainFailureBlocksRetry("identity-mismatch", true);
  }

  private void assertPremainFailureBlocksRetry(String bootstrapName, boolean includeBridge)
      throws Exception {
    Path distribution = Files.createDirectory(temporaryDirectory.resolve("distribution"));
    Path runtime = Files.createDirectory(distribution.resolve("runtime"));
    Path agent = distribution.resolve("xtrace-java-agent.jar");
    Path runtimeJar = runtime.resolve("agent-runtime.jar");
    Path bootstrap = temporaryDirectory.resolve(bootstrapName);
    Path output = temporaryDirectory.resolve("child.out");
    Files.writeString(bootstrap, "test bootstrap is consumed only by the fake runtime");
    writeBootstrapAgentJar(agent, includeBridge);
    writeFakeRuntimeJar(runtimeJar);

    Path testClasses = Path.of(
        PremainRetryFixture.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String classPath = testClasses + java.io.File.pathSeparator + agent;
    Process child = new ProcessBuilder(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-cp",
        classPath,
        "-javaagent:" + agent + "=" + bootstrap,
        PremainRetryFixture.class.getName())
        .redirectErrorStream(true)
        .redirectOutput(output.toFile())
        .start();
    try {
      assertTrue(child.waitFor(10, TimeUnit.SECONDS), "premain failure fixture must be bounded");
      assertEquals(0, child.exitValue(), "the child must reach its assertion after premain returns");
      assertTrue(Files.readString(output).contains("PREMAIN_PARTIAL_ATTACH_BLOCKED"));
      assertFalse(Files.readString(output).contains("UNEXPECTEDLY_ALLOWED"));
    } finally {
      if (child.isAlive()) {
        child.destroyForcibly();
        child.waitFor(5, TimeUnit.SECONDS);
      }
    }
  }

  private static void writeBootstrapAgentJar(Path target, boolean includeBridge) throws Exception {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Premain-Class", XTraceAgent.class.getName());
    manifest.getMainAttributes().putValue("Agent-Class", XTraceAgent.class.getName());
    Path classes = Path.of(XTraceAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(target), manifest);
        var paths = Files.walk(classes)) {
      for (Path file : paths.filter(Files::isRegularFile).sorted().toList()) {
        String name = classes.relativize(file).toString().replace(java.io.File.separatorChar, '/');
        if (!name.startsWith("dev/xtrace/agent/bootstrap/")
            || !name.endsWith(".class")
            || (!includeBridge && name.startsWith(
                "dev/xtrace/agent/bootstrap/BootstrapBridge"))) continue;
        jar.putNextEntry(new JarEntry(name));
        Files.copy(file, jar);
        jar.closeEntry();
      }
    }
  }

  private static void writeFakeRuntimeJar(Path target) throws Exception {
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(target))) {
      addClass(jar, AgentRuntime.class, "dev/xtrace/agent/runtime/AgentRuntime.class");
      addClass(
          jar,
          AgentRuntime.StartFailure.class,
          "dev/xtrace/agent/runtime/AgentRuntime$StartFailure.class");
    }
  }

  private static void addClass(JarOutputStream jar, Class<?> type, String entry) throws Exception {
    try (var input = type.getResourceAsStream("/" + entry)) {
      if (input == null) throw new AssertionError("the test runtime class is unavailable");
      jar.putNextEntry(new JarEntry(entry));
      input.transferTo(jar);
      jar.closeEntry();
    }
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
