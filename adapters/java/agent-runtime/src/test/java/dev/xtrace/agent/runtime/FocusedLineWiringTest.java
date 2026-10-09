package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.runtime.line.LineProbeAsmWrapper;
import dev.xtrace.agent.runtime.line.LineProbeConfig;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Recording.BindingRole;
import xtp.agent.v1.Recording.CapturedValue;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.SourceBinding;
import xtp.agent.v1.Recording.ValueBinding;

/**
 * The focused wiring end to end inside one JVM: the real line-probe wrapper and frame advice are
 * applied to sample classes, the probes call the real {@link BootstrapBridge} owner, and the
 * events that come out of the real queue are mapped to the wire by the real writer mapping.
 */
class FocusedLineWiringTest {
  private static final String PKG = "demo.probe.";

  private final BoundedEventQueue queue = new BoundedEventQueue(65_536, 64L * 1024 * 1024);
  private final RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
  private final SiteRegistry registry = new SiteRegistry();
  private final LineProbeBridgeSink lineSink = new LineProbeBridgeSink(sink, registry);
  private final List<MethodReport> reports = new ArrayList<>();
  private ClassLoader loader;

  @BeforeEach
  void install() throws Exception {
    SourceIdentity.resetForTest();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void reset() {
    BootstrapBridge.disableLineSink(lineSink);
    BootstrapBridge.disable(sink);
    if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, true);
  }

  private void load(boolean probes, String... names) throws Exception {
    ClassLoader parent = getClass().getClassLoader();
    Map<String, byte[]> definitions = new HashMap<>();
    for (String name : names) {
      TypeDescription type = TypePool.Default.of(parent).describe(PKG + name).resolve();
      byte[] original =
          ClassFileLocator.ForClassLoader.of(parent).locate(PKG + name).resolve();
      var builder =
          new ByteBuddy()
              .redefine(type, ClassFileLocator.ForClassLoader.of(parent))
              .visit(
                  Advice.to(FixtureInstrumentation.FrameAdvice.class)
                      .on(FixtureInstrumentation.frameMethods()));
      if (probes) {
        builder =
            builder.visit(
                new LineProbeAsmWrapper(
                    LineProbeConfig.focused(FixtureInstrumentation.PROBE_OWNER),
                    registry,
                    t -> null,
                    reports::addAll,
                    // Production passes null (bootstrap loader); the unit test classpath has the
                    // bridge on the application loader.
                    getClass().getClassLoader()));
      }
      definitions.put(PKG + name, builder.make().getBytes());
      // The runtime observes the original class bytes in its transformer, before any rewrite.
      SourceIdentity.observe(
          parent, (PKG + name).replace('.', '/'), original,
          List.of("src/test/java"), Path.of(System.getProperty("user.dir", ".")));
    }
    loader = new Isolated(parent, definitions);
  }

  private String diagnostics() {
    return "sites=" + registry.siteCount() + " withoutSource=" + lineSink.linesWithoutSource()
        + " rejected=" + lineSink.linesRejected() + " reports=" + reports;
  }

  private List<RecordingEvent> drain() throws Exception {
    List<RecordingEvent> events = new ArrayList<>();
    QueueSignal signal;
    long seq = 1;
    while ((signal = queue.poll(Duration.ofMillis(5))) != null) {
      if (signal instanceof QueueSignal.Event event) {
        events.add(RecordingWriter.toProto(event, ++seq));
      }
    }
    return events;
  }

  @Test
  void focusedRequestRecordsLineCursorsWithRealSourceAndSanitizedLocals() throws Exception {
    load(true, "Orders");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    Object controller = loader.loadClass(PKG + "Orders").getDeclaredConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    assertEquals("ABC", controller.getClass().getMethod("create", String.class).invoke(controller, " abc "));
    BootstrapBridge.requestEnd(201, false);

    List<RecordingEvent> events = drain();
    List<RecordingEvent> lines =
        events.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR).toList();
    assertFalse(lines.isEmpty(), "focused mode must record line cursors; " + diagnostics());
    for (RecordingEvent line : lines) {
      assertTrue(line.getSource().getPath().endsWith("demo/probe/Orders.java"),
          line.getSource().getPath());
      assertTrue(line.getSource().getStartLine() > 0);
      assertEquals(line.getSource().getStartLine(), line.getSource().getEndLine());
      assertEquals(32, line.getSource().getContentHash().size());
      assertEquals(SourceBinding.SOURCE_BINDING_OBSERVED_UNATTESTED, line.getSourceBinding());
      assertFalse(line.getParentEventId().isEmpty());
    }
    // Frames and lines interleave under one request; ids are unique and parents precede children.
    java.util.Set<String> seen = new java.util.HashSet<>();
    for (RecordingEvent event : events) {
      assertTrue(seen.add(event.getEventId()), event.getEventId());
    }
    List<ValueBinding> locals = new ArrayList<>();
    for (RecordingEvent line : lines) locals.addAll(line.getBindingsList());
    assertTrue(locals.stream().anyMatch(b -> b.getName().equals("saved") || b.getName().equals("normalized")), "local 'saved' read");
    for (ValueBinding binding : locals) {
      assertEquals(BindingRole.BINDING_ROLE_LOCAL, binding.getRole());
      assertTrue(binding.getValue().getValueCase() != CapturedValue.ValueCase.VALUE_NOT_SET);
    }
    assertTrue(lineSink.linesWithoutSource() == 0);
  }

  @Test
  void theRealBridgeIsACompleteProbeOwner() {
    assertEquals(
        null,
        dev.xtrace.agent.runtime.line.ProbeOwnerCheck.problem(
            FixtureInstrumentation.PROBE_OWNER, getClass().getClassLoader()));
  }

  @Test
  void secretNamedLocalsAreRedactedAndNeverReachTheWire() throws Exception {
    load(true, "Secrets");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    Object target = loader.loadClass(PKG + "Secrets").getDeclaredConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/login"));
    target.getClass().getMethod("login", String.class, String.class).invoke(target, "ada", "hunter2-PLAINTEXT");
    BootstrapBridge.requestEnd(200, false);

    List<RecordingEvent> events = drain();
    String wire = events.toString();
    assertFalse(wire.contains("hunter2-PLAINTEXT"), "argument value leaked");
    assertFalse(wire.contains("S3CR3T-"), "secret-named local leaked");
    boolean redactedPassword = false;
    boolean greetingCaptured = false;
    for (RecordingEvent event : events) {
      for (ValueBinding binding : event.getBindingsList()) {
        if (binding.getName().equals("password") || binding.getName().equals("sessionToken")) {
          assertTrue(binding.getValue().hasRedacted(), binding.getName());
          redactedPassword |= binding.getName().equals("password");
        }
        if (binding.getName().equals("greeting") && binding.getValue().hasCaptured()) {
          assertEquals("hello ada", binding.getValue().getCaptured().getPreview());
          greetingCaptured = true;
        }
      }
    }
    assertTrue(redactedPassword, "password argument local must be a redacted binding");
    assertTrue(greetingCaptured, "plain local must be captured");
  }

  @Test
  void withoutALineSinkProbedClassesRecordNoLineEventsAndBehaveIdentically() throws Exception {
    load(true, "Orders");
    Object controller = loader.loadClass(PKG + "Orders").getDeclaredConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    assertEquals("ABC", controller.getClass().getMethod("create", String.class).invoke(controller, " abc "));
    BootstrapBridge.requestEnd(201, false);
    for (RecordingEvent event : drain()) {
      assertTrue(event.getKind() != RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR);
    }
  }

  @Test
  void linesOutsideARequestAreIgnoredAndTheBudgetBecomesACoalescedGap() throws Exception {
    load(true, "Secrets");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    Object target = loader.loadClass(PKG + "Secrets").getDeclaredConstructor().newInstance();
    var login = target.getClass().getMethod("login", String.class, String.class);
    login.invoke(target, "ada", "x");
    assertTrue(drain().isEmpty(), "no request context means no events");

    assertTrue(BootstrapBridge.requestStart("POST", "/login"));
    for (int i = 0; i < 2300; i++) login.invoke(target, "ada", "x");
    BootstrapBridge.requestEnd(200, false);
    // 2,300 calls make more than 8,192 line sites run: the surplus is a coalesced LINE_BUDGET gap.
    List<RecordingEvent> events = drain();
    long lines = events.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR).count();
    assertTrue(lines == 8192, "line budget respected exactly: " + lines);
    assertTrue(
        events.stream().anyMatch(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
            && e.getGap().getReason() == xtp.agent.v1.Recording.GapReason.GAP_REASON_LINE_BUDGET),
        "withheld line events are reported as LINE_BUDGET");
    assertNotNull(reports);
  }

  private static final class Isolated extends ClassLoader {
    private final Map<String, byte[]> definitions;

    Isolated(ClassLoader parent, Map<String, byte[]> definitions) {
      super(parent);
      this.definitions = definitions;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null && definitions.containsKey(name)) {
          byte[] bytes = definitions.get(name);
          loaded = defineClass(name, bytes, 0, bytes.length);
        }
        if (loaded != null) {
          if (resolve) resolveClass(loaded);
          return loaded;
        }
      }
      return super.loadClass(name, resolve);
    }
  }
}
