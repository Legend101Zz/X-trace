package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import dev.xtrace.agent.bootstrap.MethodIdentity;
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
    Map<String, byte[]> originals = new HashMap<>();
    for (String name : names) {
      TypeDescription type = TypePool.Default.of(parent).describe(PKG + name).resolve();
      byte[] original =
          ClassFileLocator.ForClassLoader.of(parent).locate(PKG + name).resolve();
      var lines = probes
          ? new LineProbeAsmWrapper(
              LineProbeConfig.focused(FixtureInstrumentation.PROBE_OWNER),
              registry,
              t -> null,
              reports::addAll,
              // Production passes null (bootstrap loader); the unit test classpath has the
              // bridge on the application loader.
              getClass().getClassLoader())
          : null;
      var builder = new ByteBuddy()
          .redefine(type, ClassFileLocator.ForClassLoader.of(parent))
          .visit(FixtureInstrumentation.boundedProbes(
              lines, new FixtureInstrumentation.CaptureLimitations(), new java.util.HashSet<>()));
      definitions.put(PKG + name, builder.make().getBytes());
      originals.put(PKG + name, original);
    }
    loader = new Isolated(parent, definitions);
    // Production observes the input bytes under the application's defining loader.
    for (var original : originals.entrySet()) {
      SourceIdentity.observe(
          loader, original.getKey().replace('.', '/'), original.getValue(),
          List.of("src/test/java"), Path.of(System.getProperty("user.dir", ".")));
    }
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
  void branchesAndLoopEmitOnlyExecutedLinesInExecutionOrder() throws Exception {
    load(true, "BranchLoop");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    Object target = loader.loadClass(PKG + "BranchLoop").getDeclaredConstructor().newInstance();
    var sum = target.getClass().getMethod("sum", int.class);
    assertTrue(BootstrapBridge.requestStart("GET", "/sum"));
    assertEquals(1, sum.invoke(target, 3));
    assertEquals(0, sum.invoke(target, 0));
    BootstrapBridge.requestEnd(200, false);

    List<RecordingEvent> lines = drain().stream()
        .filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR)
        .toList();
    // javac's LineNumberTable: the loop header repeats, each branch runs only when selected,
    // and the zero-iteration call never reaches the body. A method extent cannot satisfy this.
    assertEquals(
        List.of(5, 6, 7, 8, 9, 13, 7, 8, 11, 13, 7, 8, 9, 13, 7, 15, 5, 6, 7, 15),
        lines.stream().map(e -> e.getSource().getStartLine()).toList(), diagnostics());
    for (RecordingEvent line : lines) {
      assertEquals(MethodIdentity.symbol("demo.probe.BranchLoop", "sum", "(I)I"), line.getSymbol());
      assertEquals(line.getSource().getStartLine(), line.getSource().getEndLine());
      assertEquals(SourceBinding.SOURCE_BINDING_OBSERVED_UNATTESTED, line.getSourceBinding());
      assertFalse(line.getParentEventId().isEmpty());
    }
    assertEquals(0, lineSink.linesWithoutSource());
    assertEquals(0, lineSink.linesRejected());
  }

  @Test
  void focusedAccessorsAndLambdasParentEveryCursorToTheirOwnObservedEntry() throws Exception {
    load(true, "CursorParents");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    Class<?> type = loader.loadClass(PKG + "CursorParents");
    String getter = MethodIdentity.symbol(type.getName(), "getName", "()Ljava/lang/String;");
    String reader = MethodIdentity.symbol(type.getName(), "readName", "()Ljava/lang/String;");
    Object target = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("GET", "/parents"));
    type.getMethod("setName", String.class).invoke(target, "updated");
    assertEquals("updated", type.getMethod("getName").invoke(target));
    assertEquals(true, type.getMethod("isReady").invoke(target));
    assertEquals("updated", type.getMethod("readName").invoke(target));
    assertEquals("updated", type.getMethod("getViaLambda").invoke(target));
    assertEquals("cursor-parent", type.getMethod("toString").invoke(target));
    var failure = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> type.getMethod("getBroken").invoke(target));
    assertEquals(IllegalStateException.class, failure.getCause().getClass());
    assertEquals("updated", type.getMethod("getName").invoke(target));
    BootstrapBridge.requestEnd(200, false);

    Map<String, RecordingEvent> entries = new HashMap<>();
    java.util.Set<String> cursorMethods = new java.util.HashSet<>();
    boolean nestedGetter = false;
    boolean observedThrow = false;
    for (RecordingEvent event : drain()) {
      if (event.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER) {
        entries.put(event.getEventId(), event);
        if (event.getSymbol().equals(getter)) {
          RecordingEvent caller = entries.get(event.getParentEventId());
          nestedGetter |= caller != null && caller.getSymbol().equals(reader);
        }
      }
      if (event.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR) {
        RecordingEvent parent = entries.get(event.getParentEventId());
        assertNotNull(parent, "cursor needs an earlier method entry: " + event.getSymbol());
        assertEquals(event.getSymbol(), parent.getSymbol(), "a caller's extent cannot stand in");
        assertTrue(parent.hasSource());
        assertEquals(parent.getSource().getPath(), event.getSource().getPath());
        assertTrue(event.getSource().getStartLine() >= parent.getSource().getStartLine());
        assertTrue(event.getSource().getStartLine() <= parent.getSource().getEndLine());
        cursorMethods.add(event.getSymbol());
      }
      if (event.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW) {
        observedThrow |= event.getSymbol().equals(
            MethodIdentity.symbol(type.getName(), "getBroken", "()Ljava/lang/String;"));
      }
    }
    for (String method : List.of("setName", "getName", "isReady", "readName", "getViaLambda",
        "toString", "getBroken")) {
      var reflected = method.equals("setName") ? type.getMethod(method, String.class) : type.getMethod(method);
      assertTrue(cursorMethods.contains(MethodIdentity.symbol(type.getName(), method,
          net.bytebuddy.jar.asm.Type.getMethodDescriptor(reflected))), method);
    }
    assertTrue(cursorMethods.stream().anyMatch(symbol -> symbol.startsWith("CursorParents.lambda$")));
    assertTrue(nestedGetter, "nested accessor entry keeps the observed caller");
    assertTrue(observedThrow, "throwing accessor unwinds its own frame");
    assertEquals(0, lineSink.linesWithoutSource());
    assertEquals(0, lineSink.linesRejected());
  }

  @Test
  void aCursorCannotBorrowAnAcceptedEntryOfADifferentOverloadOnTheSameLine() throws Exception {
    load(true, "LambdaOrders");
    Class<?> type = loader.loadClass(PKG + "LambdaOrders");
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    String callerDescriptor = "(Ljava/lang/String;)Ljava/lang/String;";
    int overlappingLine = SourceIdentity.lookup(type, "create", callerDescriptor).startLine();
    assertTrue(overlappingLine > 0);
    int calleeSite = registry.addSite("demo/probe/LambdaOrders", null, "create", "(I)I", overlappingLine);
    int valueName = registry.addName("value", "Ljava/lang/String;", 1);
    assertTrue(BootstrapBridge.requestStart("GET", "/overloads"));
    String caller = BootstrapBridge.frameEnter(type, "create", callerDescriptor);
    assertNotNull(caller);
    // Simulate a callee whose boundary is absent altogether. The top frame is accepted but has
    // the wrong descriptor; the overlapping source line and simple method name cannot prove it.
    BootstrapBridge.line(calleeSite);
    BootstrapBridge.valuesBegin(calleeSite);
    BootstrapBridge.valueRef(valueName, 3, "WITHHELD-CURSOR-VALUE");
    BootstrapBridge.valuesEnd();
    BootstrapBridge.frameExit(caller, null);
    BootstrapBridge.requestEnd(200, false);
    List<QueueSignal> captured = new ArrayList<>();
    drainPressure(queue, captured);
    assertTrue(captured.stream().filter(QueueSignal.Event.class::isInstance)
        .map(QueueSignal.Event.class::cast).noneMatch(event -> event.kind() == BridgeEventKind.LINE_CURSOR));
    assertFalse(captured.toString().contains("WITHHELD-CURSOR-VALUE"));
    QueueSignal.Finish finish = captured.stream().filter(QueueSignal.Finish.class::isInstance)
        .map(QueueSignal.Finish.class::cast).findFirst().orElseThrow();
    assertEquals(1, finish.droppedEvents(), "the withheld cursor is missing evidence");
  }

  @Test
  void rejectedAccessorEntryCannotBorrowItsCallerAfterQueueCapacityRecovers() throws Exception {
    rejectEntryThenRecover("readName", "getName");
  }

  @Test
  void rejectedLambdaEntryWithholdsItsCursorsAndValuesAfterQueueCapacityRecovers() throws Exception {
    rejectEntryThenRecover("getViaLambda", "lambda$");
  }

  private void rejectEntryThenRecover(String caller, String rejectedMethod) throws Exception {
    load(true, "CursorParents");
    Class<?> type = loader.loadClass(PKG + "CursorParents");
    Object target = type.getConstructor().newInstance();
    BoundedEventQueue pressure = new BoundedEventQueue(16, 1024 * 1024);
    RuntimeBridgeSink recovering = new RuntimeBridgeSink(pressure);
    LineProbeBridgeSink recoveringLines = new LineProbeBridgeSink(recovering, registry);
    List<QueueSignal> captured = new ArrayList<>();
    boolean[] rejected = {false};
    BridgeSink bridge = new BridgeSink() {
      @Override
      public boolean offerStart(String id, long time, String method, String route) {
        return recovering.offerStart(id, time, method, route);
      }

      @Override
      public boolean offerEvent(String recording, String id, String parent, int kind,
          String symbol, long time, int detail) {
        return recovering.offerEvent(recording, id, parent, kind, symbol, time, detail);
      }

      @Override
      public boolean offerFrameEvent(String recording, String id, String parent, int kind,
          String symbol, long time, int detail, Class<?> declaring, String method, String descriptor) {
        if (!rejected[0] && method.startsWith(rejectedMethod)) {
          // Real queue rejection, then release capacity before the method's first cursor. No
          // writer timing or sleeps: the pre-fix cursor would now persist under the caller.
          int filler = 0;
          while (recovering.offerEvent(recording, "filler-" + filler++, "", BridgeEventKind.DATABASE_START,
              "queue-pressure", time, 0)) { }
          assertFalse(recovering.offerFrameEvent(recording, id, parent, kind, symbol,
              time, detail, declaring, method, descriptor));
          rejected[0] = true;
          drainPressure(pressure, captured);
          return false;
        }
        return recovering.offerFrameEvent(recording, id, parent, kind, symbol,
            time, detail, declaring, method, descriptor);
      }

      @Override
      public boolean offerFinish(String id, long started, long finished, int status, long dropped) {
        return recovering.offerFinish(id, started, finished, status, dropped);
      }

      @Override
      public void reportIncomplete(int kind) { fail("lifecycle admission must remain available"); }
    };
    BootstrapBridge.disable(sink);
    assertTrue(BootstrapBridge.install(bridge));
    assertTrue(BootstrapBridge.installLineSink(recoveringLines));
    try {
      assertTrue(BootstrapBridge.requestStart("GET", "/queue-recovery"));
      assertEquals("initial", type.getMethod(caller).invoke(target));
      drainPressure(pressure, captured);
      assertTrue(rejected[0]);
      // The same accessor/lambda can subsequently get its own accepted entry and cursors.
      assertEquals("initial", type.getMethod(caller).invoke(target));
      drainPressure(pressure, captured);
      BootstrapBridge.requestEnd(200, false);
      drainPressure(pressure, captured);
      Map<String, QueueSignal.Event> entries = new HashMap<>();
      int recoveredCursors = 0;
      for (QueueSignal signal : captured) {
        if (!(signal instanceof QueueSignal.Event event)) continue;
        if (event.kind() == BridgeEventKind.FRAME_ENTER) entries.put(event.eventId(), event);
        if (event.kind() != BridgeEventKind.LINE_CURSOR) continue;
        QueueSignal.Event parent = entries.get(event.parentEventId());
        assertNotNull(parent, "every persisted cursor requires an accepted method entry");
        assertEquals(parent.symbol(), event.symbol(), "a rejected entry cannot borrow its caller");
        if (event.symbol().startsWith("CursorParents." + rejectedMethod)) recoveredCursors++;
      }
      assertTrue(recoveredCursors > 0, "capture must recover after the missing entry has unwound");
      QueueSignal.Finish finish = captured.stream().filter(QueueSignal.Finish.class::isInstance)
          .map(QueueSignal.Finish.class::cast).findFirst().orElseThrow();
      assertTrue(finish.droppedEvents() >= 2, "count both the missing entry and withheld cursor evidence");
    } finally {
      if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, true);
      BootstrapBridge.disableLineSink(recoveringLines);
      BootstrapBridge.disable(bridge);
    }
  }

  private static void drainPressure(BoundedEventQueue pressure, List<QueueSignal> captured) {
    try {
      QueueSignal signal;
      while ((signal = pressure.poll(Duration.ZERO)) != null) captured.add(signal);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    }
  }

  @Test
  void webAnnotatedAccessorShapedHandlersAreProbedButPlainAccessorsAreNot() throws Exception {
    var matcher = FixtureInstrumentation.frameMethods();
    var methods =
        net.bytebuddy.description.type.TypeDescription.ForLoadedType.of(demo.probe.Accessors.class)
            .getDeclaredMethods();
    java.util.Map<String, Boolean> probed = new java.util.HashMap<>();
    for (var method : methods) probed.put(method.getName(), matcher.matches(method));
    assertEquals(true, probed.get("getAllOwners"), "annotated handler is probed");
    assertEquals(false, probed.get("getName"));
    assertEquals(false, probed.get("isReady"));
    assertEquals(false, probed.get("setName"));
    var focused = FixtureInstrumentation.frameMethods(true);
    methods.stream().filter(method -> !method.isConstructor())
        .forEach(method -> assertTrue(focused.matches(method), method.getName()));
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
    // The last accepted event keeps only its own iteration's locals: ignored sites attach nothing.
    RecordingEvent last =
        events.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR)
            .reduce((a, b) -> b).orElseThrow();
    java.util.Set<String> names = new java.util.HashSet<>();
    for (ValueBinding b : last.getBindingsList()) {
      assertTrue(names.add(b.getName()), "duplicate local on the last line cursor: " + b.getName());
    }
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
