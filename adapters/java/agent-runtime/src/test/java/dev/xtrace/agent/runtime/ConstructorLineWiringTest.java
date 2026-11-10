package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.MethodIdentity;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.ProbeEligibility;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.RecordingEventKind;

/** Constructor bodies use real frames; omitted delegation and initializer lines are explicit gaps. */
class ConstructorLineWiringTest {
  private static final String NAME = "demo.probe.ConstructorCases";
  private final BoundedEventQueue queue = new BoundedEventQueue(4096, 4 * 1024 * 1024);
  private final RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
  private final SiteRegistry registry = new SiteRegistry();
  private final LineProbeBridgeSink lineSink = new LineProbeBridgeSink(sink, registry);
  private final FixtureInstrumentation.CaptureLimitations limitations =
      new FixtureInstrumentation.CaptureLimitations();
  private final FixtureInstrumentation.LineProbes probes =
      new FixtureInstrumentation.LineProbes(registry, limitations);
  private final Map<String, byte[]> definitions = new HashMap<>();
  private final Map<String, java.util.Set<String>> methodSymbols = new HashMap<>();
  private Class<?> driver;

  @BeforeEach
  void install() throws Exception {
    SourceIdentity.resetForTest();
    sink.untransformedCount(limitations::count);
    assertTrue(BootstrapBridge.install(sink));
    assertTrue(BootstrapBridge.installLineSink(lineSink));
    ClassLoader parent = getClass().getClassLoader();
    ClassLoader isolated = new ClassLoader(parent) {
      @Override
      protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        byte[] bytes = definitions.get(name);
        if (bytes == null) return super.loadClass(name, resolve);
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) loaded = defineClass(name, bytes, 0, bytes.length);
        if (resolve) resolveClass(loaded);
        return loaded;
      }
    };
    var locator = ClassFileLocator.ForClassLoader.of(parent);
    List<String> names = new ArrayList<>();
    for (String suffix : List.of("", "$Base", "$Chain", "$BodyThrow", "$SuperThrow",
        "$ArgumentThrow", "$Initializer", "$UntracedBase", "$UntracedSuperThrow",
        "$AllocatedArgument", "$BranchedArgument")) names.add(NAME + suffix);
    names.add("demo.probe.CursorParents");
    for (String name : names) {
      byte[] original = locator.locate(name).resolve();
      definitions.put(name, name.equals(NAME + "$UntracedBase") ? original
          : new ByteBuddy().redefine(TypePool.Default.of(parent).describe(name).resolve(), locator)
          .visit(FixtureInstrumentation.applicationProbes(isolated, probes, limitations))
          .make().getBytes());
      SourceIdentity.observe(isolated, name.replace('.', '/'), original,
          List.of("src/test/java"), Path.of(System.getProperty("user.dir", ".")));
      new ClassReader(original).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String method, String descriptor,
            String signature, String[] exceptions) {
          String readable = name.substring(name.lastIndexOf('.') + 1) + "." + method;
          methodSymbols.computeIfAbsent(readable, ignored -> new java.util.HashSet<>())
              .add(MethodIdentity.symbol(name, method, descriptor));
          return null;
        }
      }, ClassReader.SKIP_CODE);
    }
    driver = Class.forName(NAME, true, isolated);
    assertEquals(0, limitations.count());
  }

  @AfterEach
  void close() {
    if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, true);
    BootstrapBridge.disableLineSink(lineSink);
    BootstrapBridge.disable(sink);
  }

  private Object invoke(String method) throws Exception {
    return driver.getMethod(method).invoke(null);
  }

  private List<RecordingEvent> finish() throws Exception {
    BootstrapBridge.requestEnd(200, false);
    List<RecordingEvent> events = new ArrayList<>();
    QueueSignal signal;
    long sequence = 0;
    while ((signal = queue.poll(Duration.ZERO)) != null) {
      if (signal instanceof QueueSignal.Event event) events.add(RecordingWriter.toProto(event, ++sequence));
    }
    Map<String, RecordingEvent> entries = new HashMap<>();
    ArrayDeque<String> stack = new ArrayDeque<>();
    for (RecordingEvent event : events) {
      switch (event.getKind()) {
        case RECORDING_EVENT_KIND_FRAME_ENTER -> {
          if (!stack.isEmpty()) assertEquals(stack.peek(), event.getParentEventId(), event.getSymbol());
          entries.put(event.getEventId(), event);
          stack.push(event.getEventId());
        }
        case RECORDING_EVENT_KIND_FRAME_EXIT, RECORDING_EVENT_KIND_FRAME_THROW -> {
          assertFalse(stack.isEmpty(), event.getSymbol());
          assertEquals(stack.pop(), event.getParentEventId(), event.getSymbol());
        }
        case RECORDING_EVENT_KIND_LINE_CURSOR -> {
          assertFalse(stack.isEmpty(), event.getSymbol());
          assertEquals(stack.peek(), event.getParentEventId(), event.getSymbol());
          RecordingEvent entry = entries.get(event.getParentEventId());
          assertNotNull(entry);
          assertEquals(event.getSymbol(), entry.getSymbol(), "never borrow the caller's boundary");
          assertTrue(entry.hasSource());
          assertEquals(entry.getSource().getPath(), event.getSource().getPath());
          // Overloaded constructors have distinct identities and observed source extents.
          assertTrue(event.getSource().getStartLine() >= entry.getSource().getStartLine());
          assertTrue(event.getSource().getStartLine() <= entry.getSource().getEndLine());
        }
        default -> { }
      }
    }
    assertTrue(stack.isEmpty(), "every observed entry must close before request completion");
    assertEquals(0, lineSink.linesRejected());
    assertEquals(0, lineSink.linesWithoutSource());
    return events;
  }

  private long count(List<RecordingEvent> events, RecordingEventKind kind, String symbol) {
    return events.stream().filter(e -> e.getKind() == kind && matches(e, symbol)).count();
  }

  private boolean matches(RecordingEvent event, String readable) {
    return methodSymbols.getOrDefault(readable, java.util.Set.of()).contains(event.getSymbol());
  }

  private void assertGap(List<RecordingEvent> events) {
    assertTrue(events.stream().anyMatch(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
        && e.getSymbol().equals(RecordingWriter.UNTRANSFORMED_GAP_SYMBOL)));
  }

  @Test
  void thisDelegationChainAndComputedSuperArgumentsKeepEachBodyAndNestedConstructionBalanced() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/construct"));
    assertEquals(36, invoke("normal"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(3, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, "ConstructorCases$Chain.<init>"));
    assertEquals(3, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT, "ConstructorCases$Chain.<init>"));
    assertEquals(2, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, "ConstructorCases$Base.<init>"));
    assertTrue(count(events, RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR, "ConstructorCases$Chain.<init>") >= 3);
    assertTrue(count(events, RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR, "ConstructorCases$Base.<init>") >= 2);
    assertTrue(count(events, RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR, "ConstructorCases.compute") > 0);
    var nested = events.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER
        && matches(e, "ConstructorCases$Base.<init>")).toList().get(1);
    assertTrue(events.stream().anyMatch(e -> e.getEventId().equals(nested.getParentEventId())
        && matches(e, "ConstructorCases$Chain.<init>")));
  }

  @Test
  void bodyThrowClosesItsConstructorAndLeavesTheNextMethodWithItsOwnParent() throws Exception {
    assertFailure("bodyFailure", IllegalStateException.class, "ConstructorCases$BodyThrow.<init>", true);
  }

  @Test
  void superThrowClosesTheSuperBodyWithoutOpeningADanglingDelegatingFrame() throws Exception {
    assertFailure("superFailure", IllegalArgumentException.class, "ConstructorCases$SuperThrow.<init>", false);
  }

  @Test
  void argumentThrowHasAnExplicitPreambleGapWithoutAConstructorCursorOrEntry() throws Exception {
    assertFailure("argumentFailure", UnsupportedOperationException.class, "ConstructorCases$ArgumentThrow.<init>", false);
  }

  @Test
  void uninstrumentedSuperThrowAlsoLeavesNoDanglingConstructorFrame() throws Exception {
    assertFailure("untracedSuperFailure", IllegalArgumentException.class, "ConstructorCases$UntracedSuperThrow.<init>", false);
  }

  @Test
  void allocatingTheSuperclassInItsArgumentsDoesNotMistakeThatCallForInitializingThis() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/allocated-argument"));
    assertEquals(4, invoke("allocatedSuperArgument"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, "ConstructorCases$AllocatedArgument.<init>"));
    Class<?> allocated = driver.getClassLoader().loadClass(NAME + "$AllocatedArgument");
    int delegationLine = SourceIdentity.lookup(allocated, "<init>", "()V").startLine();
    var cursors = events.stream().filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR
        && matches(e, "ConstructorCases$AllocatedArgument.<init>")).toList();
    assertFalse(cursors.isEmpty());
    assertTrue(cursors.stream().allMatch(e -> e.getSource().getStartLine() > delegationLine));
    assertEquals(2, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT, "ConstructorCases$Base.<init>"));
  }

  @Test
  void unsupportedBranchedPreamblesPreserveTheConstructorAndEmitOnlyAGapForItsLines() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/branched-argument"));
    assertEquals(3, invoke("branchedSuperArgument"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(0, count(events, RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR, "ConstructorCases$BranchedArgument.<init>"));
    assertEquals(0, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, "ConstructorCases$BranchedArgument.<init>"));
    assertTrue(probes.reports().stream().anyMatch(r -> r.name().equals("<init>")
        && r.reason().equals(MethodReport.Reasons.CONSTRUCTOR_PREAMBLE)));
  }

  @Test
  void anExceptionCaughtInsideTheConstructorKeepsItsBoundaryUntilNormalReturn() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/caught"));
    assertEquals(1, invoke("caughtBodyFailure"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT, "ConstructorCases$BodyThrow.<init>"));
    assertEquals(0, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW, "ConstructorCases$BodyThrow.<init>"));
  }

  private void assertFailure(String method, Class<? extends Throwable> failureType,
      String constructor, boolean bodyEntered) throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/throw"));
    InvocationTargetException failure = assertThrows(InvocationTargetException.class, () -> invoke(method));
    assertEquals(failureType, failure.getCause().getClass());
    if (method.equals("bodyFailure")) assertSame(driver.getField("BODY_FAILURE").get(null), failure.getCause());
    assertEquals(7, invoke("after"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(bodyEntered ? 1 : 0, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, constructor));
    assertEquals(bodyEntered ? 1 : 0, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW, constructor));
    assertEquals(bodyEntered, count(events, RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR, constructor) > 0);
    if (method.equals("superFailure")) {
      assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW, "ConstructorCases$Base.<init>"));
    }
    assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT, "ConstructorCases.after"));
  }

  @Test
  void staticInitializerLinesAreOmittedWithAnInvocationGap() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/initialize"));
    assertEquals(2, invoke("initialize"));
    assertEquals(7, invoke("after"));
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertTrue(events.stream().noneMatch(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_LINE_CURSOR
        && e.getSymbol().contains(".<clinit>#m1:")));
    assertTrue(probes.reports().stream().anyMatch(r -> r.name().equals("<clinit>")
        && r.reason().equals(MethodReport.Reasons.INITIALIZER)));
  }

  @Test
  void constructorWrapperRebuildsFramesWithoutTheLineOrBoundedWrapper() throws Exception {
    String name = NAME + "$BodyThrow";
    ClassLoader parent = getClass().getClassLoader();
    var locator = ClassFileLocator.ForClassLoader.of(parent);
    byte[] transformed = new ByteBuddy()
        .redefine(TypePool.Default.of(parent).describe(name).resolve(), locator)
        // A preceding wrapper must not prevent expanded input from reaching the constructor.
        .visit(new net.bytebuddy.asm.AsmVisitorWrapper.ForDeclaredMethods()
            .readerFlags(ClassReader.SKIP_FRAMES))
        .visit(new ConstructorProbeAsmWrapper())
        .make().getBytes();
    Class<?> type = new ClassLoader(parent) {
      Class<?> define() { return defineClass(name, transformed, 0, transformed.length); }
    }.define();
    var constructor = type.getConstructor(boolean.class, long.class);
    assertTrue(BootstrapBridge.requestStart("GET", "/constructor-frames"));
    Object normal = constructor.newInstance(false, -3L);
    assertEquals(1, type.getField("value").get(normal));
    var failure = assertThrows(InvocationTargetException.class,
        () -> constructor.newInstance(true, 3L));
    assertSame(demo.probe.ConstructorCases.BODY_FAILURE, failure.getCause());
    List<RecordingEvent> events = finish();
    assertGap(events);
    assertEquals(2, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER, "ConstructorCases$BodyThrow.<init>"));
    assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_EXIT, "ConstructorCases$BodyThrow.<init>"));
    assertEquals(1, count(events, RecordingEventKind.RECORDING_EVENT_KIND_FRAME_THROW, "ConstructorCases$BodyThrow.<init>"));
  }

  @Test
  void everyExecutableWithLineProbesAlsoHasItsOwnBoundaryAndExit() {
    for (var definition : definitions.entrySet()) {
      new ClassReader(definition.getValue()).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
            String signature, String[] exceptions) {
          return new MethodVisitor(Opcodes.ASM9) {
            int lines;
            int entries;
            int exits;
            @Override
            public void visitMethodInsn(int opcode, String owner, String method, String desc, boolean itf) {
              if (!owner.equals(FixtureInstrumentation.PROBE_OWNER)) return;
              if (method.equals("line")) lines++;
              if (method.equals("frameEnter") || method.equals("constructorEnter")) entries++;
              if (method.equals("frameExit") || method.equals("constructorExit")) exits++;
            }
            @Override
            public void visitEnd() {
              if (lines == 0) return;
              String location = definition.getKey() + "." + name + descriptor;
              assertNull(ProbeEligibility.exclusion(access, name), location);
              assertEquals(1, entries, location);
              assertTrue(exits > 0, location);
            }
          };
        }
      }, 0);
    }
  }
}
