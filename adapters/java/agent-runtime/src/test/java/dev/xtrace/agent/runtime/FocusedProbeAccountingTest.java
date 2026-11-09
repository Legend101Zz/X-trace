package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Recording.GapReason;

/** Real composed probes: class loading is not evidence that a request entered a skipped method. */
class FocusedProbeAccountingTest {
  private final BoundedEventQueue queue = new BoundedEventQueue(1024, 1024 * 1024);
  private final RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
  private final FixtureInstrumentation.LineProbes probes =
      new FixtureInstrumentation.LineProbes(new SiteRegistry());

  @BeforeEach
  void install() {
    sink.useLineProbes(probes);
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void close() {
    if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, true);
    BootstrapBridge.disable(sink);
  }

  private Class<?> load(String name, boolean stripDebug) throws Exception {
    ClassLoader parent = getClass().getClassLoader();
    byte[] bytes = ClassFileLocator.ForClassLoader.of(parent).locate(name).resolve();
    if (stripDebug) {
      ClassWriter writer = new ClassWriter(0);
      new ClassReader(bytes).accept(writer, ClassReader.SKIP_DEBUG);
      bytes = writer.toByteArray();
    }
    var locator = new ClassFileLocator.Compound(ClassFileLocator.Simple.of(name, bytes),
        ClassFileLocator.ForClassLoader.of(parent));
    class Isolated extends ClassLoader {
      Isolated() { super(parent); }
      Class<?> define(byte[] transformed) { return defineClass(name, transformed, 0, transformed.length); }
    }
    Isolated loader = new Isolated();
    byte[] transformed = new ByteBuddy().redefine(TypePool.Default.of(locator).describe(name).resolve(), locator)
        .visit(Advice.to(FixtureInstrumentation.FrameAdvice.class).on(FixtureInstrumentation.frameMethods()))
        .visit(Advice.to(FixtureInstrumentation.LineGapAdvice.class).on(FixtureInstrumentation.lineGapMethods()))
        .visit(probes.wrapper(name, loader, parent)).make().getBytes();
    return loader.define(transformed);
  }

  private List<QueueSignal.Event> events() throws Exception {
    List<QueueSignal.Event> result = new ArrayList<>();
    QueueSignal signal;
    while ((signal = queue.poll(Duration.ZERO)) != null) {
      if (signal instanceof QueueSignal.Event event) result.add(event);
    }
    return result;
  }

  @Test
  void unusedSkippedMethodsDoNotMakeAnUnrelatedRequestPartial() throws Exception {
    Class<?> missing = load("demo.probe.Orders", true);
    Object instance = missing.getConstructor().newInstance();
    // Even invocation outside capture is not a gap in a later request.
    missing.getMethod("create", String.class).invoke(instance, "outside");
    assertTrue(events().isEmpty());
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("create")
        && report.reason().equals(dev.xtrace.agent.runtime.line.MethodReport.Reasons.NO_LINE_TABLE)),
        "the skipped-method limitation remains in the transformation report");
    assertTrue(probes.unavailable(missing, "create", "(Ljava/lang/String;)Ljava/lang/String;"));
    Class<?> healthy = load("demo.probe.Secrets", false);
    Object controller = healthy.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("GET", "/healthy"));
    healthy.getMethod("login", String.class, String.class).invoke(controller, "ada", "secret");
    BootstrapBridge.requestEnd(200, false);
    List<QueueSignal.Event> captured = events();
    assertTrue(captured.stream().anyMatch(e -> e.kind() == BridgeEventKind.FRAME_ENTER));
    assertTrue(captured.stream().noneMatch(e -> e.kind() == BridgeEventKind.GAP));
  }

  @Test
  void skippedMetadataFromAnotherLoaderCannotMakeThisMethodPartial() throws Exception {
    Class<?> missing = load("demo.probe.Orders", true);
    Class<?> healthy = load("demo.probe.Orders", false);
    String descriptor = "(Ljava/lang/String;)Ljava/lang/String;";
    assertTrue(probes.unavailable(missing, "create", descriptor));
    assertFalse(probes.unavailable(healthy, "create", descriptor));
    assertFalse(probes.unavailable(missing, "create", "(I)I"), "overloads keep their own metadata");
    Object instance = healthy.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/healthy"));
    assertEquals("ABC", healthy.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    assertTrue(events().stream().noneMatch(e -> e.kind() == BridgeEventKind.GAP));
  }

  @Test
  void anEnteredSkippedMethodHasAnHonestGapAndNoInventedLine() throws Exception {
    Class<?> missing = load("demo.probe.Orders", true);
    Object instance = missing.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/missing"));
    assertEquals("ABC", missing.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    List<QueueSignal.Event> captured = events();
    var gaps = captured.stream().filter(e -> e.kind() == BridgeEventKind.GAP).toList();
    assertEquals(2, gaps.size(), "create and its nested place call both lack line tables");
    for (var gap : gaps) {
      assertEquals(RecordingWriter.UNTRANSFORMED_GAP_SYMBOL, gap.symbol());
      var wire = RecordingWriter.toProto(gap, 2);
      assertEquals(GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED, wire.getGap().getReason());
      assertEquals(1, wire.getGap().getCount());
    }
    assertTrue(captured.stream().noneMatch(e -> e.kind() == BridgeEventKind.LINE_CURSOR));
  }
}
