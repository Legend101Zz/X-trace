package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import com.google.protobuf.Message;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;

/** Real composed probes: class loading is not evidence that a request entered a skipped method. */
class FocusedProbeAccountingTest {
  private final BoundedEventQueue queue = new BoundedEventQueue(1024, 1024 * 1024);
  private final RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
  private final FixtureInstrumentation.LineProbes probes =
      new FixtureInstrumentation.LineProbes(new SiteRegistry());
  private final Map<Class<?>, byte[]> transformedClasses = new ConcurrentHashMap<>();

  @BeforeEach
  void install() {
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
    return load(name, bytes);
  }

  private Class<?> load(String name, byte[] bytes) {
    return load(name, bytes, getClass().getClassLoader());
  }

  private Class<?> load(String name, byte[] bytes, ClassLoader ownerLoader) {
    ClassLoader parent = getClass().getClassLoader();
    var locator = new ClassFileLocator.Compound(ClassFileLocator.Simple.of(name, bytes),
        ClassFileLocator.ForClassLoader.of(parent));
    class Isolated extends ClassLoader {
      Isolated() { super(parent); }
      Class<?> define(byte[] transformed) { return defineClass(name, transformed, 0, transformed.length); }
    }
    Isolated loader = new Isolated();
    byte[] transformed = new ByteBuddy().redefine(TypePool.Default.of(locator).describe(name).resolve(), locator)
        .visit(Advice.to(FixtureInstrumentation.FrameAdvice.class).on(FixtureInstrumentation.frameMethods()))
        .visit(probes.wrapper(ownerLoader)).make().getBytes();
    Class<?> type = loader.define(transformed);
    transformedClasses.put(type, transformed);
    return type;
  }

  private int gapProbes(Class<?> type, String method, String descriptor) {
    int[] count = {0};
    new ClassReader(transformedClasses.get(type)).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String desc,
          String signature, String[] exceptions) {
        if (method != null && (!name.equals(method) || !desc.equals(descriptor))) return null;
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals(FixtureInstrumentation.PROBE_OWNER) && name.equals("lineGap")) count[0]++;
          }
        };
      }
    }, 0);
    return count[0];
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
    assertEquals(1, gapProbes(missing, "create", "(Ljava/lang/String;)Ljava/lang/String;"));
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
    assertEquals(1, gapProbes(missing, "create", descriptor));
    assertEquals(0, gapProbes(healthy, "create", descriptor));
    assertEquals(0, gapProbes(missing, "create", "(I)I"), "overloads keep their own metadata");
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

  @Test
  void enteredSkippedLambdaReachesTheRecordingAndPreventsComplete() throws Exception {
    String name = "demo.probe.LambdaOrders";
    byte[] original = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader())
        .locate(name).resolve();
    ClassWriter stripped = new ClassWriter(0);
    new ClassReader(original).accept(new ClassVisitor(Opcodes.ASM9, stripped) {
      @Override
      public MethodVisitor visitMethod(int access, String method, String descriptor,
          String signature, String[] exceptions) {
        MethodVisitor next = super.visitMethod(access, method, descriptor, signature, exceptions);
        if (!method.startsWith("lambda$")) return next;
        assertTrue((access & Opcodes.ACC_SYNTHETIC) != 0);
        return new MethodVisitor(Opcodes.ASM9, next) {
          @Override
          public void visitLineNumber(int line, Label start) {}
        };
      }
    }, 0);
    Class<?> type = load(name, stripped.toByteArray());
    var lambda = java.util.Arrays.stream(type.getDeclaredMethods())
        .filter(method -> method.isSynthetic() && method.getName().startsWith("lambda$"))
        .findFirst().orElseThrow();
    assertEquals(1, gapProbes(type, lambda.getName(),
        net.bytebuddy.jar.asm.Type.getMethodDescriptor(lambda)));
    assertEquals(0, gapProbes(type, "create", "(Ljava/lang/String;)Ljava/lang/String;"));
    assertEquals(0, gapProbes(type, "create", "(I)I"));
    var skipped = probes.reports().stream()
        .filter(report -> report.status() == MethodReport.Status.SKIPPED).toList();
    assertEquals(1, skipped.size(), "only the invoked lambda lacks line probes");
    assertEquals(lambda.getName(), skipped.get(0).name());
    assertEquals(MethodReport.Reasons.NO_LINE_TABLE, skipped.get(0).reason());
    Object instance = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/lambda"));
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    assertEquals(3, type.getMethod("create", int.class).invoke(instance, 3));
    BootstrapBridge.requestEnd(200, false);

    // Exercise the production writer, including the digest-covered wire gap. The store treats
    // any persisted GAP as Partial even when the request finished and its digest is valid.
    CapturedRecording transport = new CapturedRecording();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    writer.capturePolicy("xtrace.focused.v1");
    writer.start();
    writer.close();
    assertFalse(writer.incompleteWasReported());
    assertEquals(1, transport.starts.size());
    assertEquals(1, transport.finishes.size());
    var recorded = transport.batches.stream().flatMap(batch -> batch.getEventsList().stream()).toList();
    var gaps = recorded.stream().filter(event -> event.hasGap()).toList();
    assertEquals(1, gaps.size());
    assertEquals(GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED, gaps.get(0).getGap().getReason());
    assertEquals(1, gaps.get(0).getGap().getCount());
    assertTrue(recorded.stream().noneMatch(event -> event.getKindValue() == BridgeEventKind.LINE_CURSOR));
    assertArrayEquals(EventDigest.compute(
        recorded.stream().map(event -> event.getEventId()).toList()),
        transport.finishes.get(0).getEventDigest().toByteArray());
  }

  @Test
  void successfulReportOverflowLeavesHealthyRequestsGapFreeAndRealSkipsVisible() throws Exception {
    String name = "demo.probe.ManyHealthyMethods";
    ClassWriter bytes = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null, "java/lang/Object", null);
    int methods = FixtureInstrumentation.MAX_LINE_REPORTS + 8;
    for (int i = 0; i < methods; i++) {
      MethodVisitor method = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
          "healthy" + i, "()I", null, null);
      method.visitCode();
      Label line = new Label();
      method.visitLabel(line);
      method.visitLineNumber(i + 1, line);
      method.visitIntInsn(Opcodes.BIPUSH, 7);
      method.visitInsn(Opcodes.IRETURN);
      method.visitMaxs(0, 0);
      method.visitEnd();
    }
    bytes.visitEnd();
    Class<?> healthy = load(name, bytes.toByteArray());
    assertEquals(methods, healthy.getDeclaredMethods().length);
    assertEquals(methods, probes.registry().siteCount(), "every method received its line probe");
    assertEquals(FixtureInstrumentation.MAX_LINE_REPORTS, probes.reports().size());
    assertTrue(probes.reports().stream().allMatch(report -> report.status() == MethodReport.Status.INSTRUMENTED));
    assertEquals(0, gapProbes(healthy, null, null));

    // This skip occurs after the diagnostic buffer is already full.
    Class<?> missing = load("demo.probe.Orders", true);
    Object instance = missing.getConstructor().newInstance();
    assertEquals(FixtureInstrumentation.MAX_LINE_REPORTS, probes.reports().size());
    assertTrue(BootstrapBridge.requestStart("GET", "/healthy"));
    assertEquals(7, healthy.getMethod("healthy0").invoke(null));
    assertEquals(7, healthy.getMethod("healthy" + (methods - 1)).invoke(null));
    BootstrapBridge.requestEnd(200, false);
    List<QueueSignal.Event> healthyEvents = events();
    assertTrue(healthyEvents.stream().anyMatch(e -> e.kind() == BridgeEventKind.FRAME_ENTER));
    assertTrue(healthyEvents.stream().noneMatch(e -> e.kind() == BridgeEventKind.GAP));

    assertTrue(BootstrapBridge.requestStart("POST", "/missing"));
    assertEquals("ABC", missing.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    var gaps = events().stream().filter(e -> e.kind() == BridgeEventKind.GAP).toList();
    assertEquals(2, gaps.size());
    for (var gap : gaps) {
      assertEquals(GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED,
          RecordingWriter.toProto(gap, 2).getGap().getReason());
    }
  }

  @Test
  void concurrentTransformationsKeepSameNamedMethodsIndependentAcrossLoaders() throws Exception {
    var workers = Executors.newFixedThreadPool(2);
    try {
      var missingTask = workers.submit(() -> load("demo.probe.Orders", true));
      var healthyTask = workers.submit(() -> load("demo.probe.Orders", false));
      Class<?> missing = missingTask.get();
      Class<?> healthy = healthyTask.get();
      assertNotSame(missing.getClassLoader(), healthy.getClassLoader());
      for (Class<?> type : List.of(healthy, missing)) {
        Object instance = type.getConstructor().newInstance();
        assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
        assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
        BootstrapBridge.requestEnd(200, false);
        assertEquals(type == missing ? 2 : 0,
            events().stream().filter(event -> event.kind() == BridgeEventKind.GAP).count());
      }
    } finally {
      workers.shutdownNow();
    }
  }

  @Test
  void unavailableLineOwnerStillReportsOnlyEnteredMethods() throws Exception {
    String name = "demo.probe.Orders";
    byte[] bytes = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()).locate(name).resolve();
    // Simulate an unavailable line owner while the independently supplied bootstrap gap probe
    // remains visible to the application loader.
    Class<?> type = load(name, bytes, new ClassLoader(null) {});
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("<class>")
        && report.reason().equals(MethodReport.Reasons.PROBE_OWNER)));
    Object instance = type.getConstructor().newInstance();
    assertTrue(events().isEmpty());
    assertTrue(BootstrapBridge.requestStart("POST", "/missing-owner"));
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    var gaps = events().stream().filter(event -> event.kind() == BridgeEventKind.GAP).toList();
    assertEquals(2, gaps.size());
    assertTrue(gaps.stream().allMatch(gap -> gap.symbol().equals(RecordingWriter.UNTRANSFORMED_GAP_SYMBOL)));
  }

  private static final class CapturedRecording implements RecordingWriter.Transport {
    final List<RecordingStarted> starts = new ArrayList<>();
    final List<EventBatch> batches = new ArrayList<>();
    final List<RecordingFinished> finishes = new ArrayList<>();

    @Override
    public Ack send(String messageId, String correlationToken, Message payload) {
      Ack.Builder ack = Ack.newBuilder().setDurability(AckDurability.ACK_DURABILITY_STAGED);
      if (payload instanceof RecordingStarted started) {
        starts.add(started);
        ack.putHighestContiguousRecordingSeq(uuid(started.getRecordingId().toByteArray()), 1);
      } else if (payload instanceof EventBatch batch) {
        batches.add(batch);
        ack.putHighestContiguousRecordingSeq(uuid(batch.getRecordingId().toByteArray()),
            batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq());
      } else if (payload instanceof RecordingFinished finished) {
        finishes.add(finished);
        ack.putHighestContiguousRecordingSeq(uuid(finished.getRecordingId().toByteArray()),
            finished.getFinalRecordingSeq());
      }
      return ack.build();
    }

    @Override
    public boolean fitsEnvelope(String messageId, String correlationToken, Message payload) {
      return payload.getSerializedSize() <= RecordingWriter.MAX_BATCH_BYTES;
    }

    @Override
    public void close() {}

    private static String uuid(byte[] bytes) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes);
      return new UUID(buffer.getLong(), buffer.getLong()).toString();
    }
  }
}
