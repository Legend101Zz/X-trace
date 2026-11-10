package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import com.google.protobuf.Message;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.SpringMvcBridge;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.LineProbeAsmWrapper;
import dev.xtrace.agent.runtime.line.LineProbeConfig;
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
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
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
  private final FixtureInstrumentation.CaptureLimitations limitations =
      new FixtureInstrumentation.CaptureLimitations();
  private final FixtureInstrumentation.LineProbes probes =
      new FixtureInstrumentation.LineProbes(new SiteRegistry(), limitations);
  private final Map<Class<?>, byte[]> transformedClasses = new ConcurrentHashMap<>();

  @BeforeEach
  void install() {
    sink.untransformedCount(limitations::count);
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
    return load(name, bytes, null, false);
  }

  private Class<?> load(String name, byte[] bytes, LineProbeAsmWrapper wrapper, boolean rejectBridge) {
    return load(name, bytes, wrapper, rejectBridge, true);
  }

  private Class<?> load(String name, byte[] bytes, LineProbeAsmWrapper wrapper, boolean rejectBridge,
      boolean focused) {
    ClassLoader parent = getClass().getClassLoader();
    var locator = new ClassFileLocator.Compound(ClassFileLocator.Simple.of(name, bytes),
        ClassFileLocator.ForClassLoader.of(parent));
    class Isolated extends ClassLoader {
      Isolated() { super(parent); }
      Class<?> define(byte[] transformed) { return defineClass(name, transformed, 0, transformed.length); }
      @Override
      protected Class<?> loadClass(String requested, boolean resolve) throws ClassNotFoundException {
        if (rejectBridge && requested.startsWith("dev.xtrace.agent.bootstrap.")) {
          throw new ClassNotFoundException("bootstrap bridge filtered");
        }
        return super.loadClass(requested, resolve);
      }
    }
    Isolated loader = new Isolated();
    byte[] transformed = new ByteBuddy().redefine(TypePool.Default.of(locator).describe(name).resolve(), locator)
        .visit(wrapper == null ? FixtureInstrumentation.applicationProbes(loader, focused ? probes : null, limitations)
            : FixtureInstrumentation.boundedProbes(wrapper, limitations, new java.util.HashSet<>()))
        .make().getBytes();
    Class<?> type = loader.define(transformed);
    transformedClasses.put(type, transformed);
    return type;
  }

  private int gapProbes(Class<?> type, String method, String descriptor) {
    return probeCalls(type, method, descriptor, "lineGap");
  }

  private int probeCalls(Class<?> type, String method, String descriptor, String probe) {
    int[] count = {0};
    new ClassReader(transformedClasses.get(type)).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String desc,
          String signature, String[] exceptions) {
        if (method != null && (!name.equals(method) || !desc.equals(descriptor))) return null;
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals(FixtureInstrumentation.PROBE_OWNER) && name.equals(probe)) count[0]++;
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
    List<MethodReport> reports = new ArrayList<>();
    var wrapper = new LineProbeAsmWrapper(LineProbeConfig.focused("missing/LineOwner"),
        probes.registry(), ignored -> null, reports::addAll, getClass().getClassLoader()) {
      @Override
      protected int skippedMethodEntryBytes() { return 3; }

      @Override
      protected void skippedMethodEntry(MethodVisitor method) {
        method.visitMethodInsn(Opcodes.INVOKESTATIC, FixtureInstrumentation.PROBE_OWNER,
            "lineGap", "()V", false);
      }
    };
    Class<?> type = load(name, bytes, wrapper, false);
    assertTrue(reports.stream().anyMatch(report -> report.name().equals("<class>")
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

  @Test
  void nearLimitSyntheticLambdaPreservesHealthySiblingAndPersistsTheLimitation() throws Exception {
    String name = "demo.probe.NearLimitLambda";
    ClassWriter bytes = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null, "java/lang/Object", null);
    MethodVisitor lambda = bytes.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
        "lambda$large$0", "()I", null, null);
    lambda.visitCode();
    Label line = new Label();
    lambda.visitLabel(line);
    lambda.visitLineNumber(1, line);
    // Exactly 65,535 original code bytes: even an unguarded invokestatic cannot fit.
    for (int i = 0; i < 65_533; i++) lambda.visitInsn(Opcodes.NOP);
    lambda.visitInsn(Opcodes.ICONST_5);
    lambda.visitInsn(Opcodes.IRETURN);
    lambda.visitMaxs(0, 0);
    lambda.visitEnd();
    MethodVisitor sibling = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
        "healthy", "()I", null, null);
    sibling.visitCode();
    Label siblingLine = new Label();
    sibling.visitLabel(siblingLine);
    sibling.visitLineNumber(2, siblingLine);
    sibling.visitInsn(Opcodes.ICONST_3);
    sibling.visitInsn(Opcodes.IRETURN);
    sibling.visitMaxs(0, 0);
    sibling.visitEnd();
    MethodVisitor factory = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
        "supplier", "()Ljava/util/function/IntSupplier;", null, null);
    factory.visitCode();
    Label factoryLine = new Label();
    factory.visitLabel(factoryLine);
    factory.visitLineNumber(3, factoryLine);
    factory.visitInvokeDynamicInsn("getAsInt", "()Ljava/util/function/IntSupplier;",
        new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                + "Ljava/lang/invoke/CallSite;", false),
        Type.getMethodType("()I"),
        new Handle(Opcodes.H_INVOKESTATIC, name.replace('.', '/'), "lambda$large$0", "()I", false),
        Type.getMethodType("()I"));
    factory.visitInsn(Opcodes.ARETURN);
    factory.visitMaxs(0, 0);
    factory.visitEnd();
    bytes.visitEnd();
    Class<?> type = load(name, bytes.toByteArray());
    assertTrue(type.getDeclaredMethod("lambda$large$0").isSynthetic());
    assertEquals(0, gapProbes(type, "lambda$large$0", "()I"));
    assertEquals(1, probeCalls(type, "healthy", "()I", "line"));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("lambda$large$0")
        && report.reason().equals(MethodReport.Reasons.TOO_LARGE)));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("healthy")
        && report.status() == MethodReport.Status.INSTRUMENTED));
    assertEquals(1, limitations.count());
    var supplier = (java.util.function.IntSupplier) type.getMethod("supplier").invoke(null);
    assertTrue(BootstrapBridge.requestStart("GET", "/near-limit"));
    assertEquals(5, supplier.getAsInt());
    assertEquals(3, type.getMethod("healthy").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void skippedMethodDuringDeferredExceptionResolutionPersistsPartialWithoutLeaking() throws Exception {
    Class<?> type = load("demo.probe.Orders", true);
    Object instance = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/exception"));
    assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("handled")));
    assertTrue(BootstrapBridge.awaitingResolution());
    Object resolution = SpringMvcBridge.exceptionResolutionEnter();
    assertNotNull(resolution);
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(422, false);
    SpringMvcBridge.exceptionResolved(null, null, null, resolution);
    // The ended context cannot receive later gaps or contaminate the next recording.
    BootstrapBridge.lineGap();
    assertFalse(BootstrapBridge.hasContext());
    assertTrue(BootstrapBridge.requestStart("GET", "/next"));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(2, 2);
    assertEquals(2, persistedGaps(transport, 0));
    assertEquals(0, persistedGaps(transport, 1));
  }

  @Test
  void fullExceptionTableOmitsTheGuardAndPersistsACaptureLimitation() throws Exception {
    String name = "demo.probe.FullExceptionTable";
    ClassWriter bytes = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null, "java/lang/Object", null);
    MethodVisitor method = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
        "lambda$handlers$0", "()I", null, null);
    method.visitCode();
    Label start = new Label();
    Label end = new Label();
    Label handler = new Label();
    for (int i = 0; i < 65_535; i++) method.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
    method.visitLabel(start);
    method.visitInsn(Opcodes.ICONST_5);
    method.visitInsn(Opcodes.IRETURN);
    method.visitLabel(end);
    method.visitLabel(handler);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.ICONST_0);
    method.visitInsn(Opcodes.IRETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    bytes.visitEnd();
    Class<?> type = load(name, bytes.toByteArray());
    assertEquals(0, gapProbes(type, "lambda$handlers$0", "()I"));
    assertEquals(1, limitations.count());
    assertTrue(BootstrapBridge.requestStart("GET", "/handler-limit"));
    assertEquals(5, type.getMethod("lambda$handlers$0").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void nearLimitOrdinaryExceptionTableBudgetsFrameAdviceAndKeepsHealthySibling() throws Exception {
    String name = "demo.probe.OrdinaryHandlerLimit";
    byte[] minimal = ordinaryLimitClass(name, 0, 0, 0);
    var locator = new ClassFileLocator.Compound(ClassFileLocator.Simple.of(name, minimal),
        ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    byte[] framed = new ByteBuddy().redefine(TypePool.Default.of(locator).describe(name).resolve(), locator)
        .visit(Advice.to(FixtureInstrumentation.FrameAdvice.class).on(FixtureInstrumentation.frameMethods()))
        .make().getBytes();
    int[] frameHandlers = {0};
    new ClassReader(framed).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String method, String descriptor,
          String signature, String[] exceptions) {
        if (!method.equals("limited")) return null;
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
            frameHandlers[0]++;
          }
        };
      }
    }, 0);
    assertTrue(frameHandlers[0] > 0);
    // Frame advice alone fills the table exactly. Adding the skipped-method guard must cause
    // this ordinary method to fall back before ASM can truncate the count with putShort.
    Class<?> type = load(name, ordinaryLimitClass(name, 0, 65_535 - frameHandlers[0], 0));
    assertEquals(0, gapProbes(type, "limited", "()I"));
    assertEquals(0, probeCalls(type, "limited", "()I", "frameEnter"));
    assertEquals(1, limitations.count());
    assertLimitedMethodAndHealthySibling(type);
  }

  @Test
  void nearLimitOrdinaryCodeBudgetsFrameAdviceAndKeepsHealthySibling() throws Exception {
    // The original method is valid at exactly 65,535 bytes; no composed advice can fit.
    Class<?> type = load("demo.probe.OrdinaryCodeLimit",
        ordinaryLimitClass("demo.probe.OrdinaryCodeLimit", 65_533, 0, 0));
    assertEquals(0, probeCalls(type, "limited", "()I", "frameEnter"));
    assertTrue(limitations.count() > 0);
    assertLimitedMethodAndHealthySibling(type);
  }

  @Test
  void nearLimitOrdinaryLocalsBudgetFrameAdviceAndKeepHealthySibling() throws Exception {
    Class<?> type = load("demo.probe.OrdinaryLocalLimit",
        ordinaryLimitClass("demo.probe.OrdinaryLocalLimit", 0, 0, 65_535));
    assertEquals(0, probeCalls(type, "limited", "()I", "frameEnter"));
    assertTrue(limitations.count() > 0);
    assertLimitedMethodAndHealthySibling(type);
  }

  @Test
  void standardModeAlsoPreservesNearLimitOrdinaryMethodsAndHealthySiblingFrames() throws Exception {
    String name = "demo.probe.StandardCodeLimit";
    Class<?> type = load(name, ordinaryLimitClass(name, 65_533, 0, 0), null, false, false);
    assertEquals(0, probeCalls(type, "limited", "()I", "frameEnter"));
    assertEquals(1, probeCalls(type, "healthy", "()I", "frameEnter"));
    assertEquals(0, probeCalls(type, null, null, "line"));
    assertEquals(1, limitations.count());
    assertTrue(BootstrapBridge.requestStart("GET", "/standard-limit"));
    assertEquals(5, type.getMethod("limited").invoke(null));
    assertEquals(3, type.getMethod("healthy").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void nearLimitStackOmitsLineInstrumentationAndKeepsTheClassValid() throws Exception {
    String name = "demo.probe.OrdinaryStackLimit";
    // A declared maximum may conservatively exceed actual usage. It remains a valid input;
    // composing probes must still avoid overflowing the class file's unsigned stack field.
    Class<?> type = load(name, ordinaryLimitClass(name, 0, 0, 0, 65_535));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("limited")
        && report.reason().equals(MethodReport.Reasons.TOO_LARGE)));
    assertEquals(1, probeCalls(type, "healthy", "()I", "line"));
    assertTrue(BootstrapBridge.requestStart("GET", "/stack-limit"));
    assertEquals(5, type.getMethod("limited").invoke(null));
    assertEquals(3, type.getMethod("healthy").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void nearLimitConstructorCodeBudgetsTheWholeBodyBoundaryAndPreservesTheClass() throws Exception {
    assertLimitedConstructor("ConstructorCodeLimit", 65_530, 0, 0);
  }

  @Test
  void nearLimitConstructorLocalsBudgetTheBoundaryAndPreserveTheClass() throws Exception {
    assertLimitedConstructor("ConstructorLocalLimit", 0, 0, 65_535);
  }

  @Test
  void fullConstructorExceptionTableBudgetsTheUnwindHandlerAndPreservesTheClass() throws Exception {
    assertLimitedConstructor("ConstructorHandlerLimit", 0, 65_535, 0);
  }

  private void assertLimitedConstructor(String simpleName, int nops, int handlers, int locals) throws Exception {
    String name = "demo.probe." + simpleName;
    ClassWriter bytes = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null, "java/lang/Object", null);
    MethodVisitor constructor = bytes.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    Label start = new Label();
    Label end = new Label();
    Label handler = new Label();
    for (int i = 0; i < handlers; i++) constructor.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
    constructor.visitLabel(start);
    constructor.visitLineNumber(1, start);
    for (int i = 0; i < nops; i++) constructor.visitInsn(Opcodes.NOP);
    if (locals > 0) {
      constructor.visitInsn(Opcodes.ICONST_0);
      constructor.visitVarInsn(Opcodes.ISTORE, locals - 1);
    }
    constructor.visitInsn(Opcodes.RETURN);
    if (handlers > 0) {
      constructor.visitLabel(end);
      constructor.visitLabel(handler);
      constructor.visitInsn(Opcodes.POP);
      constructor.visitInsn(Opcodes.RETURN);
    }
    constructor.visitMaxs(0, 0);
    constructor.visitEnd();
    MethodVisitor healthy = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "healthy", "()I", null, null);
    healthy.visitCode();
    Label line = new Label();
    healthy.visitLabel(line);
    healthy.visitLineNumber(2, line);
    healthy.visitInsn(Opcodes.ICONST_3);
    healthy.visitInsn(Opcodes.IRETURN);
    healthy.visitMaxs(0, 0);
    healthy.visitEnd();
    bytes.visitEnd();

    Class<?> type = load(name, bytes.toByteArray());
    assertEquals(0, probeCalls(type, "<init>", "()V", "line"));
    assertEquals(0, probeCalls(type, "<init>", "()V", "constructorEnter"));
    assertEquals(0, probeCalls(type, "<init>", "()V", "lineGap"));
    assertEquals(1, probeCalls(type, "healthy", "()I", "frameEnter"));
    assertEquals(1, probeCalls(type, "healthy", "()I", "line"));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("<init>")
        && report.reason().equals(MethodReport.Reasons.TOO_LARGE)));
    assertTrue(limitations.count() > 0);
    assertTrue(BootstrapBridge.requestStart("GET", "/constructor-limit"));
    assertNotNull(type.getConstructor().newInstance());
    assertEquals(3, type.getMethod("healthy").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  private void assertLimitedMethodAndHealthySibling(Class<?> type) throws Exception {
    assertEquals(1, probeCalls(type, "healthy", "()I", "line"));
    assertEquals(1, probeCalls(type, "healthy", "()I", "frameEnter"));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("limited")
        && report.status() == MethodReport.Status.SKIPPED
        && report.reason().equals(MethodReport.Reasons.TOO_LARGE)));
    assertTrue(probes.reports().stream().anyMatch(report -> report.name().equals("healthy")
        && report.status() == MethodReport.Status.INSTRUMENTED));
    assertTrue(BootstrapBridge.requestStart("GET", "/ordinary-limit"));
    assertEquals(5, type.getMethod("limited").invoke(null));
    assertEquals(3, type.getMethod("healthy").invoke(null));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(1);
    assertEquals(limitations.count(), transport.batches.stream()
        .flatMap(batch -> batch.getEventsList().stream()).filter(event -> event.hasGap())
        .findFirst().orElseThrow().getGap().getCount());
  }

  private static byte[] ordinaryLimitClass(String name, int nops, int handlers, int locals) {
    return ordinaryLimitClass(name, nops, handlers, locals, 0);
  }

  private static byte[] ordinaryLimitClass(String name, int nops, int handlers, int locals, int stack) {
    ClassWriter bytes = new ClassWriter(stack == 0 ? ClassWriter.COMPUTE_FRAMES : 0);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name.replace('.', '/'), null, "java/lang/Object", null);
    MethodVisitor method = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
        "limited", "()I", null, null);
    method.visitCode();
    Label start = new Label();
    Label end = new Label();
    Label handler = new Label();
    for (int i = 0; i < handlers; i++) method.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
    method.visitLabel(start);
    if (stack > 0) method.visitLineNumber(1, start);
    for (int i = 0; i < nops; i++) method.visitInsn(Opcodes.NOP);
    method.visitInsn(Opcodes.ICONST_5);
    if (locals > 0) {
      method.visitVarInsn(Opcodes.ISTORE, locals - 1);
      method.visitVarInsn(Opcodes.ILOAD, locals - 1);
    }
    method.visitInsn(Opcodes.IRETURN);
    if (handlers > 0) {
      method.visitLabel(end);
      method.visitLabel(handler);
      method.visitInsn(Opcodes.POP);
      method.visitInsn(Opcodes.ICONST_0);
      method.visitInsn(Opcodes.IRETURN);
    }
    method.visitMaxs(stack, locals);
    method.visitEnd();
    MethodVisitor sibling = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
        "healthy", "()I", null, null);
    sibling.visitCode();
    Label line = new Label();
    sibling.visitLabel(line);
    sibling.visitLineNumber(1, line);
    sibling.visitInsn(Opcodes.ICONST_3);
    sibling.visitInsn(Opcodes.IRETURN);
    sibling.visitMaxs(1, 0);
    sibling.visitEnd();
    bytes.visitEnd();
    return bytes.toByteArray();
  }

  @Test
  void staleDeferralCannotAttributeGapsToTheNextRequest() throws Exception {
    Class<?> type = load("demo.probe.Orders", true);
    Object instance = type.getConstructor().newInstance();
    SpringMvcBridge.dispatchEnter();
    try {
      assertTrue(BootstrapBridge.requestStart("GET", "/stale"));
      assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("unresolved")));
      assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
      assertTrue(BootstrapBridge.requestStart("GET", "/next"));
      assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
      BootstrapBridge.requestEnd(200, false);
      assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
      CapturedRecording transport = assertPersistedPartial(4, 2);
      assertNotEquals(transport.starts.get(0).getRecordingId(), transport.starts.get(1).getRecordingId());
      assertEquals(2, persistedGaps(transport, 0));
      assertEquals(2, persistedGaps(transport, 1));
      assertEquals(transport.starts.get(0).getRecordingId(), transport.finishes.get(0).getRecordingId());
      assertEquals(xtp.agent.v1.Recording.OutcomeKind.OUTCOME_KIND_EXCEPTION_PROPAGATED,
          transport.finishes.get(0).getOutcome().getKind());
      assertEquals(200, transport.finishes.get(1).getOutcome().getHttpStatus());
      assertFalse(BootstrapBridge.hasContext());
    } finally {
      SpringMvcBridge.dispatchEnd(null, null);
    }
  }

  @Test
  void unresolvedDeferralOutsideAnObservableBoundaryCannotReceiveUnrelatedGaps() throws Exception {
    Class<?> type = load("demo.probe.Orders", true);
    Object instance = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("GET", "/unresolved"));
    assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("unresolved")));
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    assertTrue(BootstrapBridge.awaitingResolution());
    // A new unrelated dispatch on the same thread must not adopt the abandoned context.
    SpringMvcBridge.dispatchEnter();
    try {
      Object resolution = SpringMvcBridge.exceptionResolutionEnter();
      assertNull(resolution, "a new dispatch cannot adopt a stale deferral");
      assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
      SpringMvcBridge.exceptionResolved(null, new Object(), null, resolution);
    } finally {
      SpringMvcBridge.dispatchEnd(null, null);
    }
    assertTrue(BootstrapBridge.requestStart("GET", "/next"));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(0, 2);
    assertEquals(0, persistedGaps(transport, 0));
    assertEquals(0, persistedGaps(transport, 1));
    assertTrue(transport.batches.stream().flatMap(batch -> batch.getEventsList().stream())
        .noneMatch(event -> event.getKind() == xtp.agent.v1.Recording.RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER));
  }

  @Test
  void deferredGapAttributionEndsWhenItsDispatchExitsEvenIfStillUnresolved() throws Exception {
    Class<?> type = load("demo.probe.Orders", true);
    Object instance = type.getConstructor().newInstance();
    SpringMvcBridge.dispatchEnter();
    try {
      assertTrue(BootstrapBridge.requestStart("GET", "/unresolved"));
      assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("unresolved")));
      assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    } finally {
      SpringMvcBridge.dispatchEnd(null, null);
    }
    assertTrue(BootstrapBridge.awaitingResolution());
    assertNull(SpringMvcBridge.exceptionResolutionEnter(), "the original dispatch has ended");
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    assertTrue(BootstrapBridge.requestStart("GET", "/next"));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(2, 2);
    assertEquals(2, persistedGaps(transport, 0));
    assertEquals(0, persistedGaps(transport, 1));
  }

  @Test
  void healthyFinishQueuedBeforeTransformationFailureRemainsHealthyWhenDrainedLater() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/healthy"));
    BootstrapBridge.requestEnd(200, false);
    limitations.report();
    assertTrue(BootstrapBridge.requestStart("GET", "/later"));
    BootstrapBridge.requestEnd(200, false);
    // The writer has not started: both finishes are queued before its first drain.
    CapturedRecording transport = assertPersistedPartial(1, 2);
    assertEquals(0, persistedGaps(transport, 0));
    assertEquals(1, persistedGaps(transport, 1));
    assertEquals(200, transport.finishes.get(0).getOutcome().getHttpStatus());
  }

  @Test
  void exceptionResolutionExitCannotFinishAReplacementContext() throws Exception {
    Class<?> type = load("demo.probe.Orders", true);
    Object instance = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("GET", "/stale-resolver"));
    assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("unresolved")));
    Object resolution = SpringMvcBridge.exceptionResolutionEnter();
    assertNotNull(resolution);
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    assertTrue(BootstrapBridge.requestStart("GET", "/replacement"));
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    SpringMvcBridge.exceptionResolved(null, new Object(), null, resolution);
    assertTrue(BootstrapBridge.inRequest(), "the old resolver cannot complete the replacement");
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(4, 2);
    assertEquals(2, persistedGaps(transport, 0));
    assertEquals(2, persistedGaps(transport, 1));
    assertEquals(200, transport.finishes.get(1).getOutcome().getHttpStatus());
  }

  @Test
  void definingLoaderRejectingBridgePreservesApplicationAndPersistsLimitation() throws Exception {
    String name = "demo.probe.Orders";
    byte[] bytes = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()).locate(name).resolve();
    ClassWriter stripped = new ClassWriter(0);
    new ClassReader(bytes).accept(stripped, ClassReader.SKIP_DEBUG);
    Class<?> type = load(name, stripped.toByteArray(), null, true);
    assertThrows(ClassNotFoundException.class,
        () -> type.getClassLoader().loadClass(BootstrapBridge.class.getName()));
    assertFalse(FixtureInstrumentation.gapOwnerAvailable(type.getClassLoader()));
    assertEquals(0, gapProbes(type, null, null));
    assertTrue(probes.reports().stream().anyMatch(report -> report.reason().equals(MethodReport.Reasons.PROBE_OWNER)));
    Object instance = type.getConstructor().newInstance();
    assertTrue(BootstrapBridge.requestStart("POST", "/filtered-loader"));
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void constructorBodyIsPreservedWhenItsDefiningLoaderCannotResolveTheBoundaryOwner() throws Exception {
    String name = "demo.probe.CursorParents";
    byte[] bytes = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()).locate(name).resolve();
    Class<?> type = load(name, bytes, null, true);
    assertEquals(0, probeCalls(type, "<init>", "()V", "constructorEnter"));
    assertEquals(0, probeCalls(type, "<init>", "()V", "lineGap"));
    assertEquals(0, probeCalls(type, "<init>", "()V", "line"));
    assertTrue(limitations.count() > 0);
    assertTrue(BootstrapBridge.requestStart("GET", "/constructor-owner"));
    Object instance = type.getConstructor().newInstance();
    assertEquals("initial", type.getMethod("getName").invoke(instance));
    BootstrapBridge.requestEnd(200, false);
    assertPersistedPartial(1);
  }

  @Test
  void gapCallResolutionFailureIsSuppressedAtTheCaller() throws Exception {
    String name = "demo.probe.Orders";
    byte[] bytes = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()).locate(name).resolve();
    // An independent gap owner is deliberately unreachable at execution. This exercises the
    // guard itself rather than production preflight's omission of unreachable bridge calls.
    var wrapper = new LineProbeAsmWrapper(LineProbeConfig.focused("missing/LineOwner"),
        probes.registry(), ignored -> null, ignored -> {}, getClass().getClassLoader()) {
      @Override
      protected int skippedMethodEntryBytes() { return 3; }

      @Override
      protected void skippedMethodEntry(MethodVisitor method) {
        method.visitMethodInsn(Opcodes.INVOKESTATIC, FixtureInstrumentation.PROBE_OWNER,
            "lineGap", "()V", false);
      }
    };
    Class<?> type = load(name, bytes, wrapper, true);
    assertEquals(1, gapProbes(type, "create", "(Ljava/lang/String;)Ljava/lang/String;"));
    Object instance = type.getConstructor().newInstance();
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    var failure = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> type.getMethod("create", String.class).invoke(instance, (Object) null));
    assertInstanceOf(NullPointerException.class, failure.getCause());

    // Expanded guard frames must preserve wide arguments and array locals as well as constructors.
    String wideName = "demo.probe.WideGapArguments";
    ClassWriter wide = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    wide.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, wideName.replace('.', '/'), null, "java/lang/Object", null);
    MethodVisitor method = wide.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
        "lambda$wide$0", "(JD[Ljava/lang/Object;)J", null, null);
    method.visitCode();
    method.visitVarInsn(Opcodes.LLOAD, 0);
    method.visitInsn(Opcodes.LRETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    wide.visitEnd();
    Class<?> wideType = load(wideName, wide.toByteArray(), wrapper, true);
    assertEquals(42L, wideType.getMethod("lambda$wide$0", long.class, double.class, Object[].class)
        .invoke(null, 42L, 1.5, new Object[0]));
  }

  @Test
  void frameComputationFailureKeepsOriginalBytesAndMarksOpenAndFutureRecordingsPartial() throws Exception {
    String name = "demo.probe.Orders";
    ClassLoader parent = getClass().getClassLoader();
    byte[] original = ClassFileLocator.ForClassLoader.of(parent).locate(name).resolve();
    ClassLoader loader = new ClassLoader(parent) { };
    var listener = new FixtureInstrumentation.SafeListener(
        () -> fail("ordinary application frame failure must preserve the runtime"),
        new ApplicationScope(List.of("demo.probe"), List.of()), limitations);
    var broken = new net.bytebuddy.asm.AsmVisitorWrapper.AbstractBase() {
      @Override
      public ClassVisitor wrap(net.bytebuddy.description.type.TypeDescription type, ClassVisitor writer,
          net.bytebuddy.implementation.Implementation.Context context, TypePool pool,
          net.bytebuddy.description.field.FieldList<net.bytebuddy.description.field.FieldDescription.InDefinedShape> fields,
          net.bytebuddy.description.method.MethodList<?> methods, int writerFlags, int readerFlags) {
        return new ClassVisitor(Opcodes.ASM9, writer) {
          @Override
          public MethodVisitor visitMethod(int access, String method, String descriptor,
              String signature, String[] exceptions) {
            MethodVisitor output = super.visitMethod(access, method, descriptor, signature, exceptions);
            if (!method.equals("create") || !descriptor.startsWith("(Ljava/lang/String;")) return output;
            return new MethodVisitor(Opcodes.ASM9, output) {
              @Override
              public void visitCode() {
                super.visitCode();
                // An empty-stack pop followed by an edge forces final frame computation to fail.
                // Without COMPUTE_FRAMES make() would hand this malformed body to the JVM.
                Label merge = new Label();
                visitInsn(Opcodes.POP);
                visitJumpInsn(Opcodes.GOTO, merge);
                visitLabel(merge);
              }
            };
          }
        };
      }
    };
    var failure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
    var transformer = new AgentBuilder.Default().with(new AgentBuilder.Listener.Compound(listener,
        new AgentBuilder.Listener.Adapter() {
          @Override
          public void onError(String type, ClassLoader definingLoader, net.bytebuddy.utility.JavaModule module,
              boolean loaded, Throwable problem) { failure.set(problem); }
        }))
        .type((type, definingLoader, module, redefined, domain) -> {
          listener.observeScope(definingLoader, type.getName(), domain);
          return type.getName().equals(name);
        })
        .transform((builder, type, definingLoader, module, domain) -> builder.visit(
            new BoundedProbeAsmWrapper(broken, ignored -> limitations.report())))
        .makeRaw();
    assertTrue(BootstrapBridge.requestStart("GET", "/open-frame-failure"));
    // makeRaw notifies the listener, then throws. The JVM ignores transformer exceptions and
    // keeps the input bytes; a direct Java call must assert that exception rather than null.
    var rejected = assertThrows(IllegalStateException.class,
        () -> transformer.transform(loader, name.replace('.', '/'), null, null, original));
    assertEquals("Failed transformation of " + name, rejected.getMessage());
    assertNotNull(failure.get());
    assertSame(failure.get(), rejected.getCause());
    assertInstanceOf(NegativeArraySizeException.class, failure.get());
    assertTrue(java.util.Arrays.stream(failure.get().getStackTrace())
        .anyMatch(frame -> frame.getClassName().equals("net.bytebuddy.jar.asm.MethodWriter")
            && frame.getMethodName().equals("computeAllFrames")),
        "the negative control must reach final frame computation: " + failure.get());
    assertEquals(1, limitations.count());
    Class<?> preserved = new ClassLoader(parent) {
      Class<?> define() { return defineClass(name, original, 0, original.length); }
    }.define();
    Object target = preserved.getConstructor().newInstance();
    assertEquals("ABC", preserved.getMethod("create", String.class).invoke(target, " abc "));
    BootstrapBridge.requestEnd(200, false);
    assertTrue(BootstrapBridge.requestStart("GET", "/after-frame-failure"));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording persisted = assertPersistedPartial(2, 2);
    assertEquals(1, persistedGaps(persisted, 0));
    assertEquals(1, persistedGaps(persisted, 1));
  }

  @Test
  void ordinaryApplicationTransformationFailureMarksOpenAndFutureRecordingsPartial() throws Exception {
    String name = "demo.probe.Orders";
    ClassLoader parent = getClass().getClassLoader();
    byte[] bytes = ClassFileLocator.ForClassLoader.of(parent).locate(name).resolve();
    class Isolated extends ClassLoader {
      Isolated() { super(parent); }
      Class<?> define(byte[] original) { return defineClass(name, original, 0, original.length); }
    }
    Isolated loader = new Isolated();
    assertTrue(BootstrapBridge.requestStart("GET", "/open"));
    var listener = new FixtureInstrumentation.SafeListener(
        () -> fail("ordinary application failure must preserve the runtime"),
        new ApplicationScope(List.of("demo.probe"), List.of()), limitations);
    var transformationFailure = new IllegalStateException("transformation failed");
    var transformer = new AgentBuilder.Default().with(listener)
        .type((type, definingLoader, module, redefined, domain) -> {
          listener.observeScope(definingLoader, type.getName(), domain);
          return type.getName().equals(name);
        })
        .transform((builder, type, definingLoader, module, domain) -> {
          throw transformationFailure;
        }).makeRaw();
    var rejected = assertThrows(IllegalStateException.class,
        () -> transformer.transform(loader, name.replace('.', '/'), null, null, bytes));
    assertEquals("Failed transformation of " + name, rejected.getMessage());
    assertSame(transformationFailure, rejected.getCause());
    Class<?> type = loader.define(bytes);
    Object instance = type.getConstructor().newInstance();
    assertEquals("ABC", type.getMethod("create", String.class).invoke(instance, " abc "));
    BootstrapBridge.requestEnd(200, false);
    assertTrue(BootstrapBridge.requestStart("GET", "/later"));
    BootstrapBridge.requestEnd(200, false);
    CapturedRecording transport = assertPersistedPartial(2, 2);
    assertEquals(1, persistedGaps(transport, 0));
    assertEquals(1, persistedGaps(transport, 1));
    listener.onError("org.example.Framework", getClass().getClassLoader(), null, false,
        new IllegalStateException("out of scope"));
    assertEquals(1, limitations.count());
  }

  private static long persistedGaps(CapturedRecording transport, int recording) {
    var id = transport.starts.get(recording).getRecordingId();
    return transport.batches.stream().filter(batch -> batch.getRecordingId().equals(id))
        .flatMap(batch -> batch.getEventsList().stream()).filter(event -> event.hasGap()).count();
  }

  private CapturedRecording assertPersistedPartial(int expectedGaps) throws Exception {
    return assertPersistedPartial(expectedGaps, 1);
  }

  private CapturedRecording assertPersistedPartial(int expectedGaps, int expectedRecordings) throws Exception {
    CapturedRecording transport = new CapturedRecording();
    RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofMillis(100));
    writer.capturePolicy("xtrace.focused.v1");
    writer.start();
    writer.close();
    assertFalse(writer.incompleteWasReported());
    assertEquals(expectedRecordings, transport.starts.size());
    assertEquals(expectedRecordings, transport.finishes.size());
    var recorded = transport.batches.stream().flatMap(batch -> batch.getEventsList().stream()).toList();
    var gaps = recorded.stream().filter(event -> event.hasGap()).toList();
    assertEquals(expectedGaps, gaps.size());
    assertTrue(gaps.stream().allMatch(event -> event.getGap().getReason()
        == GapReason.GAP_REASON_CLASS_NOT_TRANSFORMED));
    assertTrue(gaps.stream().allMatch(event -> event.getGap().getCount() > 0));
    for (var finish : transport.finishes) {
      var recording = transport.batches.stream()
          .filter(batch -> batch.getRecordingId().equals(finish.getRecordingId()))
          .flatMap(batch -> batch.getEventsList().stream()).toList();
      assertArrayEquals(EventDigest.compute(recording.stream().map(event -> event.getEventId()).toList()),
          finish.getEventDigest().toByteArray());
    }
    return transport;
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
