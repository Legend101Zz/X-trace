package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static net.bytebuddy.matcher.ElementMatchers.named;

import dev.xtrace.agent.runtime.line.MethodReport.Reasons;
import dev.xtrace.agent.runtime.line.MethodReport.Status;
import java.lang.instrument.ClassFileTransformer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;

/** Final-stage fixes: probe-owner guard, deny scope, line 0, decision fail-open, advice shapes. */
class LineProbeFinalFixesTest {
  static final String OWNER = LineProbeDispatch.INTERNAL_NAME;

  /** Owner that lacks valuesEnd. */
  public static final class PartialOwner {
    public static void line(int s) {}

    public static void valuesBegin(int s) {}

    public static void valueInt(int a, int b, int c) {}

    public static void valueLong(int a, int b, long c) {}

    public static void valueFloat(int a, int b, float c) {}

    public static void valueDouble(int a, int b, double c) {}

    public static void valueRef(int a, int b, Object c) {}
  }

  /** Owner whose line method is not static. */
  public static final class InstanceOwner {
    public void line(int s) {}
  }

  static final class Loader extends ClassLoader {
    Loader() {
      super(LineProbeFinalFixesTest.class.getClassLoader());
    }

    private final java.util.Map<String, byte[]> served = new java.util.HashMap<>();

    Class<?> define(String name, byte[] b) {
      served.put(name.replace('.', '/') + ".class", b);
      return defineClass(name, b, 0, b.length);
    }

    @Override
    public java.io.InputStream getResourceAsStream(String name) {
      byte[] b = served.get(name);
      return b != null ? new java.io.ByteArrayInputStream(b) : super.getResourceAsStream(name);
    }
  }

  /** {@code static int m(int a)}: three lines; line numbers are given by the caller (0 allowed). */
  static byte[] simple(String internal, int l1, int l2, boolean lines, String lvtDescriptor) {
    // an empty descriptor is only writable without ASM's own max computation
    ClassWriter cw = new ClassWriter(lvtDescriptor != null ? 0 : ClassWriter.COMPUTE_MAXS);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
    cw.visitSource("S.java", null);
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "(I)I", null, null);
    mv.visitCode();
    Label a = new Label();
    Label b = new Label();
    Label e = new Label();
    mv.visitLabel(a);
    if (lines) mv.visitLineNumber(l1, a);
    mv.visitInsn(Opcodes.ICONST_1);
    mv.visitVarInsn(Opcodes.ISTORE, 1);
    mv.visitLabel(b);
    if (lines) mv.visitLineNumber(l2, b);
    mv.visitVarInsn(Opcodes.ILOAD, 1);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitLabel(e);
    mv.visitLocalVariable("a", lvtDescriptor == null ? "I" : lvtDescriptor, null, a, e, 0);
    mv.visitLocalVariable("b", "I", null, b, e, 1);
    mv.visitMaxs(2, 2);
    mv.visitEnd();
    cw.visitEnd();
    return cw.toByteArray();
  }

  static byte[] viaByteBuddy(
      String dotted, byte[] bytes, LineProbeConfig cfg, SiteRegistry reg, List<MethodReport> reports,
      ClassLoader ownerLoader) throws Exception {
    ClassFileLocator loc = ClassFileLocator.Simple.of(dotted, bytes);
    TypePool pool =
        TypePool.Default.of(
            new ClassFileLocator.Compound(loc, ClassFileLocator.ForClassLoader.ofSystemLoader()));
    return new ByteBuddy()
        .with(TypeValidation.DISABLED)
        .redefine(pool.describe(dotted).resolve(), loc)
        .visit(
            new LineProbeAsmWrapper(
                cfg, reg, t -> LineProbeInstrumenter.blake3(bytes), reports::addAll, ownerLoader))
        .make()
        .getBytes();
  }

  // ---- F2: probe owner guard ----

  @Test
  void ownerCheckAcceptsTheCompleteOwnerAndRejectsEveryBrokenOne() {
    assertNull(ProbeOwnerCheck.problem(OWNER, getClass().getClassLoader()));
    String partial = PartialOwner.class.getName().replace('.', '/');
    assertTrue(ProbeOwnerCheck.problem(partial, getClass().getClassLoader()).contains("valuesEnd"));
    String inst = InstanceOwner.class.getName().replace('.', '/');
    assertNotNull(ProbeOwnerCheck.problem(inst, getClass().getClassLoader()));
    assertNotNull(ProbeOwnerCheck.problem("dev/xtrace/agent/bootstrap/NoSuchBridge", getClass().getClassLoader()));
    // null means the bootstrap loader, which cannot see a test class
    assertNotNull(ProbeOwnerCheck.problem(OWNER, null));
  }

  @Test
  void wrapperLeavesClassesUntouchedWhenTheOwnerIsWrongOrIncomplete() throws Exception {
    String partial = PartialOwner.class.getName().replace('.', '/');
    for (String owner : new String[] {"dev/xtrace/agent/bootstrap/Typo", partial}) {
      byte[] plain = simple("fixes/Own", 10, 11, true, null);
      List<MethodReport> reports = new ArrayList<>();
      byte[] out =
          viaByteBuddy("fixes.Own", plain, LineProbeConfig.focused(owner), new SiteRegistry(), reports, getClass().getClassLoader());
      assertEquals(1, reports.size(), reports.toString());
      assertEquals(Reasons.PROBE_OWNER, reports.get(0).reason());
      assertEquals(Status.SKIPPED, reports.get(0).status());
      // no reference to the owner in the output: calling it would throw in application code
      assertFalse(new String(out, StandardCharsets.ISO_8859_1).contains(owner), owner);
    }
  }

  @Test
  void wrapperInstrumentsWhenTheOwnerIsComplete() throws Exception {
    byte[] plain = simple("fixes/Own2", 10, 11, true, null);
    List<MethodReport> reports = new ArrayList<>();
    byte[] out =
        viaByteBuddy("fixes.Own2", plain, LineProbeConfig.lineOnly(OWNER), new SiteRegistry(), reports, getClass().getClassLoader());
    assertTrue(new String(out, StandardCharsets.ISO_8859_1).contains(OWNER));
    assertEquals(Status.INSTRUMENTED, reports.get(0).status());
    assertEquals(2, reports.get(0).sites());
  }

  // ---- F13: deny scope ----

  @Test
  void probeOwnerAndXtraceJdkNamespacesAreNeverInstrumented() {
    for (String internal : new String[] {OWNER, "dev/xtrace/agent/runtime/Foo", "java/util/Foo", "jdk/internal/Foo", "sun/misc/Foo"}) {
      byte[] plain = simple(internal, 10, 11, true, null);
      LineProbeInstrumenter.Result r =
          new LineProbeInstrumenter(LineProbeConfig.focused(OWNER), new SiteRegistry()).instrument(plain);
      assertFalse(r.changed(), internal);
      assertEquals(Reasons.DENY_SCOPE, r.methods().get(0).reason(), internal);
    }
    byte[] app = simple("com/acme/Foo", 10, 11, true, null);
    assertTrue(new LineProbeInstrumenter(LineProbeConfig.focused(OWNER), new SiteRegistry()).instrument(app).changed());
  }

  // ---- F6: line 0 ----

  @Test
  void lineNumberZeroEntriesAreNotSitesAndAreCounted() {
    byte[] plain = simple("fixes/Zero", 0, 5, true, null);
    SiteRegistry reg = new SiteRegistry();
    LineProbeInstrumenter.Result r =
        new LineProbeInstrumenter(LineProbeConfig.lineOnly(OWNER), reg).instrument(plain);
    MethodReport m = r.methods().get(0);
    assertEquals(Status.INSTRUMENTED, m.status());
    assertEquals(1, m.sites());
    assertEquals(1, m.zeroLineEntries());
    assertEquals(5, reg.site(1).line());
    // only line-0 entries: nothing to instrument
    byte[] only0 = simple("fixes/Zero2", 0, 0, true, null);
    LineProbeInstrumenter.Result r0 =
        new LineProbeInstrumenter(LineProbeConfig.lineOnly(OWNER), new SiteRegistry()).instrument(only0);
    assertFalse(r0.changed());
    assertEquals(Reasons.NO_LINE_TABLE, r0.methods().get(0).reason());
  }

  // ---- F11: decision-phase failure is per method and fail-open ----

  @Test
  void aThrowingDecisionPhaseSkipsTheMethodInsteadOfTheClass() {
    // An empty LVT descriptor makes liveAt() throw. The sink writer does no max computation, so it
    // can re-emit the odd table; the visitor itself must not let the exception escape.
    byte[] plain = simple("fixes/BadLvt", 10, 11, true, "");
    SiteRegistry reg = new SiteRegistry();
    List<MethodReport> reports = new ArrayList<>();
    ClassWriter sink = new ClassWriter(0);
    new net.bytebuddy.jar.asm.ClassReader(plain)
        .accept(new LineProbeVisitor(sink, LineProbeConfig.focused(OWNER), reg, new byte[32], reports), 0);
    assertNotNull(sink.toByteArray());
    assertEquals(1, reports.size());
    assertEquals(Status.SKIPPED, reports.get(0).status());
    assertEquals(Reasons.TRANSFORM_ERROR, reports.get(0).reason());
    assertEquals(0, reg.siteCount());
    assertFalse(new String(sink.toByteArray(), StandardCharsets.ISO_8859_1).contains(OWNER));
  }

  // ---- F8: stable site ids across retransformation ----

  @Test
  void transformingTheSameBytesTwiceReusesSiteIds() {
    byte[] plain = simple("fixes/Twice", 10, 11, true, null);
    SiteRegistry reg = new SiteRegistry();
    LineProbeInstrumenter inst = new LineProbeInstrumenter(LineProbeConfig.lineOnly(OWNER), reg);
    LineProbeInstrumenter.Result a = inst.instrument(plain);
    int after1 = reg.siteCount();
    LineProbeInstrumenter.Result b = inst.instrument(plain);
    assertEquals(after1, reg.siteCount(), "registry must not grow on re-transformation");
    assertEquals(2, after1);
    assertTrue(java.util.Arrays.equals(a.bytes(), b.bytes()), "same bytes in, same probes out");
  }

  // ---- F9(f): wide locals, goto_w widening, -g:none on the wrapper path ----

  @Test
  void aLiveLocalAtSlotAbove255IsReadWithAWideInstructionAndVerifies() throws Exception {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixes/Wide", null, "java/lang/Object", null);
    cw.visitSource("Wide.java", null);
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "(I)I", null, null);
    mv.visitCode();
    Label l0 = new Label();
    Label l1 = new Label();
    Label l2 = new Label();
    mv.visitLabel(l0);
    mv.visitLineNumber(10, l0);
    mv.visitIntInsn(Opcodes.SIPUSH, 777);
    mv.visitVarInsn(Opcodes.ISTORE, 300);
    mv.visitLabel(l1);
    mv.visitLineNumber(11, l1);
    mv.visitVarInsn(Opcodes.ILOAD, 300);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitLabel(l2);
    mv.visitLocalVariable("a", "I", null, l0, l2, 0);
    mv.visitLocalVariable("wide", "I", null, l1, l2, 300);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    cw.visitEnd();
    SiteRegistry reg = new SiteRegistry();
    LineProbeInstrumenter.Result r =
        new LineProbeInstrumenter(LineProbeConfig.focused(OWNER), reg).instrument(cw.toByteArray());
    assertTrue(r.changed());
    List<String> names = new ArrayList<>();
    LineProbeDispatch.install(
        new LineProbeSink() {
          @Override
          public void valueInt(int slot, int nameId, int v) {
            names.add(reg.name(nameId).name() + "=" + v + "@" + slot);
          }
        });
    try {
      Class<?> c = new Loader().define("fixes.Wide", r.bytes());
      assertEquals(777, c.getMethod("m", int.class).invoke(null, 1));
    } finally {
      LineProbeDispatch.install(null);
    }
    assertTrue(names.contains("wide=777@300"), names.toString());
  }

  @Test
  void aBackwardJumpPushedPast32KiBByProbesIsWidenedAndStillVerifiesAndRuns() throws Exception {
    // 1000 line entries, each followed by 7 sipush/pop pairs (28 bytes): a 28 KB loop body, so the
    // probes (6 bytes each) push the backward ifgt beyond the 16-bit branch offset.
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixes/Far", null, "java/lang/Object", null);
    cw.visitSource("Far.java", null);
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "(I)I", null, null);
    mv.visitCode();
    Label start = new Label();
    mv.visitLabel(start);
    mv.visitLineNumber(1, start);
    Label top = new Label();
    mv.visitLabel(top);
    for (int i = 0; i < 1000; i++) {
      Label l = new Label();
      mv.visitLabel(l);
      mv.visitLineNumber(100 + i, l);
      for (int k = 0; k < 7; k++) {
        mv.visitIntInsn(Opcodes.SIPUSH, 1000);
        mv.visitInsn(Opcodes.POP);
      }
    }
    Label end = new Label();
    mv.visitLabel(end);
    mv.visitLineNumber(2000, end);
    mv.visitIincInsn(0, -1);
    mv.visitVarInsn(Opcodes.ILOAD, 0);
    mv.visitJumpInsn(Opcodes.IFGT, top);
    mv.visitInsn(Opcodes.ICONST_5);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    cw.visitEnd();
    byte[] plain = cw.toByteArray();
    SiteRegistry reg = new SiteRegistry();
    LineProbeInstrumenter.Result r =
        new LineProbeInstrumenter(LineProbeConfig.lineOnly(OWNER), reg).instrument(plain);
    assertEquals(Status.INSTRUMENTED, r.methods().get(0).status(), r.methods().toString());
    assertTrue(r.methods().get(0).sites() >= 1000);
    assertTrue(plain.length < 32_767 + 2_000, "original loop must be within short branch range");
    int[] events = {0};
    LineProbeDispatch.install(
        new LineProbeSink() {
          @Override
          public void line(int siteId) {
            events[0]++;
          }
        });
    try {
      Class<?> c = new Loader().define("fixes.Far", r.bytes()); // verifier runs here
      assertEquals(5, c.getMethod("m", int.class).invoke(null, 2));
    } finally {
      LineProbeDispatch.install(null);
    }
    // line 1 shares its first instruction with line 100 (last entry wins): 1000 + 1 sites per pass
    assertEquals(2 * 1001, events[0]);
  }

  @Test
  void classesWithoutDebugInfoThroughTheWrapperAreLeftAloneAndReported() throws Exception {
    byte[] plain = simple("fixes/NoDebug", 10, 11, false, null);
    List<MethodReport> reports = new ArrayList<>();
    byte[] out =
        viaByteBuddy("fixes.NoDebug", plain, LineProbeConfig.focused(OWNER), new SiteRegistry(), reports, getClass().getClassLoader());
    assertEquals(Reasons.NO_LINE_TABLE, reports.get(0).reason());
    assertFalse(new String(out, StandardCharsets.ISO_8859_1).contains(OWNER));
    assertEquals(1, new Loader().define("fixes.NoDebug", out).getMethod("m", int.class).invoke(null, 1));
  }

  // ---- F3: production advice shape (enter + exit onThrowable) in both registration orders ----

  /** Enter plus exit-on-throwable, the shape lane J applies at call boundaries. */
  public static final class ProdAdvice {
    public static int entered;
    public static int exited;
    public static int thrown;

    @Advice.OnMethodEnter
    static void enter() {
      entered++;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.Thrown Throwable t) {
      exited++;
      if (t != null) thrown++;
    }
  }

  /** {@code static int m(int a) { if (a < 0) throw new IllegalStateException(); return a + 1; }} */
  static byte[] throwing() {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixes/Thrower", null, "java/lang/Object", null);
    cw.visitSource("Thrower.java", null);
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "(I)I", null, null);
    mv.visitCode();
    Label l0 = new Label();
    Label ok = new Label();
    Label l2 = new Label();
    mv.visitLabel(l0);
    mv.visitLineNumber(10, l0);
    mv.visitVarInsn(Opcodes.ILOAD, 0);
    mv.visitJumpInsn(Opcodes.IFGE, ok);
    Label l1 = new Label();
    mv.visitLabel(l1);
    mv.visitLineNumber(11, l1);
    mv.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException");
    mv.visitInsn(Opcodes.DUP);
    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "()V", false);
    mv.visitInsn(Opcodes.ATHROW);
    mv.visitLabel(ok);
    mv.visitLineNumber(12, ok);
    mv.visitVarInsn(Opcodes.ILOAD, 0);
    mv.visitInsn(Opcodes.ICONST_1);
    mv.visitInsn(Opcodes.IADD);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitLabel(l2);
    mv.visitLocalVariable("a", "I", null, l0, l2, 0);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    cw.visitEnd();
    return cw.toByteArray();
  }

  @Test
  void composesWithEnterAndExitOnThrowableAdviceInBothOrders() throws Exception {
    byte[] plain = throwing();
    for (boolean adviceFirst : new boolean[] {true, false}) {
      for (LineProbeConfig cfg : List.of(LineProbeConfig.lineOnly(OWNER), LineProbeConfig.focused(OWNER))) {
        SiteRegistry reg = new SiteRegistry();
        List<MethodReport> reports = new ArrayList<>();
        ClassFileTransformer t =
            new AgentBuilder.Default()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .disableClassFormatChanges()
                .ignore(net.bytebuddy.matcher.ElementMatchers.none())
                .type(named("fixes.Thrower"))
                .transform(
                    (b, td, cl, m, pd) -> {
                      var advice = Advice.to(ProdAdvice.class).on(net.bytebuddy.matcher.ElementMatchers.isMethod().and(named("m")));
                      var wrapper =
                          new LineProbeAsmWrapper(cfg, reg, x -> LineProbeInstrumenter.blake3(plain), reports::addAll);
                      return adviceFirst ? b.visit(advice).visit(wrapper) : b.visit(wrapper).visit(advice);
                    })
                .makeRaw();
        Loader original = new Loader();
        original.define("fixes.Thrower", plain);
        byte[] out = t.transform(original, "fixes/Thrower", null, null, plain);
        assertNotNull(out, "transformer returned no bytes (adviceFirst=" + adviceFirst + ")");
        assertEquals(Status.INSTRUMENTED, reports.get(reports.size() - 1).status(), reports.toString());
        Class<?> c = new Loader().define("fixes.Thrower", out); // verifier runs here
        List<Integer> lines = new ArrayList<>();
        LineProbeDispatch.install(
            new LineProbeSink() {
              @Override
              public void line(int siteId) {
                lines.add(reg.site(siteId).line());
              }
            });
        try {
          ProdAdvice.entered = 0;
          ProdAdvice.exited = 0;
          ProdAdvice.thrown = 0;
          assertEquals(6, c.getMethod("m", int.class).invoke(null, 5));
          assertEquals(1, ProdAdvice.entered, "advice enter ran, adviceFirst=" + adviceFirst);
          assertEquals(1, ProdAdvice.exited);
          assertEquals(0, ProdAdvice.thrown);
          assertEquals(List.of(10, 12), lines);

          lines.clear();
          ProdAdvice.entered = 0;
          ProdAdvice.exited = 0;
          var ex = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> c.getMethod("m", int.class).invoke(null, -1));
          assertTrue(ex.getCause() instanceof IllegalStateException);
          assertEquals(1, ProdAdvice.entered);
          assertEquals(1, ProdAdvice.exited, "exit advice ran on the throwing path");
          assertEquals(1, ProdAdvice.thrown, "the thrown exception reached the exit advice");
          assertEquals(List.of(10, 11), lines);
        } finally {
          LineProbeDispatch.install(null);
        }
      }
    }
  }
}
