package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

/** Inconsistent LocalVariableTables and non-javac classes must fail open, never break class load. */
class LineProbeHostileLvtTest {
  static final String OWNER = LineProbeDispatch.INTERNAL_NAME;

  enum Lvt {
    VALID,
    OVERLAP_MISTYPED_SLOT1,
    OVERLAP_SAME_SLOT_HIGH_INDEX
  }

  /** {@code static int m(int a)}: b = 1; return b. Lines 10 and 11. */
  static byte[] build(String className, String source, boolean kotlinMetadata, Lvt lvt) {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
    if (source != null) cw.visitSource(source, null);
    if (kotlinMetadata) cw.visitAnnotation("Lkotlin/Metadata;", true).visitEnd();
    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m", "(I)I", null, null);
    mv.visitCode();
    int slot = lvt == Lvt.OVERLAP_SAME_SLOT_HIGH_INDEX ? 300 : 1;
    Label l0 = new Label();
    Label l1 = new Label();
    Label l2 = new Label();
    mv.visitLabel(l0);
    mv.visitLineNumber(10, l0);
    mv.visitInsn(Opcodes.ICONST_1);
    mv.visitVarInsn(Opcodes.ISTORE, slot);
    mv.visitLabel(l1);
    mv.visitLineNumber(11, l1);
    mv.visitVarInsn(Opcodes.ILOAD, slot);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitLabel(l2);
    mv.visitLocalVariable("a", "I", null, l0, l2, 0);
    mv.visitLocalVariable("b", "I", null, l1, l2, slot);
    if (lvt == Lvt.OVERLAP_MISTYPED_SLOT1) {
      mv.visitLocalVariable("bogus", "Ljava/lang/String;", null, l1, l2, slot);
    }
    if (lvt == Lvt.OVERLAP_SAME_SLOT_HIGH_INDEX) {
      mv.visitLocalVariable("bogus", "J", null, l1, l2, slot);
    }
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    cw.visitEnd();
    return cw.toByteArray();
  }

  static final class Loader extends ClassLoader {
    Loader() {
      super(LineProbeHostileLvtTest.class.getClassLoader());
    }

    Class<?> define(String name, byte[] b) {
      return defineClass(name, b, 0, b.length);
    }
  }

  private record Outcome(List<String> names, LineProbeInstrumenter.Result result, Object returned) {}

  private static Outcome run(byte[] bytes, String dotted, SiteRegistry reg, LineProbeInstrumenter.Result r)
      throws Exception {
    List<String> names = new ArrayList<>();
    LineProbeDispatch.install(
        new LineProbeSink() {
          @Override
          public void valueInt(int slot, int nameId, int v) {
            names.add(reg.name(nameId).name());
          }
        });
    try {
      Class<?> c = new Loader().define(dotted, r.bytes()); // verifier runs here
      return new Outcome(names, r, c.getMethod("m", int.class).invoke(null, 7));
    } finally {
      LineProbeDispatch.install(null);
    }
  }

  private static Outcome instrumentAndRun(byte[] bytes, String dotted) throws Exception {
    SiteRegistry reg = new SiteRegistry();
    LineProbeInstrumenter.Result r =
        new LineProbeInstrumenter(LineProbeConfig.focused(OWNER), reg).instrument(bytes);
    return run(bytes, dotted, reg, r);
  }

  private static MethodReport m(LineProbeInstrumenter.Result r) {
    for (MethodReport x : r.methods()) if (x.name().equals("m")) return x;
    throw new AssertionError(r.methods().toString());
  }

  @Test
  void validJavacShapedTableReadsBothLocals() throws Exception {
    Outcome o = instrumentAndRun(build("hostile/Valid", "Valid.java", false, Lvt.VALID), "hostile.Valid");
    assertEquals(1, o.returned());
    assertTrue(o.names().contains("a") && o.names().contains("b"), o.names().toString());
  }

  @Test
  void overlappingMistypedEntriesForOneSlotAreDroppedAndTheClassStillVerifies() throws Exception {
    Outcome o =
        instrumentAndRun(
            build("hostile/Over", "Over.java", false, Lvt.OVERLAP_MISTYPED_SLOT1), "hostile.Over");
    assertEquals(1, o.returned());
    assertTrue(o.names().contains("a"));
    assertTrue(!o.names().contains("b") && !o.names().contains("bogus"), o.names().toString());
  }

  @Test
  void overlapOnSlotsAbove255IsDroppedToo() throws Exception {
    Outcome o =
        instrumentAndRun(
            build("hostile/High", "High.java", false, Lvt.OVERLAP_SAME_SLOT_HIGH_INDEX), "hostile.High");
    assertEquals(1, o.returned());
    assertTrue(o.names().contains("a"));
    assertTrue(!o.names().contains("b") && !o.names().contains("bogus"), o.names().toString());
  }

  @Test
  void kotlinScalaGroovyAndUnknownSourcesNeverReadValuesButStillTraceLines() throws Exception {
    byte[][] cases = {
      build("hostile/K", "K.java", true, Lvt.VALID), // kotlin.Metadata marker
      build("hostile/NoSrc", null, false, Lvt.VALID), // no SourceFile
      build("hostile/Kt", "Kt.kt", false, Lvt.VALID),
      build("hostile/Sc", "Sc.scala", false, Lvt.VALID)
    };
    String[] names = {"hostile.K", "hostile.NoSrc", "hostile.Kt", "hostile.Sc"};
    for (int i = 0; i < cases.length; i++) {
      Outcome o = instrumentAndRun(cases[i], names[i]);
      assertEquals(1, o.returned());
      assertTrue(o.names().isEmpty(), names[i] + " read " + o.names());
      MethodReport rep = m(o.result());
      assertEquals(MethodReport.Status.INSTRUMENTED, rep.status());
      assertEquals(2, rep.sites(), names[i]);
      assertEquals(0, rep.valueCalls());
      assertEquals(MethodReport.Reasons.VALUES_NON_JAVAC, rep.valuesReason());
    }
  }
}
