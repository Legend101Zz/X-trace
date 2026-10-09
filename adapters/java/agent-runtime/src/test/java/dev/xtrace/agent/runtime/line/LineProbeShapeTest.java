package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.line.MethodReport.Status;
import java.lang.instrument.ClassFileTransformer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.jar.asm.AnnotationVisitor;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.RecordComponentVisitor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Retransformation safety: the instrumented class has exactly the original shape (no member,
 * attribute or hierarchy change), only Code differs, and every LineNumberTable entry run maps to
 * exactly one probe.
 */
class LineProbeShapeTest {
  static final String OWNER = LineProbeDispatch.INTERNAL_NAME;

  @TempDir Path tmp;

  static final String GOLDEN =
      "package linecorpus;\n" // 1
          + "public final class Golden {\n" // 2
          + "  public static int s_f(int a) {\n" // 3
          + "    int b = a + 1;\n" // 4
          + "    if (b > 2) {\n" // 5
          + "      b *= 2;\n" // 6
          + "    }\n" // 7
          + "    return b;\n" // 8
          + "  }\n" // 9
          + "  interface Shape { int area(); }\n" // 10
          + "  record Sq(int side) implements Shape { public int area() { return side * side; } }\n" // 11
          + "  enum Color { RED, GREEN; int code() { return ordinal() + 1; } }\n" // 12
          + "}\n";

  /** Everything except Code, as a comparable list of strings. */
  static List<String> shapeOf(byte[] bytes) {
    List<String> out = new ArrayList<>();
    new ClassReader(bytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public void visit(int v, int acc, String n, String sig, String sup, String[] itf) {
                out.add("class " + v + " " + acc + " " + n + " " + sig + " " + sup + " " + java.util.Arrays.toString(itf));
              }

              @Override
              public void visitSource(String s, String d) {
                out.add("source " + s + " " + d);
              }

              @Override
              public void visitOuterClass(String o, String n, String d) {
                out.add("outer " + o + " " + n + " " + d);
              }

              @Override
              public void visitNestHost(String h) {
                out.add("nestHost " + h);
              }

              @Override
              public void visitNestMember(String m) {
                out.add("nestMember " + m);
              }

              @Override
              public void visitPermittedSubclass(String p) {
                out.add("permitted " + p);
              }

              @Override
              public void visitInnerClass(String n, String o, String i, int a) {
                out.add("inner " + n + " " + o + " " + i + " " + a);
              }

              @Override
              public AnnotationVisitor visitAnnotation(String d, boolean v) {
                out.add("classAnn " + d);
                return null;
              }

              @Override
              public RecordComponentVisitor visitRecordComponent(String n, String d, String s) {
                out.add("component " + n + " " + d + " " + s);
                return null;
              }

              @Override
              public FieldVisitor visitField(int a, String n, String d, String s, Object v) {
                out.add("field " + a + " " + n + " " + d + " " + s + " " + v);
                return null;
              }

              @Override
              public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                out.add("method " + a + " " + n + " " + d + " " + s + " " + java.util.Arrays.toString(e));
                return new MethodVisitor(Opcodes.ASM9) {
                  @Override
                  public AnnotationVisitor visitAnnotation(String ad, boolean v) {
                    out.add("  ann " + ad);
                    return null;
                  }

                  @Override
                  public void visitParameter(String pn, int pa) {
                    out.add("  param " + pn + " " + pa);
                  }
                };
              }
            },
            0);
    return out;
  }

  /** Per method: {probe calls, independent count of instruction runs following a line entry}. */
  static Map<String, int[]> probeAndRunCounts(byte[] bytes) {
    Map<String, int[]> out = new java.util.TreeMap<>();
    new ClassReader(bytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
                int[] c = new int[2];
                out.put(n + d, c);
                return new MethodVisitor(Opcodes.ASM9) {
                  boolean pending;

                  private void real() {
                    if (pending) {
                      c[1]++;
                      pending = false;
                    }
                  }

                  @Override
                  public void visitLineNumber(int l, net.bytebuddy.jar.asm.Label st) {
                    pending = true;
                  }

                  @Override
                  public void visitMethodInsn(int op, String o, String mn, String md, boolean i) {
                    if (op == Opcodes.INVOKESTATIC && o.equals(OWNER) && mn.equals("line") && md.equals("(I)V")) {
                      c[0]++;
                      return; // our own probe does not start a run of the original code
                    }
                    if (o.equals(OWNER)) return;
                    real();
                  }

                  @Override public void visitInsn(int op) { real(); }
                  @Override public void visitIntInsn(int op, int x) { real(); }
                  @Override public void visitVarInsn(int op, int x) { real(); }
                  @Override public void visitTypeInsn(int op, String t) { real(); }
                  @Override public void visitFieldInsn(int op, String o, String n2, String d2) { real(); }
                  @Override public void visitInvokeDynamicInsn(String n2, String d2, net.bytebuddy.jar.asm.Handle h, Object... x) { real(); }
                  @Override public void visitJumpInsn(int op, net.bytebuddy.jar.asm.Label l) { real(); }
                  @Override public void visitLdcInsn(Object v) { real(); }
                  @Override public void visitIincInsn(int v, int i) { real(); }
                  @Override public void visitTableSwitchInsn(int mn, int mx, net.bytebuddy.jar.asm.Label d2, net.bytebuddy.jar.asm.Label... l) { real(); }
                  @Override public void visitLookupSwitchInsn(net.bytebuddy.jar.asm.Label d2, int[] k, net.bytebuddy.jar.asm.Label[] l) { real(); }
                  @Override public void visitMultiANewArrayInsn(String d2, int dm) { real(); }
                };
              }
            },
            0);
    return out;
  }

  private CorpusPipeline build(LineProbeConfig cfg) throws Exception {
    return CorpusPipeline.build(
        tmp.resolve("shape"), new SiteRegistry(), Map.of("Golden", GOLDEN), new String[] {"-g"},
        CorpusPipeline.byteApi(cfg));
  }

  @Test
  void onlyCodeChangesAndEveryLineEntryRunHasExactlyOneProbe() throws Exception {
    for (LineProbeConfig cfg : List.of(LineProbeConfig.lineOnly(OWNER), LineProbeConfig.focused(OWNER))) {
      CorpusPipeline p = build(cfg);
      int instrumentedMethods = 0;
      for (var e : p.results.entrySet()) {
        byte[] before = p.plainBytes.get(e.getKey());
        byte[] after = e.getValue().bytes();
        assertEquals(shapeOf(before), shapeOf(after), "shape changed: " + e.getKey());
        Map<String, int[]> beforeCounts = probeAndRunCounts(before);
        Map<String, int[]> afterCounts = probeAndRunCounts(after);
        assertEquals(beforeCounts.keySet(), afterCounts.keySet());
        for (String m : afterCounts.keySet()) {
          assertEquals(0, beforeCounts.get(m)[0], "no probes before: " + m);
          MethodReport rep = null;
          for (MethodReport r : e.getValue().methods()) {
            if ((r.name() + r.descriptor()).equals(m)) rep = r;
          }
          int probes = afterCounts.get(m)[0];
          if (rep != null && rep.status() == Status.INSTRUMENTED) {
            instrumentedMethods++;
            assertEquals(rep.sites(), probes, e.getKey() + "." + m);
            assertEquals(beforeCounts.get(m)[1], probes, "runs vs probes " + e.getKey() + "." + m);
          } else {
            assertEquals(0, probes, e.getKey() + "." + m);
          }
        }
      }
      assertTrue(instrumentedMethods > 20, "methods instrumented: " + instrumentedMethods);
    }
  }

  @Test
  void goldenLineTableMapsToExactlyTheExpectedSites() throws Exception {
    CorpusPipeline p = build(LineProbeConfig.lineOnly(OWNER));
    MethodReport rep = null;
    for (MethodReport r : p.results.get("linecorpus/Golden").methods()) {
      if (r.name().equals("s_f")) rep = r;
    }
    assertEquals(Status.INSTRUMENTED, rep.status());
    List<Integer> lines = new ArrayList<>();
    for (int id = 1; id <= p.registry.siteCount(); id++) {
      SiteRegistry.Site s = p.registry.site(id);
      if (s.classInternalName().equals("linecorpus/Golden") && s.method().equals("s_f")) lines.add(s.line());
    }
    assertEquals(List.of(4, 5, 6, 8), lines);
  }

  /** Advice used only to prove composition with a real boundary-style transformation. */
  public static final class BoundaryAdvice {
    public static int entered;

    @Advice.OnMethodEnter
    static void enter() {
      entered++;
    }
  }

  static final class Loader extends ClassLoader {
    Loader() {
      super(LineProbeShapeTest.class.getClassLoader());
    }

    private final Map<String, byte[]> served = new java.util.HashMap<>();

    void serve(String resource, byte[] b) {
      served.put(resource, b);
    }

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

  @Test
  void composesWithAdviceUnderDisableClassFormatChangesAndVerifiesAndRuns() throws Exception {
    CorpusPipeline p = build(LineProbeConfig.lineOnly(OWNER));
    byte[] plain = p.plainBytes.get("linecorpus/Golden");
    SiteRegistry reg = new SiteRegistry();
    List<MethodReport> reports = new ArrayList<>();
    ClassFileTransformer t =
        new AgentBuilder.Default()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .disableClassFormatChanges() // forbids adding any member: would throw
            .ignore(net.bytebuddy.matcher.ElementMatchers.none())
            .type(named("linecorpus.Golden"))
            .transform(
                (b, td, cl, m, pd) ->
                    b.visit(Advice.to(BoundaryAdvice.class).on(isMethod().and(named("s_f"))))
                        .visit(
                            new LineProbeAsmWrapper(
                                LineProbeConfig.lineOnly(OWNER), reg,
                                x -> LineProbeInstrumenter.blake3(plain), reports::addAll)))
            .makeRaw();
    // 1) first load, 2) "retransformation" of an already loaded class (classBeingRedefined set)
    Loader original = new Loader();
    for (var e : p.plainBytes.entrySet()) original.serve(e.getKey() + ".class", e.getValue());
    Class<?> loaded = original.define("linecorpus.Golden", plain);
    for (Class<?> redefined : new Class<?>[] {null, loaded}) {
      byte[] out = t.transform(original, "linecorpus/Golden", redefined, null, plain);
      assertTrue(out != null, "transformer returned no bytes");
      assertEquals(shapeOf(plain), shapeOf(out), "class shape must not change");
      Loader fresh = new Loader(); // default verification applies to non-boot loaders
      Class<?> c = fresh.define("linecorpus.Golden", out);
      List<Integer> lines = new ArrayList<>();
      LineProbeDispatch.install(
          new LineProbeSink() {
            @Override
            public void line(int siteId) {
              lines.add(reg.site(siteId).line());
            }
          });
      try {
        BoundaryAdvice.entered = 0;
        assertEquals(8, c.getMethod("s_f", int.class).invoke(null, 3)); // b = 4 -> 8
        assertEquals(1, BoundaryAdvice.entered, "the Advice half must have run");
      } finally {
        LineProbeDispatch.install(null);
      }
      assertEquals(List.of(4, 5, 6, 8), lines);
    }
    assertFalse(reports.isEmpty());
  }
}
