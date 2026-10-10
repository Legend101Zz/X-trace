package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.line.CorpusHarness.Run;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Proves the -Xverify:all child really verifies, and that the Byte Buddy wrapper path is clean. */
class LineProbeVerifierGuardTest {
  static final String OWNER = LineProbeDispatch.INTERNAL_NAME;

  @TempDir Path tmp;

  @Test
  void negativeControlStackImbalanceIsRejectedByTheChildVerifier() throws Exception {
    // Deliberately wrong "probe": pushes without popping. If the child did not verify, this would load.
    CorpusPipeline p =
        CorpusPipeline.build(
            tmp.resolve("neg"), new SiteRegistry(), CorpusPipeline.noExtra(), new String[] {"-g"},
            reg -> (name, bytes) -> new LineProbeInstrumenter.Result(bytes, false, "", List.of()));
    byte[] original = p.plainBytes.get("linecorpus/Trace");
    byte[] broken = brokenTypeError(original);
    Files.write(p.instrDir.resolve("linecorpus/Trace.class"), broken);
    CorpusPipeline.Child c = p.runChild();
    assertTrue(c.stderr().contains("VerifyError"), c.stderr());
    assertTrue(c.exit() != 0 || c.loadFailed().stream().anyMatch(x -> x.startsWith("linecorpus.Trace")));
  }

  private static byte[] brokenTypeError(byte[] original) {
    ClassReader reader = new ClassReader(original);
    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(
        new ClassVisitor(Opcodes.ASM9, writer) {
          @Override
          public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
            MethodVisitor mv = super.visitMethod(a, n, d, s, e);
            if (!n.equals("hit") || !d.equals("(Ljava/lang/String;)V")) return mv;
            return new MethodVisitor(Opcodes.ASM9, mv) {
              @Override
              public void visitCode() {
                super.visitCode();
                super.visitInsn(Opcodes.ICONST_1);
                super.visitInsn(Opcodes.ARETURN); // returning an int as a reference in a void method
              }
            };
          }
        },
        0);
    return writer.toByteArray();
  }

  @Test
  void byteBuddyWrapperProducesVerifierCleanEquivalentOutput() throws Exception {
    LineProbeConfig cfg = LineProbeConfig.focused(OWNER);
    CorpusPipeline p =
        CorpusPipeline.build(
            tmp.resolve("bb"), new SiteRegistry(), CorpusPipeline.noExtra(), new String[] {"-g"},
            reg -> {
              return (internal, bytes) -> {
                try {
                  String dotted = internal.replace('/', '.');
                  ClassFileLocator locator = new ClassFileLocator.ForFolder(tmp.resolve("bb").resolve("plain").toFile());
                  TypePool pool =
                      TypePool.Default.of(
                          new ClassFileLocator.Compound(locator, ClassFileLocator.ForClassLoader.ofSystemLoader()));
                  var type = pool.describe(internal.replace('/', '.')).resolve();
                  List<MethodReport> reports = new java.util.ArrayList<>();
                  byte[] out =
                      new ByteBuddy()
                          .with(TypeValidation.DISABLED)
                          .redefine(type, locator)
                          .visit(new LineProbeAsmWrapper(cfg, reg, t -> LineProbeInstrumenter.blake3(bytes), reports::addAll))
                          .make()
                          .getBytes();
                  return new LineProbeInstrumenter.Result(out, true, "", reports);
                } catch (Exception e) {
                  throw new IllegalStateException(e);
                }
              };
            });
    CorpusPipeline.Child c = p.runChild();
    assertEquals(0, c.exit(), c.stderr());
    assertTrue(c.loadFailed().isEmpty(), c.loadFailed() + c.stderr());
    List<Run> plain = p.runPlain();
    assertEquals(plain.size(), c.runs().size());
    int events = 0;
    for (int i = 0; i < plain.size(); i++) {
      assertEquals(plain.get(i).result(), c.runs().get(i).result(), plain.get(i).name());
      for (String t : c.runs().get(i).tokens()) if (t.startsWith("L ")) events++;
    }
    assertTrue(events > 100, "events through the Byte Buddy wrapper: " + events);
    assertFalse(p.registry.siteCount() == 0);
  }
}
