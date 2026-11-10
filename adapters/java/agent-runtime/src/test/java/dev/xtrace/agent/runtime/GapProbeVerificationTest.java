package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import dev.xtrace.agent.runtime.line.LineProbeAsmWrapper;
import dev.xtrace.agent.runtime.line.LineProbeConfig;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;

/** Loads and executes gap guards both alone and with the production boundary composition. */
class GapProbeVerificationTest {
  @Test
  void standaloneGapGuardsVerifyCompressedFramesConstructorsAndRealLambdas() throws Exception {
    verify(false);
  }

  @Test
  void composedGapGuardsVerifyCompressedFramesConstructorsAndRealLambdas() throws Exception {
    verify(true);
  }

  private void verify(boolean composed) throws Exception {
    assertTrue(ManagementFactory.getRuntimeMXBean().getInputArguments().contains("-Xverify:all"));
    String name = "demo.probe.CompressedGapFrames";
    byte[] original = compressed(name.replace('.', '/'));
    Set<Integer> formats = new HashSet<>();
    new ClassReader(original).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String method, String descriptor,
          String signature, String[] exceptions) {
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitFrame(int kind, int nLocal, Object[] locals, int nStack, Object[] stack) {
            formats.add(kind);
          }
        };
      }
    }, 0);
    assertTrue(formats.containsAll(Set.of(Opcodes.F_SAME, Opcodes.F_APPEND, Opcodes.F_CHOP)), formats.toString());
    Class<?> type = transform(name, original, composed);
    assertNotNull(type.getConstructor(boolean.class).newInstance(true));
    assertNotNull(type.getConstructor(boolean.class).newInstance(false));
    assertEquals(7, type.getMethod("choose", boolean.class).invoke(null, true));
    assertEquals(5, type.getMethod("choose", boolean.class).invoke(null, false));

    String lambdaName = "demo.probe.LambdaOrders";
    byte[] lambda = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()).locate(lambdaName).resolve();
    ClassWriter stripped = new ClassWriter(0);
    new ClassReader(lambda).accept(stripped, ClassReader.SKIP_DEBUG);
    Class<?> lambdas = transform(lambdaName, stripped.toByteArray(), composed);
    Object target = lambdas.getConstructor().newInstance();
    assertEquals("ABC", lambdas.getMethod("create", String.class).invoke(target, " abc "));
    assertEquals(3, lambdas.getMethod("create", int.class).invoke(target, 3));
  }

  private Class<?> transform(String name, byte[] original, boolean composed) {
    ClassLoader parent = getClass().getClassLoader();
    List<MethodReport> reports = new ArrayList<>();
    // Force every method to take the skipped-entry path, including methods with existing frames.
    var wrapper = new LineProbeAsmWrapper(LineProbeConfig.focused("unavailable/LineOwner"),
        new SiteRegistry(), ignored -> null, reports::addAll, parent) {
      @Override
      protected int skippedMethodEntryBytes() { return 3; }

      @Override
      protected void skippedMethodEntry(MethodVisitor method) {
        // Resolution fails at execution: the caller-side guard itself must suppress it.
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "unavailable/GapOwner", "gap", "()V", false);
      }
    };
    var locator = new ClassFileLocator.Compound(ClassFileLocator.Simple.of(name, original),
        ClassFileLocator.ForClassLoader.of(parent));
    byte[] transformed = new ByteBuddy().redefine(TypePool.Default.of(locator).describe(name).resolve(), locator)
        .visit(composed ? FixtureInstrumentation.boundedProbes(wrapper,
            new FixtureInstrumentation.CaptureLimitations(), new HashSet<>()) : wrapper)
        .make().getBytes();
    int[] guards = {0};
    Set<String> gapMethods = new HashSet<>();
    new ClassReader(transformed).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String method, String descriptor,
          String signature, String[] exceptions) {
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitMethodInsn(int opcode, String owner, String called, String desc, boolean itf) {
            if (owner.equals("unavailable/GapOwner")) gapMethods.add(method);
          }

          @Override
          public void visitTryCatchBlock(Label start, Label end, Label handler, String catchType) {
            if ("java/lang/Throwable".equals(catchType)) guards[0]++;
          }
        };
      }
    }, 0);
    assertTrue(guards[0] >= 2, "both entry guards and original method bodies must survive");
    assertTrue(gapMethods.contains("<init>"), "the constructor must execute a guarded gap call");
    if (name.endsWith("CompressedGapFrames")) assertTrue(gapMethods.contains("choose"));
    else assertTrue(gapMethods.stream().anyMatch(method -> method.startsWith("lambda$")),
        "the real lambda body must execute a guarded gap call");
    return new ClassLoader(parent) {
      Class<?> define() { return defineClass(name, transformed, 0, transformed.length); }
    }.define();
  }

  @Test
  void verifierRejectsAnInvalidMethodBodyAsANegativeControl() {
    ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/probe/InvalidVerificationControl", null,
        "java/lang/Object", null);
    MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "broken", "()I", null, null);
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitInsn(Opcodes.IRETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    byte[] bytes = writer.toByteArray();
    assertThrows(VerifyError.class, () -> new ClassLoader(getClass().getClassLoader()) {
      Class<?> define() { return defineClass(null, bytes, 0, bytes.length); }
    }.define().getDeclaredMethods());
  }

  private static byte[] compressed(String owner) {
    ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null);
    MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "(Z)V", null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    Label initialized = new Label();
    constructor.visitVarInsn(Opcodes.ILOAD, 1);
    constructor.visitJumpInsn(Opcodes.IFEQ, initialized);
    constructor.visitInsn(Opcodes.NOP);
    constructor.visitLabel(initialized);
    constructor.visitFrame(Opcodes.F_FULL, 2, new Object[] {owner, Opcodes.INTEGER}, 0, null);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 2);
    constructor.visitEnd();

    MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "choose", "(Z)I", null, null);
    Label start = new Label(), append = new Label(), same = new Label(), chop = new Label();
    Label end = new Label(), handler = new Label();
    method.visitCode();
    method.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException");
    method.visitLabel(start);
    method.visitVarInsn(Opcodes.ILOAD, 0);
    method.visitJumpInsn(Opcodes.IFEQ, append);
    method.visitIntInsn(Opcodes.BIPUSH, 7);
    method.visitInsn(Opcodes.IRETURN);
    method.visitLabel(append);
    method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
    method.visitInsn(Opcodes.ICONST_1);
    method.visitVarInsn(Opcodes.ISTORE, 1);
    method.visitJumpInsn(Opcodes.GOTO, same);
    method.visitLabel(same);
    method.visitFrame(Opcodes.F_APPEND, 1, new Object[] {Opcodes.INTEGER}, 0, null);
    method.visitVarInsn(Opcodes.ILOAD, 0);
    method.visitJumpInsn(Opcodes.IFEQ, chop);
    method.visitIincInsn(1, 1);
    method.visitLabel(chop);
    method.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
    method.visitInsn(Opcodes.ICONST_5);
    method.visitInsn(Opcodes.IRETURN);
    method.visitLabel(end);
    method.visitLabel(handler);
    method.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] {"java/lang/RuntimeException"});
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.ICONST_M1);
    method.visitInsn(Opcodes.IRETURN);
    method.visitMaxs(1, 2);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
