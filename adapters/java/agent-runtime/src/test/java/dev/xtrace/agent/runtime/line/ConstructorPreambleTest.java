package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.function.Consumer;
import net.bytebuddy.jar.asm.ConstantDynamic;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import org.junit.jupiter.api.Test;

class ConstructorPreambleTest {
  private static final String OWNER = "demo/Child";
  private static final String PARENT = "demo/Parent";

  private ConstructorPreamble start() {
    ConstructorPreamble preamble = new ConstructorPreamble(OWNER, PARENT);
    preamble.visitCode();
    line(preamble, 10);
    preamble.visitVarInsn(Opcodes.ALOAD, 0);
    return preamble;
  }

  private void line(MethodVisitor method, int number) {
    Label label = new Label();
    method.visitLabel(label);
    method.visitLineNumber(number, label);
  }

  private void delegate(ConstructorPreamble preamble) {
    preamble.visitMethodInsn(Opcodes.INVOKESPECIAL, PARENT, "<init>", "()V", false);
    preamble.visitInsn(Opcodes.RETURN);
    preamble.visitMaxs(10, 10);
  }

  @Test
  void loadsAndLiteralConstantsOnTheDelegationLineAreTrivial() {
    ConstructorPreamble preamble = start();
    for (int opcode : new int[] {Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD,
        Opcodes.DLOAD, Opcodes.ALOAD}) preamble.visitVarInsn(opcode, 1);
    for (int opcode = Opcodes.ACONST_NULL; opcode <= Opcodes.DCONST_1; opcode++) {
      preamble.visitInsn(opcode);
    }
    preamble.visitIntInsn(Opcodes.BIPUSH, 42);
    preamble.visitIntInsn(Opcodes.SIPUSH, 1000);
    for (Object value : List.of(100_000, 100L, 2.5f, 2.5d, "literal")) preamble.visitLdcInsn(value);
    delegate(preamble);
    assertTrue(preamble.trivial());
  }

  @Test
  void evenLoadsOnAnotherExecutableSourceLineKeepTheGap() {
    ConstructorPreamble preamble = start();
    line(preamble, 11);
    delegate(preamble);
    assertTrue(preamble.supported());
    assertFalse(preamble.trivial());
  }

  @Test
  void lineEntriesWithNoInstructionOfTheirOwnDoNotInventLostObservations() {
    ConstructorPreamble preamble = new ConstructorPreamble(OWNER, PARENT);
    preamble.visitCode();
    line(preamble, 9);
    line(preamble, 10);
    preamble.visitVarInsn(Opcodes.ALOAD, 0);
    delegate(preamble);
    line(preamble, 11);
    preamble.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "body", "()V", false);
    assertTrue(preamble.trivial(), "body instructions must not change preamble classification");
  }

  @Test
  void missingLineInformationKeepsTheGap() {
    ConstructorPreamble preamble = new ConstructorPreamble(OWNER, PARENT);
    preamble.visitVarInsn(Opcodes.ALOAD, 0);
    delegate(preamble);
    assertTrue(preamble.supported());
    assertFalse(preamble.trivial());
  }

  @Test
  void callsAllocationsFieldReadsArithmeticAndOtherInstructionsKeepTheGap() {
    Handle bootstrap = new Handle(Opcodes.H_INVOKESTATIC, OWNER, "bootstrap", "()V", false);
    List<Consumer<MethodVisitor>> nonTrivial = List.of(
        method -> method.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "compute", "()I", false),
        method -> method.visitTypeInsn(Opcodes.NEW, PARENT),
        method -> method.visitFieldInsn(Opcodes.GETSTATIC, OWNER, "value", "I"),
        method -> method.visitFieldInsn(Opcodes.GETFIELD, OWNER, "value", "I"),
        method -> method.visitInsn(Opcodes.IADD),
        method -> method.visitInsn(Opcodes.NOP),
        method -> method.visitVarInsn(Opcodes.ISTORE, 1),
        method -> method.visitIincInsn(1, 1),
        method -> method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT),
        method -> method.visitMultiANewArrayInsn("[[I", 2),
        method -> method.visitInvokeDynamicInsn("compute", "()I", bootstrap),
        method -> method.visitLdcInsn(Type.getObjectType(OWNER)),
        method -> method.visitLdcInsn(bootstrap),
        method -> method.visitLdcInsn(new ConstantDynamic("value", "I", bootstrap)));
    for (int i = 0; i < nonTrivial.size(); i++) {
      ConstructorPreamble preamble = start();
      nonTrivial.get(i).accept(preamble);
      delegate(preamble);
      assertFalse(preamble.trivial(), "instruction case " + i);
    }
  }

  @Test
  void branchesAndProtectedPreamblesAreNeverTrivial() {
    ConstructorPreamble branch = start();
    branch.visitJumpInsn(Opcodes.IFEQ, new Label());
    delegate(branch);
    assertFalse(branch.supported());
    assertFalse(branch.trivial());

    ConstructorPreamble protectedPreamble = start();
    Label start = new Label();
    protectedPreamble.visitTryCatchBlock(start, new Label(), new Label(), "java/lang/Throwable");
    protectedPreamble.visitLabel(start);
    delegate(protectedPreamble);
    assertFalse(protectedPreamble.supported());
    assertFalse(protectedPreamble.trivial());
  }
}
