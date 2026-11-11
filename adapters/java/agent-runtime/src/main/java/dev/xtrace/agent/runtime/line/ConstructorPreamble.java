package dev.xtrace.agent.runtime.line;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * Recognizes a straight-line constructor preamble without reading uninitializedThis. More
 * complicated bytecode is preserved with an explicit gap, rather than guessing at initialization.
 */
public final class ConstructorPreamble extends MethodVisitor {
  private final String owner;
  private final String parent;
  private final Map<String, Integer> allocations = new HashMap<>();
  private final Set<Label> preambleLabels = new HashSet<>();
  private final Set<Label> protectedStarts = new HashSet<>();
  private boolean initialized;
  private boolean unsupported;
  private boolean nonTrivial;
  private int currentLine = -1;
  private int preambleLine = -1;
  private int calls;
  private int initializationCall;
  private int maxLocals;

  public ConstructorPreamble(String owner, String parent) {
    super(Opcodes.ASM9);
    this.owner = owner;
    this.parent = parent;
  }

  public boolean initialized() { return initialized; }
  public boolean supported() {
    return initialized && !unsupported && protectedStarts.stream().noneMatch(preambleLabels::contains);
  }
  public int initializationCall() { return initializationCall; }
  public int maxLocals() { return maxLocals; }

  /** Only proven loads/literals on the delegation line can omit the preamble gap. */
  public boolean trivial() { return supported() && !nonTrivial; }

  private void instruction(boolean loadOrLiteral) {
    if (initialized) return;
    if (preambleLine == -1) preambleLine = currentLine;
    if (!loadOrLiteral || currentLine <= 0 || currentLine != preambleLine) nonTrivial = true;
  }

  @Override
  public void visitLineNumber(int line, Label start) {
    currentLine = line;
  }

  @Override
  public void visitInsn(int opcode) {
    instruction(opcode >= Opcodes.ACONST_NULL && opcode <= Opcodes.DCONST_1);
  }

  @Override
  public void visitIntInsn(int opcode, int operand) {
    instruction(opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH);
  }

  @Override
  public void visitLdcInsn(Object value) {
    // Resolution of types, handles and dynamic constants can execute or fail: keep their gaps.
    instruction(value instanceof Integer || value instanceof Long || value instanceof Float
        || value instanceof Double || value instanceof String);
  }

  @Override
  public void visitFieldInsn(int opcode, String type, String name, String descriptor) {
    instruction(false);
  }

  @Override
  public void visitInvokeDynamicInsn(String name, String descriptor, Handle handle, Object... arguments) {
    instruction(false);
  }

  @Override
  public void visitIincInsn(int index, int increment) { instruction(false); }

  @Override
  public void visitMultiANewArrayInsn(String descriptor, int dimensions) { instruction(false); }

  @Override
  public void visitLabel(Label label) {
    if (!initialized) preambleLabels.add(label);
  }

  @Override
  public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
    protectedStarts.add(start);
  }

  @Override
  public void visitTypeInsn(int opcode, String type) {
    instruction(false);
    if (!initialized && opcode == Opcodes.NEW) allocations.merge(type, 1, Integer::sum);
  }

  @Override
  public void visitMethodInsn(int opcode, String type, String name, String descriptor, boolean itf) {
    calls++;
    if (initialized) return;
    if (opcode != Opcodes.INVOKESPECIAL || !name.equals("<init>")) {
      instruction(false);
      return;
    }
    int pending = allocations.getOrDefault(type, 0);
    if (pending > 0) {
      instruction(false);
      allocations.put(type, pending - 1);
    } else if (type.equals(owner) || type.equals(parent)) {
      instruction(true);
      initialized = true;
      initializationCall = calls;
    } else unsupported = true;
  }

  @Override
  public void visitJumpInsn(int opcode, Label label) {
    instruction(false);
    if (!initialized || opcode == Opcodes.JSR) unsupported = true;
  }

  @Override
  public void visitVarInsn(int opcode, int index) {
    instruction(opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD);
    if (opcode == Opcodes.RET) unsupported = true;
    // Aliasing uninitializedThis requires dataflow analysis; never infer it from an owner name.
    if (!initialized && opcode == Opcodes.ASTORE) unsupported = true;
  }

  @Override
  public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
    instruction(false);
    if (!initialized) unsupported = true;
  }

  @Override
  public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
    instruction(false);
    if (!initialized) unsupported = true;
  }

  @Override
  public void visitMaxs(int stack, int locals) { maxLocals = locals; }
}
