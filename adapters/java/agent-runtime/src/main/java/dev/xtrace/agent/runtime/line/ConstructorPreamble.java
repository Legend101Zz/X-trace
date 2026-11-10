package dev.xtrace.agent.runtime.line;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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
    if (!initialized && opcode == Opcodes.NEW) allocations.merge(type, 1, Integer::sum);
  }

  @Override
  public void visitMethodInsn(int opcode, String type, String name, String descriptor, boolean itf) {
    calls++;
    if (initialized || opcode != Opcodes.INVOKESPECIAL || !name.equals("<init>")) return;
    int pending = allocations.getOrDefault(type, 0);
    if (pending > 0) allocations.put(type, pending - 1);
    else if (type.equals(owner) || type.equals(parent)) {
      initialized = true;
      initializationCall = calls;
    } else unsupported = true;
  }

  @Override
  public void visitJumpInsn(int opcode, Label label) {
    if (!initialized || opcode == Opcodes.JSR) unsupported = true;
  }

  @Override
  public void visitVarInsn(int opcode, int index) {
    if (opcode == Opcodes.RET) unsupported = true;
    // Aliasing uninitializedThis requires dataflow analysis; never infer it from an owner name.
    if (!initialized && opcode == Opcodes.ASTORE) unsupported = true;
  }

  @Override
  public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
    if (!initialized) unsupported = true;
  }

  @Override
  public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
    if (!initialized) unsupported = true;
  }

  @Override
  public void visitMaxs(int stack, int locals) { maxLocals = locals; }
}
