package dev.xtrace.agent.runtime.line;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import net.bytebuddy.jar.asm.AnnotationVisitor;
import net.bytebuddy.jar.asm.Attribute;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.TypePath;

/**
 * Holds a method until composed instrumentation has been budgeted. Labels remain unresolved:
 * exactly one selected buffer is replayed to the class writer, including its annotations.
 */
public final class BufferedMethodVisitor extends MethodVisitor {
  private final List<Consumer<MethodVisitor>> operations = new ArrayList<>();
  private final Consumer<BufferedMethodVisitor> completed;
  private long bytes;
  private int handlers;
  private int stack;
  private int locals;

  public BufferedMethodVisitor(Consumer<BufferedMethodVisitor> completed) {
    super(Opcodes.ASM9);
    this.completed = completed;
  }

  /** Conservative final bounds include wide branches, local indexes and switch padding. */
  public boolean fits() {
    return bytes <= 65_535 && handlers <= 65_535 && stack <= 65_535 && locals <= 65_535;
  }

  public void replay(MethodVisitor target) {
    for (var operation : operations) operation.accept(target);
  }

  private void instruction(int size, Consumer<MethodVisitor> operation) {
    bytes += size;
    operations.add(operation);
  }

  private AnnotationVisitor annotation(Function<MethodVisitor, AnnotationVisitor> target) {
    AnnotationRecorder annotation = new AnnotationRecorder();
    operations.add(method -> {
      AnnotationVisitor visitor = target.apply(method);
      if (visitor != null) annotation.replay(visitor);
    });
    return annotation;
  }

  @Override
  public void visitParameter(String name, int access) {
    operations.add(method -> method.visitParameter(name, access));
  }

  @Override
  public AnnotationVisitor visitAnnotationDefault() {
    return annotation(MethodVisitor::visitAnnotationDefault);
  }

  @Override
  public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
    return annotation(method -> method.visitAnnotation(descriptor, visible));
  }

  @Override
  public AnnotationVisitor visitTypeAnnotation(int ref, TypePath path, String descriptor, boolean visible) {
    return annotation(method -> method.visitTypeAnnotation(ref, path, descriptor, visible));
  }

  @Override
  public void visitAnnotableParameterCount(int count, boolean visible) {
    operations.add(method -> method.visitAnnotableParameterCount(count, visible));
  }

  @Override
  public AnnotationVisitor visitParameterAnnotation(int parameter, String descriptor, boolean visible) {
    return annotation(method -> method.visitParameterAnnotation(parameter, descriptor, visible));
  }

  @Override
  public void visitAttribute(Attribute attribute) {
    operations.add(method -> method.visitAttribute(attribute));
  }

  @Override
  public void visitCode() {
    operations.add(MethodVisitor::visitCode);
  }

  @Override
  public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] values) {
    Object[] l = local == null ? null : local.clone();
    Object[] s = values == null ? null : values.clone();
    operations.add(method -> method.visitFrame(type, nLocal, l, nStack, s));
  }

  @Override
  public void visitInsn(int opcode) {
    instruction(1, method -> method.visitInsn(opcode));
  }

  @Override
  public void visitIntInsn(int opcode, int operand) {
    instruction(3, method -> method.visitIntInsn(opcode, operand));
  }

  @Override
  public void visitVarInsn(int opcode, int index) {
    int width = opcode == Opcodes.LLOAD || opcode == Opcodes.DLOAD
        || opcode == Opcodes.LSTORE || opcode == Opcodes.DSTORE ? 2 : 1;
    locals = Math.max(locals, index + width);
    instruction(4, method -> method.visitVarInsn(opcode, index));
  }

  @Override
  public void visitTypeInsn(int opcode, String type) {
    instruction(3, method -> method.visitTypeInsn(opcode, type));
  }

  @Override
  public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
    instruction(3, method -> method.visitFieldInsn(opcode, owner, name, descriptor));
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean itf) {
    instruction(5, method -> method.visitMethodInsn(opcode, owner, name, descriptor, itf));
  }

  @Override
  public void visitInvokeDynamicInsn(String name, String descriptor, Handle handle, Object... arguments) {
    Object[] copy = arguments.clone();
    instruction(5, method -> method.visitInvokeDynamicInsn(name, descriptor, handle, copy));
  }

  @Override
  public void visitJumpInsn(int opcode, Label label) {
    instruction(8, method -> method.visitJumpInsn(opcode, label));
  }

  @Override
  public void visitLabel(Label label) {
    operations.add(method -> method.visitLabel(label));
  }

  @Override
  public void visitLdcInsn(Object value) {
    instruction(3, method -> method.visitLdcInsn(value));
  }

  @Override
  public void visitIincInsn(int index, int increment) {
    locals = Math.max(locals, index + 1);
    instruction(6, method -> method.visitIincInsn(index, increment));
  }

  @Override
  public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
    Label[] copy = labels.clone();
    instruction(16 + 4 * copy.length, method -> method.visitTableSwitchInsn(min, max, dflt, copy));
  }

  @Override
  public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
    int[] k = keys.clone();
    Label[] l = labels.clone();
    instruction(12 + 8 * l.length, method -> method.visitLookupSwitchInsn(dflt, k, l));
  }

  @Override
  public void visitMultiANewArrayInsn(String descriptor, int dimensions) {
    instruction(4, method -> method.visitMultiANewArrayInsn(descriptor, dimensions));
  }

  @Override
  public AnnotationVisitor visitInsnAnnotation(int ref, TypePath path, String descriptor, boolean visible) {
    return annotation(method -> method.visitInsnAnnotation(ref, path, descriptor, visible));
  }

  @Override
  public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
    handlers++;
    operations.add(method -> method.visitTryCatchBlock(start, end, handler, type));
  }

  @Override
  public AnnotationVisitor visitTryCatchAnnotation(int ref, TypePath path, String descriptor, boolean visible) {
    return annotation(method -> method.visitTryCatchAnnotation(ref, path, descriptor, visible));
  }

  @Override
  public void visitLocalVariable(String name, String descriptor, String signature, Label start, Label end, int index) {
    operations.add(method -> method.visitLocalVariable(name, descriptor, signature, start, end, index));
  }

  @Override
  public AnnotationVisitor visitLocalVariableAnnotation(int ref, TypePath path, Label[] start,
      Label[] end, int[] index, String descriptor, boolean visible) {
    Label[] s = start.clone();
    Label[] e = end.clone();
    int[] i = index.clone();
    return annotation(method -> method.visitLocalVariableAnnotation(ref, path, s, e, i, descriptor, visible));
  }

  @Override
  public void visitLineNumber(int line, Label start) {
    operations.add(method -> method.visitLineNumber(line, start));
  }

  @Override
  public void visitMaxs(int maxStack, int maxLocals) {
    stack = Math.max(stack, maxStack);
    locals = Math.max(locals, maxLocals);
    operations.add(method -> method.visitMaxs(maxStack, maxLocals));
  }

  @Override
  public void visitEnd() {
    operations.add(MethodVisitor::visitEnd);
    completed.accept(this);
  }
}
