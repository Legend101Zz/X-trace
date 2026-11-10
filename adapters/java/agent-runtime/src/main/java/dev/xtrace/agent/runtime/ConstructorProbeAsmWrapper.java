package dev.xtrace.agent.runtime;

import dev.xtrace.agent.runtime.line.BufferedMethodVisitor;
import dev.xtrace.agent.runtime.line.ConstructorPreamble;
import dev.xtrace.agent.runtime.line.ProbeEligibility;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.pool.TypePool;

/**
 * Constructor body boundaries. The delegation call is outside the boundary: catching its failure
 * would require a verifier-illegal handler spanning initialization of uninitializedThis. Focused
 * cursors omit that preamble, and its entry gap also accounts for a delegation that never returns.
 */
final class ConstructorProbeAsmWrapper extends AsmVisitorWrapper.AbstractBase {
  @Override
  public int mergeWriter(int flags) {
    // Like the line/gap and bounded wrappers, rebuild frames for the selected final body.
    return flags | ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS;
  }

  @Override
  public int mergeReader(int flags) {
    return (flags | ClassReader.EXPAND_FRAMES) & ~ClassReader.SKIP_FRAMES;
  }

  @Override
  public ClassVisitor wrap(TypeDescription type, ClassVisitor writer, Implementation.Context context,
      TypePool pool, FieldList<FieldDescription.InDefinedShape> fields, MethodList<?> methods,
      int writerFlags, int readerFlags) {
    String owner = type.getInternalName();
    String parent = type.getSuperClass().asErasure().getInternalName();
    return new ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor,
          String signature, String[] exceptions) {
        MethodVisitor output = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (output == null || !name.equals("<init>")
            || ProbeEligibility.exclusion(access, name) != null) return output;
        return new BufferedMethodVisitor(buffer -> {
          ConstructorPreamble preamble = new ConstructorPreamble(owner, parent);
          buffer.replay(preamble);
          if (!preamble.supported()) {
            // The line visitor uses this same recognizer and emits only a skipped-entry gap.
            buffer.replay(output);
            return;
          }
          buffer.replay(new Body(output, owner, descriptor, preamble));
        });
      }
    };
  }

  private static final class Body extends MethodVisitor {
    private final String owner;
    private final String descriptor;
    private final ConstructorPreamble preamble;
    private final Label start = new Label();
    private final Label end = new Label();
    private final Label handler = new Label();
    private int calls;
    private boolean initialized;

    Body(MethodVisitor output, String owner, String descriptor, ConstructorPreamble preamble) {
      super(Opcodes.ASM9, output);
      this.owner = owner;
      this.descriptor = descriptor;
      this.preamble = preamble;
    }

    @Override
    public void visitCode() {
      super.visitCode();
      // This bootstrap entry point catches Throwable and never reads the receiver.
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, FixtureInstrumentation.PROBE_OWNER,
          "lineGap", "()V", false);
    }

    @Override
    public void visitMethodInsn(int opcode, String type, String name, String desc, boolean itf) {
      super.visitMethodInsn(opcode, type, name, desc, itf);
      if (++calls != preamble.initializationCall()) return;
      initialized = true;
      mv.visitLdcInsn(Type.getObjectType(owner));
      mv.visitLdcInsn(descriptor);
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, FixtureInstrumentation.PROBE_OWNER,
          "constructorEnter", "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;", false);
      mv.visitVarInsn(Opcodes.ASTORE, preamble.maxLocals());
      // Original handlers have already been declared. Keep them first, and declare our range
      // before visiting its labels so caught application exceptions stay inside the body.
      mv.visitTryCatchBlock(start, end, handler, "java/lang/Throwable");
      mv.visitLabel(start);
    }

    @Override
    public void visitInsn(int opcode) {
      if (opcode == Opcodes.RETURN) close(false);
      super.visitInsn(opcode);
    }

    private void close(boolean threw) {
      mv.visitVarInsn(Opcodes.ALOAD, preamble.maxLocals());
      if (threw) mv.visitVarInsn(Opcodes.ALOAD, preamble.maxLocals() + 1);
      else mv.visitInsn(Opcodes.ACONST_NULL);
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, FixtureInstrumentation.PROBE_OWNER,
          "constructorExit", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false);
    }

    @Override
    public void visitFrame(int type, int count, Object[] locals, int stackCount, Object[] stack) {
      if (!initialized) {
        super.visitFrame(type, count, locals, stackCount, stack);
        return;
      }
      if (type != Opcodes.F_NEW) throw new IllegalStateException("expanded constructor frames required");
      List<Object> extended = new ArrayList<>();
      int slots = 0;
      for (int i = 0; i < count; i++) {
        extended.add(locals[i]);
        slots += locals[i].equals(Opcodes.LONG) || locals[i].equals(Opcodes.DOUBLE) ? 2 : 1;
      }
      while (slots < preamble.maxLocals()) {
        extended.add(Opcodes.TOP);
        slots++;
      }
      extended.add("java/lang/String");
      super.visitFrame(Opcodes.F_NEW, extended.size(), extended.toArray(), stackCount, stack);
    }

    @Override
    public void visitMaxs(int stack, int locals) {
      mv.visitLabel(end);
      mv.visitLabel(handler);
      Object[] frame = new Object[preamble.maxLocals() + 1];
      java.util.Arrays.fill(frame, Opcodes.TOP);
      frame[preamble.maxLocals()] = "java/lang/String";
      mv.visitFrame(Opcodes.F_NEW, frame.length, frame, 1, new Object[] {"java/lang/Throwable"});
      mv.visitVarInsn(Opcodes.ASTORE, preamble.maxLocals() + 1);
      close(true);
      mv.visitVarInsn(Opcodes.ALOAD, preamble.maxLocals() + 1);
      mv.visitInsn(Opcodes.ATHROW);
      super.visitMaxs(Math.max(stack + 2, 2), Math.max(locals, preamble.maxLocals() + 2));
    }
  }
}
