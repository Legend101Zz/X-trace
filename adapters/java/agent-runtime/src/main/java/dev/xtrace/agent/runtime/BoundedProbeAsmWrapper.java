package dev.xtrace.agent.runtime;

import dev.xtrace.agent.runtime.line.BufferedMethodVisitor;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;

/** Budgets the composed method before the real writer can truncate any u2 field. */
final class BoundedProbeAsmWrapper extends AsmVisitorWrapper.AbstractBase {
  private final AsmVisitorWrapper probes;
  private final Consumer<String> omitted;

  BoundedProbeAsmWrapper(AsmVisitorWrapper probes, Consumer<String> omitted) {
    this.probes = probes;
    this.omitted = omitted;
  }

  @Override
  public int mergeWriter(int flags) { return probes.mergeWriter(flags); }

  @Override
  public int mergeReader(int flags) { return probes.mergeReader(flags); }

  @Override
  public ClassVisitor wrap(TypeDescription type, ClassVisitor writer, Implementation.Context context,
      TypePool pool, FieldList<FieldDescription.InDefinedShape> fields, MethodList<?> methods,
      int writerFlags, int readerFlags) {
    Map<String, BufferedMethodVisitor> originals = new HashMap<>();
    ClassVisitor destination = new ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor,
          String signature, String[] exceptions) {
        MethodVisitor output = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (output == null) return null;
        String key = name + descriptor;
        return new BufferedMethodVisitor(candidate -> {
          BufferedMethodVisitor original = originals.remove(key);
          if (candidate.fits()) candidate.replay(output);
          else {
            // Preserve the application's complete original method, including frames and handlers.
            // Missing entry attribution requires a persistent limitation, not a silent skip.
            omitted.accept(key);
            original.replay(output);
          }
        });
      }
    };
    // Advice otherwise emits placeholder maxima when ASM will compute them. Our decision must
    // precede that computation: request real composed bounds while the final writer keeps its
    // original computation flags. Advice also retains the frames needed by an original fallback.
    int measuredFlags = writerFlags & ~(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
    ClassVisitor instrumented = probes.wrap(type, destination, context, pool, fields, methods,
        measuredFlags, readerFlags);
    return new ClassVisitor(Opcodes.ASM9, instrumented) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor,
          String signature, String[] exceptions) {
        String key = name + descriptor;
        BufferedMethodVisitor original = new BufferedMethodVisitor(buffer -> {
          MethodVisitor target = super.visitMethod(access, name, descriptor, signature, exceptions);
          if (target != null) buffer.replay(target);
          else originals.remove(key);
        });
        originals.put(key, original);
        return original;
      }
    };
  }
}
