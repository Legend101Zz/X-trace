package dev.xtrace.agent.runtime.line;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import net.bytebuddy.jar.asm.AnnotationVisitor;
import net.bytebuddy.jar.asm.Opcodes;

/** Records an annotation visit so it can be replayed onto another visitor later, unchanged. */
final class AnnotationRecorder extends AnnotationVisitor {
  private final List<Consumer<AnnotationVisitor>> steps = new ArrayList<>();

  AnnotationRecorder() {
    super(Opcodes.ASM9);
  }

  @Override
  public void visit(String name, Object value) {
    steps.add(av -> av.visit(name, value));
  }

  @Override
  public void visitEnum(String name, String descriptor, String value) {
    steps.add(av -> av.visitEnum(name, descriptor, value));
  }

  @Override
  public AnnotationVisitor visitAnnotation(String name, String descriptor) {
    AnnotationRecorder nested = new AnnotationRecorder();
    steps.add(
        av -> {
          AnnotationVisitor target = av.visitAnnotation(name, descriptor);
          if (target != null) nested.replay(target);
        });
    return nested;
  }

  @Override
  public AnnotationVisitor visitArray(String name) {
    AnnotationRecorder nested = new AnnotationRecorder();
    steps.add(
        av -> {
          AnnotationVisitor target = av.visitArray(name);
          if (target != null) nested.replay(target);
        });
    return nested;
  }

  @Override
  public void visitEnd() {
    // replay() issues the terminating visitEnd on the target
  }

  void replay(AnnotationVisitor target) {
    for (Consumer<AnnotationVisitor> step : steps) step.accept(target);
    target.visitEnd();
  }
}
