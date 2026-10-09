package dev.xtrace.agent.runtime.line;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.pool.TypePool;

/**
 * Byte Buddy hook: {@code builder.visit(new LineProbeAsmWrapper(...))}. Adds {@code COMPUTE_MAXS}
 * (never {@code COMPUTE_FRAMES}) to the writer flags and keeps existing stack map frames.
 */
public final class LineProbeAsmWrapper extends AsmVisitorWrapper.AbstractBase {
  private final LineProbeConfig config;
  private final SiteRegistry registry;
  private final Function<TypeDescription, byte[]> digestResolver;
  private final Consumer<List<MethodReport>> reportSink;

  /**
   * @param digestResolver BLAKE3-256 of the class bytes the transformer saw, or null when unknown
   * @param reportSink receives the per-method report after each class (may be null)
   */
  public LineProbeAsmWrapper(
      LineProbeConfig config,
      SiteRegistry registry,
      Function<TypeDescription, byte[]> digestResolver,
      Consumer<List<MethodReport>> reportSink) {
    this.config = config;
    this.registry = registry;
    this.digestResolver = digestResolver;
    this.reportSink = reportSink;
  }

  @Override
  public int mergeWriter(int flags) {
    return (flags | ClassWriter.COMPUTE_MAXS) & ~ClassWriter.COMPUTE_FRAMES;
  }

  @Override
  public int mergeReader(int flags) {
    // Frames must reach the writer. The visitor handles compressed and expanded frames alike, so a
    // composed Advice wrapper may keep EXPAND_FRAMES; only SKIP_FRAMES is removed.
    return flags & ~net.bytebuddy.jar.asm.ClassReader.SKIP_FRAMES;
  }

  @Override
  public ClassVisitor wrap(
      TypeDescription instrumentedType,
      ClassVisitor classVisitor,
      Implementation.Context implementationContext,
      TypePool typePool,
      FieldList<FieldDescription.InDefinedShape> fields,
      MethodList<?> methods,
      int writerFlags,
      int readerFlags) {
    byte[] digest = digestResolver == null ? null : digestResolver.apply(instrumentedType);
    List<MethodReport> reports = new ArrayList<>();
    return new LineProbeVisitor(classVisitor, config, registry, digest, reports) {
      @Override
      public void visitEnd() {
        super.visitEnd();
        if (reportSink != null) reportSink.accept(reports);
      }
    };
  }
}
