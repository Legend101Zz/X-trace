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
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.pool.TypePool;

/**
 * Byte Buddy hook: {@code builder.visit(new LineProbeAsmWrapper(...))}. Adds {@code COMPUTE_MAXS}
 * to the writer flags (it never needs {@code COMPUTE_FRAMES}) and keeps existing stack map frames.
 */
public class LineProbeAsmWrapper extends AsmVisitorWrapper.AbstractBase {
  private final LineProbeConfig config;
  private final SiteRegistry registry;
  private final Function<TypeDescription, byte[]> digestResolver;
  private final Consumer<List<MethodReport>> reportSink;
  private final ClassLoader ownerLoader;
  /** Set once the owner has been proven complete; a missing owner is re-checked per class. */
  private volatile boolean ownerVerified;

  /**
   * Resolves the probe owner through this wrapper's own class loader (fine for tests; production
   * passes the application's defining loader via the five-argument constructor).
   */
  public LineProbeAsmWrapper(
      LineProbeConfig config,
      SiteRegistry registry,
      Function<TypeDescription, byte[]> digestResolver,
      Consumer<List<MethodReport>> reportSink) {
    this(config, registry, digestResolver, reportSink, LineProbeAsmWrapper.class.getClassLoader());
  }

  /**
   * @param ownerLoader loader through which application code resolves the probe owner ({@code null}
   *     = bootstrap). If the owner lacks any of the eight probe methods, line probes are omitted
   *     and a class-level {@code probe_owner_unavailable} row is reported. An independently supplied
   *     gap entry probe still runs for eligible methods.
   * @param digestResolver BLAKE3-256 of the class bytes the transformer saw, or null when unknown
   * @param reportSink receives the per-method report after each class (may be null)
   */
  public LineProbeAsmWrapper(
      LineProbeConfig config,
      SiteRegistry registry,
      Function<TypeDescription, byte[]> digestResolver,
      Consumer<List<MethodReport>> reportSink,
      ClassLoader ownerLoader) {
    this.ownerLoader = ownerLoader;
    this.config = config;
    this.registry = registry;
    this.digestResolver = digestResolver;
    this.reportSink = reportSink;
  }

  @Override
  public int mergeWriter(int flags) {
    // Only add COMPUTE_MAXS: this visitor works with or without a composed COMPUTE_FRAMES.
    return flags | ClassWriter.COMPUTE_MAXS;
  }

  @Override
  public int mergeReader(int flags) {
    // Frames must reach the writer. The visitor handles compressed and expanded frames alike, so a
    // composed Advice wrapper may keep EXPAND_FRAMES; only SKIP_FRAMES is removed.
    // SKIP_DEBUG would hide the LineNumberTable and report a misleading no_line_table.
    return flags
        & ~(net.bytebuddy.jar.asm.ClassReader.SKIP_FRAMES
            | net.bytebuddy.jar.asm.ClassReader.SKIP_DEBUG);
  }

  /** Optional gap call, emitted inside a size-checked caller-side Throwable guard. */
  protected void skippedMethodEntry(MethodVisitor method) {}

  /** Conservative call byte bound; zero disables the optional gap call. */
  protected int skippedMethodEntryBytes() { return 0; }

  /** Called when the method cannot safely carry the guarded entry call. */
  protected void skippedMethodEntryUnavailable() {}

  /** May additionally check an independently supplied gap owner's identity and entry point. */
  protected String probeOwnerProblem() {
    return ProbeOwnerCheck.problem(config.probeOwner(), ownerLoader);
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
    String skipReason = null;
    if (!ownerVerified) {
      String problem = probeOwnerProblem();
      if (problem != null) {
        if (reportSink != null) {
          reportSink.accept(
              List.of(
                  new MethodReport(
                      "<class>", "", MethodReport.Status.SKIPPED,
                      MethodReport.Reasons.PROBE_OWNER, 0, 0, MethodReport.Reasons.NONE)));
        }
        if (skippedMethodEntryBytes() == 0) return classVisitor;
        skipReason = MethodReport.Reasons.PROBE_OWNER;
      } else {
        ownerVerified = true;
      }
    }
    byte[] digest = digestResolver == null ? null : digestResolver.apply(instrumentedType);
    List<MethodReport> reports = new ArrayList<>();
    String classSkip = skipReason;
    return new LineProbeVisitor(classVisitor, config, registry, digest, reports) {
      @Override
      protected String classSkipReason() { return classSkip; }

      @Override
      protected void skippedMethodEntry(MethodVisitor method) {
        LineProbeAsmWrapper.this.skippedMethodEntry(method);
      }

      @Override
      protected int skippedMethodEntryBytes() {
        return LineProbeAsmWrapper.this.skippedMethodEntryBytes();
      }

      @Override
      protected void skippedMethodEntryUnavailable() {
        LineProbeAsmWrapper.this.skippedMethodEntryUnavailable();
      }

      @Override
      public void visitEnd() {
        super.visitEnd();
        if (reportSink != null && classSkip == null) reportSink.accept(reports);
      }
    };
  }
}
