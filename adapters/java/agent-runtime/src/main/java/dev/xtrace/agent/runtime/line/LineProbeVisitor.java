package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.MethodReport.Reasons;
import dev.xtrace.agent.runtime.line.MethodReport.Status;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.function.Consumer;
import net.bytebuddy.jar.asm.AnnotationVisitor;
import net.bytebuddy.jar.asm.Attribute;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Handle;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.jar.asm.TypePath;

/**
 * ASM class visitor that inserts a call-only static probe at the first instruction of every
 * LineNumberTable entry (ADR 0003 section 2.2).
 *
 * <p>Safety rules that make the output verifier-clean without frame recomputation:
 *
 * <ul>
 *   <li>Probes push constants / already-live locals and call a static {@code void} method, so the
 *       operand stack is neutral at every inserted point. Only {@code COMPUTE_MAXS} is needed; the
 *       writer must not use {@code COMPUTE_FRAMES}.
 *   <li>A probe is placed immediately before the first real instruction at or after the line label,
 *       after any {@code visitFrame} for that offset, so a stack map frame still describes the first
 *       byte of the probe (jump targets land on the probe, never past it).
 *   <li>No field, method or class is added (retransformation-safe).
 *   <li>Bridge and non-lambda synthetic methods, methods without a LineNumberTable, methods using
 *       JSR/RET, and methods that would exceed the code-size or site budgets are left byte-for-byte
 *       equivalent and reported as SKIPPED with a reason.
 * </ul>
 *
 * <p>Local reads (focused mode) are gated by the LocalVariableTable range covering the probe, and
 * never read slot 0 of an instance method (it may be {@code uninitializedThis} in a constructor).
 */
public class LineProbeVisitor extends ClassVisitor {
  private static final int ASM = Opcodes.ASM9;

  private final LineProbeConfig config;
  private final SiteRegistry registry;
  private final byte[] classDigest;
  private final List<MethodReport> reports;
  private String className = "";

  public LineProbeVisitor(
      ClassVisitor next,
      LineProbeConfig config,
      SiteRegistry registry,
      byte[] classDigest,
      List<MethodReport> reports) {
    super(ASM, next);
    this.config = config;
    this.registry = registry;
    this.classDigest = classDigest;
    this.reports = reports;
  }

  @Override
  public void visit(
      int version, int access, String name, String signature, String superName, String[] interfaces) {
    this.className = name;
    super.visit(version, access, name, signature, superName, interfaces);
  }

  @Override
  public MethodVisitor visitMethod(
      int access, String name, String descriptor, String signature, String[] exceptions) {
    MethodVisitor next = super.visitMethod(access, name, descriptor, signature, exceptions);
    if (next == null) return null;
    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return next;
    if ((access & Opcodes.ACC_BRIDGE) != 0) {
      reports.add(skipped(name, descriptor, Reasons.BRIDGE));
      return next;
    }
    if ((access & Opcodes.ACC_SYNTHETIC) != 0 && !name.startsWith("lambda$")) {
      reports.add(skipped(name, descriptor, Reasons.SYNTHETIC));
      return next;
    }
    return new Buffer(next, access, name, descriptor);
  }

  private static MethodReport skipped(String name, String descriptor, String reason) {
    return new MethodReport(name, descriptor, Status.SKIPPED, reason, 0, 0, Reasons.NONE);
  }

  // ---------------------------------------------------------------------------------------------

  private enum Kind {
    OTHER,
    LABEL,
    LINE,
    FRAME,
    INSN
  }

  private record LocalEntry(
      String name, String descriptor, int index, Label start, Label end) {}

  private record PlannedSite(int opIndex, int line, List<LocalEntry> locals) {}

  /** Buffers the code of one method, then replays it with probes (or unchanged). */
  private final class Buffer extends MethodVisitor {
    private final MethodVisitor out;
    private final int access;
    private final String name;
    private final String descriptor;

    private final List<Consumer<MethodVisitor>> ops = new ArrayList<>();
    private final List<Kind> kinds = new ArrayList<>();
    private final List<Integer> lineOf = new ArrayList<>();
    private final IdentityHashMap<Label, Integer> labelPos = new IdentityHashMap<>();
    private final List<LocalEntry> locals = new ArrayList<>();
    private boolean inCode;
    private boolean hasLine;
    private boolean hasJsrRet;
    private int estimatedBytes;

    Buffer(MethodVisitor out, int access, String name, String descriptor) {
      super(ASM, null);
      this.out = out;
      this.access = access;
      this.name = name;
      this.descriptor = descriptor;
    }

    // ---- pre-code members pass straight through ----

    @Override
    public void visitParameter(String n, int a) {
      out.visitParameter(n, a);
    }

    @Override
    public AnnotationVisitor visitAnnotationDefault() {
      return out.visitAnnotationDefault();
    }

    @Override
    public AnnotationVisitor visitAnnotation(String d, boolean visible) {
      return out.visitAnnotation(d, visible);
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        int typeRef, TypePath typePath, String d, boolean visible) {
      return out.visitTypeAnnotation(typeRef, typePath, d, visible);
    }

    @Override
    public void visitAnnotableParameterCount(int count, boolean visible) {
      out.visitAnnotableParameterCount(count, visible);
    }

    @Override
    public AnnotationVisitor visitParameterAnnotation(int p, String d, boolean visible) {
      return out.visitParameterAnnotation(p, d, visible);
    }

    @Override
    public void visitAttribute(Attribute attribute) {
      if (!inCode) {
        out.visitAttribute(attribute);
        return;
      }
      add(Kind.OTHER, mv -> mv.visitAttribute(attribute));
    }

    // ---- code ----

    @Override
    public void visitCode() {
      inCode = true;
      add(Kind.OTHER, MethodVisitor::visitCode);
    }

    private void add(Kind kind, Consumer<MethodVisitor> op) {
      ops.add(op);
      kinds.add(kind);
      lineOf.add(0);
    }

    private void insn(int bytes, Consumer<MethodVisitor> op) {
      estimatedBytes += bytes;
      add(Kind.INSN, op);
    }

    @Override
    public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] stack) {
      Object[] l = local == null ? null : local.clone();
      Object[] s = stack == null ? null : stack.clone();
      add(Kind.FRAME, mv -> mv.visitFrame(type, nLocal, l, nStack, s));
    }

    @Override
    public void visitInsn(int opcode) {
      insn(1, mv -> mv.visitInsn(opcode));
    }

    @Override
    public void visitIntInsn(int opcode, int operand) {
      insn(3, mv -> mv.visitIntInsn(opcode, operand));
    }

    @Override
    public void visitVarInsn(int opcode, int varIndex) {
      if (opcode == Opcodes.RET) hasJsrRet = true;
      insn(4, mv -> mv.visitVarInsn(opcode, varIndex));
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
      insn(3, mv -> mv.visitTypeInsn(opcode, type));
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String n, String d) {
      insn(3, mv -> mv.visitFieldInsn(opcode, owner, n, d));
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String n, String d, boolean itf) {
      insn(5, mv -> mv.visitMethodInsn(opcode, owner, n, d, itf));
    }

    @Override
    public void visitInvokeDynamicInsn(String n, String d, Handle bsm, Object... args) {
      insn(5, mv -> mv.visitInvokeDynamicInsn(n, d, bsm, args));
    }

    @Override
    public void visitJumpInsn(int opcode, Label label) {
      if (opcode == Opcodes.JSR) hasJsrRet = true;
      // ASM may widen conditional jumps to a 8-byte inverted-jump + goto_w sequence.
      insn(8, mv -> mv.visitJumpInsn(opcode, label));
    }

    @Override
    public void visitLabel(Label label) {
      labelPos.put(label, ops.size());
      add(Kind.LABEL, mv -> mv.visitLabel(label));
    }

    @Override
    public void visitLdcInsn(Object value) {
      insn(3, mv -> mv.visitLdcInsn(value));
    }

    @Override
    public void visitIincInsn(int varIndex, int increment) {
      insn(6, mv -> mv.visitIincInsn(varIndex, increment));
    }

    @Override
    public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
      insn(16 + 4 * labels.length, mv -> mv.visitTableSwitchInsn(min, max, dflt, labels));
    }

    @Override
    public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
      insn(12 + 8 * labels.length, mv -> mv.visitLookupSwitchInsn(dflt, keys, labels));
    }

    @Override
    public void visitMultiANewArrayInsn(String d, int dims) {
      insn(4, mv -> mv.visitMultiANewArrayInsn(d, dims));
    }

    @Override
    public AnnotationVisitor visitInsnAnnotation(
        int typeRef, TypePath typePath, String d, boolean visible) {
      AnnotationRecorder rec = new AnnotationRecorder();
      add(
          Kind.OTHER,
          mv -> {
            AnnotationVisitor av = mv.visitInsnAnnotation(typeRef, typePath, d, visible);
            if (av != null) rec.replay(av);
          });
      return rec;
    }

    @Override
    public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
      add(Kind.OTHER, mv -> mv.visitTryCatchBlock(start, end, handler, type));
    }

    @Override
    public AnnotationVisitor visitTryCatchAnnotation(
        int typeRef, TypePath typePath, String d, boolean visible) {
      AnnotationRecorder rec = new AnnotationRecorder();
      add(
          Kind.OTHER,
          mv -> {
            AnnotationVisitor av = mv.visitTryCatchAnnotation(typeRef, typePath, d, visible);
            if (av != null) rec.replay(av);
          });
      return rec;
    }

    @Override
    public void visitLocalVariable(
        String n, String d, String signature, Label start, Label end, int index) {
      locals.add(new LocalEntry(n, d, index, start, end));
      add(Kind.OTHER, mv -> mv.visitLocalVariable(n, d, signature, start, end, index));
    }

    @Override
    public AnnotationVisitor visitLocalVariableAnnotation(
        int typeRef,
        TypePath typePath,
        Label[] start,
        Label[] end,
        int[] index,
        String d,
        boolean visible) {
      AnnotationRecorder rec = new AnnotationRecorder();
      add(
          Kind.OTHER,
          mv -> {
            AnnotationVisitor av =
                mv.visitLocalVariableAnnotation(typeRef, typePath, start, end, index, d, visible);
            if (av != null) rec.replay(av);
          });
      return rec;
    }

    @Override
    public void visitLineNumber(int line, Label start) {
      hasLine = true;
      ops.add(mv -> mv.visitLineNumber(line, start));
      kinds.add(Kind.LINE);
      lineOf.add(line);
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
      add(Kind.OTHER, mv -> mv.visitMaxs(maxStack, maxLocals));
    }

    @Override
    public void visitEnd() {
      if (!inCode) {
        out.visitEnd();
        return;
      }
      try {
        finish();
      } finally {
        out.visitEnd();
      }
    }

    // ---- decision + replay ----

    private void finish() {
      String skip = null;
      if (!hasLine) skip = Reasons.NO_LINE_TABLE;
      else if (hasJsrRet) skip = Reasons.JSR_RET;

      List<PlannedSite> plan = skip == null ? plan() : List.of();
      int valueCalls = 0;
      String valuesReason = Reasons.NONE;

      if (skip == null && plan.size() > config.maxSitesPerMethod()) skip = Reasons.SITE_BUDGET;
      if (skip == null && plan.isEmpty()) skip = Reasons.NO_LINE_TABLE;

      boolean values = skip == null && config.focusedValues();
      if (values) {
        if (locals.isEmpty()) {
          values = false;
          valuesReason = Reasons.NO_LVT;
        } else {
          int total = 0;
          for (PlannedSite site : plan) total += Math.min(site.locals().size(), config.maxValuesPerSite());
          if (total > config.maxValueCallsPerMethod()) {
            values = false;
            valuesReason = Reasons.VALUE_BUDGET;
          }
        }
      }
      if (skip == null) {
        long extra = 0;
        for (PlannedSite site : plan) {
          extra += 8;
          if (values) extra += 6L + 11L * Math.min(site.locals().size(), config.maxValuesPerSite());
        }
        if (estimatedBytes + extra > config.maxEstimatedCodeBytes()) {
          if (values && estimatedBytes + 8L * plan.size() <= config.maxEstimatedCodeBytes()) {
            values = false;
            valuesReason = Reasons.TOO_LARGE;
          } else {
            skip = Reasons.TOO_LARGE;
          }
        }
      }
      if (skip == null && !registry.hasRoomFor(plan.size())) skip = Reasons.REGISTRY_FULL;

      if (skip != null) {
        replay(List.of(), false, null);
        reports.add(skipped(name, descriptor, skip));
        return;
      }

      if (values) {
        for (PlannedSite site : plan) {
          if (site.locals().size() > config.maxValuesPerSite()) {
            valuesReason = Reasons.VALUES_CAPPED;
            break;
          }
        }
      }
      int[] siteIds = new int[plan.size()];
      for (int i = 0; i < siteIds.length; i++) {
        siteIds[i] = registry.addSite(className, classDigest, name, descriptor, plan.get(i).line());
        if (siteIds[i] < 0) {
          // Lost a race for the last registry slots: fall back to the unmodified method.
          replay(List.of(), false, null);
          reports.add(skipped(name, descriptor, Reasons.REGISTRY_FULL));
          return;
        }
      }
      valueCalls = replay(plan, values, siteIds);
      reports.add(
          new MethodReport(
              name, descriptor, Status.INSTRUMENTED, Reasons.NONE, plan.size(), valueCalls, valuesReason));
    }

    /** Pending-line walk: one planned site per run of line entries before a real instruction. */
    private List<PlannedSite> plan() {
      List<PlannedSite> plan = new ArrayList<>();
      int pendingLine = -1;
      for (int i = 0; i < ops.size(); i++) {
        Kind kind = kinds.get(i);
        if (kind == Kind.LINE) {
          pendingLine = lineOf.get(i);
        } else if (kind == Kind.INSN && pendingLine >= 0) {
          plan.add(new PlannedSite(i, pendingLine, config.focusedValues() ? liveAt(i) : List.of()));
          pendingLine = -1;
        }
      }
      return plan;
    }

    private List<LocalEntry> liveAt(int opIndex) {
      List<LocalEntry> live = new ArrayList<>();
      boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
      boolean[] seen = new boolean[256];
      for (LocalEntry e : locals) {
        Integer s = labelPos.get(e.start());
        Integer en = labelPos.get(e.end());
        if (s == null || en == null) continue;
        if (!(s <= opIndex && opIndex < en)) continue;
        if (!isStatic && e.index() == 0) continue; // `this` may be uninitializedThis
        if (e.index() < seen.length) {
          if (seen[e.index()]) continue; // overlapping ranges for one slot: never guess
          seen[e.index()] = true;
        }
        char c = e.descriptor().charAt(0);
        if (c != 'Z' && c != 'B' && c != 'C' && c != 'S' && c != 'I' && c != 'J' && c != 'F'
            && c != 'D' && c != 'L' && c != '[') {
          continue;
        }
        live.add(e);
      }
      live.sort((a, b) -> Integer.compare(a.index(), b.index()));
      return live;
    }

    private int replay(List<PlannedSite> plan, boolean values, int[] siteIds) {
      int next = 0;
      int valueCalls = 0;
      for (int i = 0; i < ops.size(); i++) {
        if (next < plan.size() && plan.get(next).opIndex() == i) {
          valueCalls += emitProbe(plan.get(next), siteIds[next], values);
          next++;
        }
        ops.get(i).accept(out);
      }
      return valueCalls;
    }

    private int emitProbe(PlannedSite site, int siteId, boolean values) {
      MethodVisitor mv = out;
      pushInt(mv, siteId);
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "line", "(I)V", false);
      if (!values || site.locals().isEmpty()) return 0;
      int count = Math.min(site.locals().size(), config.maxValuesPerSite());
      pushInt(mv, siteId);
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valuesBegin", "(I)V", false);
      for (int i = 0; i < count; i++) {
        LocalEntry e = site.locals().get(i);
        int nameId = registry.addName(e.name(), e.descriptor(), e.index());
        char c = e.descriptor().charAt(0);
        switch (c) {
          case 'J' -> {
            pushInt(mv, e.index());
            pushInt(mv, nameId);
            mv.visitVarInsn(Opcodes.LLOAD, e.index());
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valueLong", "(IIJ)V", false);
          }
          case 'F' -> {
            pushInt(mv, e.index());
            pushInt(mv, nameId);
            mv.visitVarInsn(Opcodes.FLOAD, e.index());
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valueFloat", "(IIF)V", false);
          }
          case 'D' -> {
            pushInt(mv, e.index());
            pushInt(mv, nameId);
            mv.visitVarInsn(Opcodes.DLOAD, e.index());
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valueDouble", "(IID)V", false);
          }
          case 'L', '[' -> {
            pushInt(mv, nameId);
            pushInt(mv, 3);
            mv.visitVarInsn(Opcodes.ALOAD, e.index());
            mv.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                config.probeOwner(),
                "valueRef",
                "(IILjava/lang/Object;)V",
                false);
          }
          default -> {
            pushInt(mv, e.index());
            pushInt(mv, nameId);
            mv.visitVarInsn(Opcodes.ILOAD, e.index());
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valueInt", "(III)V", false);
          }
        }
      }
      mv.visitMethodInsn(Opcodes.INVOKESTATIC, config.probeOwner(), "valuesEnd", "()V", false);
      return count;
    }
  }

  private static void pushInt(MethodVisitor mv, int value) {
    if (value >= -1 && value <= 5) {
      mv.visitInsn(Opcodes.ICONST_0 + value);
    } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
      mv.visitIntInsn(Opcodes.BIPUSH, value);
    } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
      mv.visitIntInsn(Opcodes.SIPUSH, value);
    } else {
      mv.visitLdcInsn(value);
    }
  }

  /** Exposed for tests that want the exact probe descriptor set. */
  static String descriptorOfLine() {
    return Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE);
  }
}
