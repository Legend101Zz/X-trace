package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.MethodReport.Reasons;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassWriter;
import org.bouncycastle.crypto.digests.Blake3Digest;

/**
 * Byte-level entry point: {@code classfile bytes in, instrumented bytes out}. Fail-open: any
 * problem returns the original bytes and an honest class-level reason.
 */
public final class LineProbeInstrumenter {
  /** Outcome of one class. {@code bytes} equals the input array when nothing changed. */
  public record Result(
      byte[] bytes, boolean changed, String classReason, List<MethodReport> methods) {
    public int sites() {
      int n = 0;
      for (MethodReport m : methods) n += m.sites();
      return n;
    }
  }

  private final LineProbeConfig config;
  private final SiteRegistry registry;

  public LineProbeInstrumenter(LineProbeConfig config, SiteRegistry registry) {
    this.config = config;
    this.registry = registry;
  }

  public Result instrument(byte[] classfile) {
    List<MethodReport> reports = new ArrayList<>();
    try {
      ClassReader reader = new ClassReader(classfile);
      if ((reader.getAccess() & 0x8000) != 0) { // ACC_MODULE
        return new Result(classfile, false, "module_info", List.of());
      }
      ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
      LineProbeVisitor visitor =
          new LineProbeVisitor(writer, config, registry, blake3(classfile), reports);
      reader.accept(visitor, 0);
      boolean any = false;
      for (MethodReport m : reports) any |= m.sites() > 0;
      if (!any) return new Result(classfile, false, Reasons.NONE, reports);
      byte[] out = writer.toByteArray();
      return new Result(out, true, Reasons.NONE, reports);
    } catch (IllegalArgumentException e) {
      return new Result(classfile, false, Reasons.CLASS_VERSION, List.of());
    } catch (RuntimeException | LinkageError e) {
      // includes ASM MethodTooLargeException / ClassTooLargeException
      return new Result(classfile, false, Reasons.TRANSFORM_ERROR, List.of());
    }
  }

  static byte[] blake3(byte[] value) {
    Blake3Digest d = new Blake3Digest(256);
    d.update(value, 0, value.length);
    byte[] out = new byte[32];
    d.doFinal(out, 0);
    return out;
  }
}
