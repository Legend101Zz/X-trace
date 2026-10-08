package dev.xtrace.agent.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.bouncycastle.crypto.digests.Blake3Digest;

/**
 * Build-time generator for the three explicitly approved Spring fixture source
 * bindings.
 */
public final class SourceAttestationGenerator {
  private static final long MAX_SOURCE_BYTES = 1024 * 1024;
  private static final long MAX_CLASS_BYTES = 8 * 1024 * 1024;
  private static final String PREFIX =
      "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/";
  private static final String[][] TARGETS = {
      {"dev.xtrace.fixture.OrderController", "create", "OrderController.java"},
      {"dev.xtrace.fixture.OrderService", "place", "OrderService.java"},
      {"dev.xtrace.fixture.OrderRepository", "save", "OrderRepository.java"}};

  private SourceAttestationGenerator() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 4)
      throw new IllegalArgumentException(
          "expected repository, classes, output, and compile-input snapshot " +
          "paths");
    Path repository = Path.of(args[0]).toRealPath();
    Path classes = Path.of(args[1]).toRealPath();
    Path output = Path.of(args[2]);
    Path snapshot = Path.of(args[3]).toRealPath();
    Files.createDirectories(output.getParent());
    List<String> rows = new ArrayList<>();
    for (String[] target : TARGETS) {
      Path classFile = classes.resolve(target[0].replace('.', '/') + (".clas" +
                                                                      "s"));
      Path sourceFile = repository.resolve(PREFIX + target[2]).normalize();
      if (!sourceFile.startsWith(repository) ||
          hasSymlinkComponent(repository, sourceFile))
        throw new IllegalStateException("source path is invalid");
      byte[] source = readBounded(sourceFile, MAX_SOURCE_BYTES);
      byte[] compileInput =
          readBounded(snapshot.resolve("dev/xtrace/fixture/" + target[2]),
                      MAX_SOURCE_BYTES);
      requireCompileInputMatches(source, compileInput);
      byte[] classBytes = readBounded(classFile, MAX_CLASS_BYTES);
      MethodLines lines = findMethod(classBytes, target[1]);
      if (lines.descriptor == null)
        throw new IllegalStateException(
            "fixture method is absent from compiled output");
      rows.add(target[0] + "\t" + target[1] + "\t" + lines.descriptor + "\t" +
               PREFIX + target[2] + "\t" + hex(blake3(classBytes)) + "\t" +
               hex(blake3(source)) + "\t" + lines.start + ":" + lines.end);
    }
    Files.writeString(output, String.join("\n", rows) + "\n",
                      java.nio.charset.StandardCharsets.UTF_8);
  }

  static void requireCompileInputMatches(byte[] currentSource, byte[] compileInput)
      throws IllegalStateException {
    if (!java.util.Arrays.equals(currentSource, compileInput)) {
      throw new IllegalStateException("source changed after compile input snapshot");
    }
  }

  private static boolean hasSymlinkComponent(Path root, Path file) {
    Path current = root;
    for (Path part : root.relativize(file)) {
      current = current.resolve(part);
      if (Files.isSymbolicLink(current))
        return true;
    }
    return false;
  }

  private static byte[] readBounded(Path path, long maximum) throws Exception {
    if (!Files.isRegularFile(path) || Files.size(path) > maximum)
      throw new IllegalStateException(
          "attestation input is unavailable or too large");
    try (var input = Files.newInputStream(path)) {
      byte[] bytes = input.readNBytes(Math.toIntExact(maximum + 1));
      if (bytes.length > maximum)
        throw new IllegalStateException("attestation input is too large");
      return bytes;
    }
  }

  private static MethodLines findMethod(byte[] bytes, String wanted) {
    MethodLines lines = new MethodLines();
    new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
      @Override
      public MethodVisitor visitMethod(int access, String name,
                                       String descriptor, String signature,
                                       String[] exceptions) {
        if (!wanted.equals(name))
          return null;
        return new MethodVisitor(Opcodes.ASM9) {
          @Override
          public void visitLineNumber(int line,
                                      net.bytebuddy.jar.asm.Label start) {
            lines.start = lines.start == 0 ? line : Math.min(lines.start, line);
            lines.end = Math.max(lines.end, line);
          }
          @Override
          public void visitEnd() {
            lines.descriptor = descriptor;
          }
        };
      }
    }, ClassReader.SKIP_FRAMES);
    return lines;
  }

  private static byte[] blake3(byte[] value) {
    Blake3Digest d = new Blake3Digest(256);
    d.update(value, 0, value.length);
    byte[] out = new byte[32];
    d.doFinal(out, 0);
    return out;
  }
  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(64);
    for (byte b : bytes)
      out.append(String.format("%02x", b & 255));
    return out.toString();
  }
  private static final class MethodLines {
    String descriptor;
    int start;
    int end;
  }
}
