package dev.xtrace.agent.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * Source identity for application classes that carry no build attestation. For each loaded
 * application class it records, from the class bytes the JVM presented, the {@code SourceFile}
 * name and each method's debug line extent, and binds the class to the BLAKE3 of the source file
 * found under the declared source roots when the class is loaded.
 *
 * <p>This is observation, not attestation: nothing proves the file compiled into the class. The
 * binding is therefore {@code OBSERVED_UNATTESTED}; a file that is missing, whose name disagrees
 * with the class's {@code SourceFile}, or whose length cannot contain the method's lines is shown
 * as such and never as a match.
 */
final class SourceIdentity {
  /** Wire value of {@code SOURCE_BINDING_OBSERVED_UNATTESTED}. */
  static final int OBSERVED_UNATTESTED = 6;

  private static final int ATTESTATION_MISSING = 2;
  private static final int DEBUG_METADATA_ABSENT = 4;
  private static final int SOURCE_METADATA_INVALID = 5;
  private static final long MAX_SOURCE_BYTES = 1024 * 1024;
  private static final int MAX_CLASS_BYTES = 8 * 1024 * 1024;
  private static final int MAX_CLASSES_PER_LOADER = 20_000;

  private static final Map<ClassLoader, Map<String, ClassFacts>> LOADERS = new WeakHashMap<>();

  private SourceIdentity() {}

  /** Records facts for a class presented to the transformer. Never throws. */
  static void observe(
      ClassLoader loader,
      String internalName,
      byte[] classBytes,
      List<String> sourceRoots,
      Path workingDirectory) {
    if (loader == null || internalName == null || classBytes == null) return;
    if (classBytes.length > MAX_CLASS_BYTES) return;
    try {
      ClassFacts facts = parse(internalName, classBytes);
      facts.resolve(sourceRoots, workingDirectory);
      synchronized (LOADERS) {
        Map<String, ClassFacts> classes = LOADERS.computeIfAbsent(loader, key -> new HashMap<>());
        if (classes.size() < MAX_CLASSES_PER_LOADER) {
          classes.put(internalName.replace('/', '.'), facts);
        }
      }
    } catch (RuntimeException | LinkageError ignored) {
      // An unreadable class simply has no source identity.
    }
  }

  /** Source facts for one method of a loaded class, honest about every missing piece. */
  static SourceAttestation.SourceInfo lookup(Class<?> type, String method, String descriptor) {
    ClassLoader loader = type == null ? null : type.getClassLoader();
    if (loader == null) return SourceAttestation.SourceInfo.unavailable(ATTESTATION_MISSING);
    ClassFacts facts;
    synchronized (LOADERS) {
      Map<String, ClassFacts> classes = LOADERS.get(loader);
      facts = classes == null ? null : classes.get(type.getName());
    }
    if (facts == null) return SourceAttestation.SourceInfo.unavailable(ATTESTATION_MISSING);
    return facts.info(method + descriptor);
  }

  /**
   * Source facts for one line of an application class named by its internal or dotted name, from
   * the class bytes observed at load. Null when the class, file or line cannot be tied to a file.
   * The probe site registry has no loader, so the first loader that observed the class wins.
   */
  static SourceAttestation.SourceInfo lookupLine(String className, int line) {
    if (className == null) return null;
    String dotted = className.replace('/', '.');
    ClassFacts facts = null;
    synchronized (LOADERS) {
      for (Map<String, ClassFacts> classes : LOADERS.values()) {
        facts = classes.get(dotted);
        if (facts != null) break;
      }
    }
    return facts == null ? null : facts.lineInfo(line);
  }

  static void resetForTest() {
    synchronized (LOADERS) {
      LOADERS.clear();
    }
  }

  static ClassFacts parse(String internalName, byte[] classBytes) {
    ClassFacts facts = new ClassFacts(internalName.replace('/', '.'), internalName);
    new ClassReader(classBytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public void visitSource(String source, String debug) {
                facts.sourceFile = source;
              }

              @Override
              public MethodVisitor visitMethod(
                  int access, String name, String descriptor, String signature, String[] ex) {
                if ((access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) return null;
                int[] range = {Integer.MAX_VALUE, 0};
                facts.lines.put(name + descriptor, range);
                return new MethodVisitor(Opcodes.ASM9) {
                  @Override
                  public void visitLineNumber(int line, Label start) {
                    if (line < range[0]) range[0] = line;
                    if (line > range[1]) range[1] = line;
                  }
                };
              }
            },
            ClassReader.SKIP_FRAMES);
    return facts;
  }

  /** Facts for one class; resolved once, immutable afterwards. */
  static final class ClassFacts {
    private final String className;
    private final String internalName;
    private final Map<String, int[]> lines = new HashMap<>();
    private String sourceFile;
    private String path;
    private byte[] hash;
    private int fileLines;
    private int fileProblem;

    ClassFacts(String className, String internalName) {
      this.className = className;
      this.internalName = internalName;
    }

    String sourceFile() {
      return sourceFile;
    }

    String path() {
      return path;
    }

    byte[] hash() {
      return hash == null ? null : hash.clone();
    }

    int[] range(String methodAndDescriptor) {
      int[] range = lines.get(methodAndDescriptor);
      return range == null ? null : range.clone();
    }

    void resolve(List<String> sourceRoots, Path workingDirectory) {
      if (sourceFile == null || !simpleSourceName(sourceFile)) {
        fileProblem = sourceFile == null ? DEBUG_METADATA_ABSENT : SOURCE_METADATA_INVALID;
        return;
      }
      int slash = internalName.lastIndexOf('/');
      String packagePath = slash < 0 ? "" : internalName.substring(0, slash + 1);
      for (String root : sourceRoots) {
        Path found = locate(workingDirectory, root + "/" + packagePath + sourceFile);
        if (found == null) continue;
        try {
          if (Files.size(found) > MAX_SOURCE_BYTES) {
            fileProblem = SOURCE_METADATA_INVALID;
            return;
          }
          byte[] bytes = Files.readAllBytes(found);
          hash = SourceAttestation.blake3Of(bytes);
          fileLines = countLines(bytes);
          path = repoRelative(found, workingDirectory);
          return;
        } catch (IOException unreadable) {
          fileProblem = ATTESTATION_MISSING;
          return;
        }
      }
      fileProblem = ATTESTATION_MISSING;
    }

    SourceAttestation.SourceInfo info(String methodAndDescriptor) {
      if (fileProblem != 0 || hash == null || path == null) {
        return SourceAttestation.SourceInfo.unavailable(
            fileProblem == 0 ? ATTESTATION_MISSING : fileProblem);
      }
      int[] range = lines.get(methodAndDescriptor);
      if (range == null || range[1] == 0 || range[0] == Integer.MAX_VALUE) {
        return SourceAttestation.SourceInfo.unavailable(DEBUG_METADATA_ABSENT);
      }
      if (range[0] < 1 || range[1] > fileLines) {
        return SourceAttestation.SourceInfo.unavailable(SOURCE_METADATA_INVALID);
      }
      return new SourceAttestation.SourceInfo(
          path, range[0], range[1], hash.clone(), OBSERVED_UNATTESTED);
    }

    SourceAttestation.SourceInfo lineInfo(int line) {
      if (fileProblem != 0 || hash == null || path == null || line < 1 || line > fileLines) {
        return null;
      }
      return new SourceAttestation.SourceInfo(path, line, line, hash.clone(), OBSERVED_UNATTESTED);
    }

    String className() {
      return className;
    }
  }

  private static boolean simpleSourceName(String name) {
    if (name.length() < 6 || name.length() > 200 || !name.endsWith(".java")) return false;
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (c == '/' || c == '\\' || c < ' ' || c == 0x7f || c == ':') return false;
    }
    return !name.equals(".java") && !name.startsWith(".");
  }

  /** Finds the file by climbing from the working directory; each probe is a plain regular file. */
  private static Path locate(Path workingDirectory, String relative) {
    if (workingDirectory == null) return null;
    Path base = workingDirectory.toAbsolutePath().normalize();
    for (int depth = 0; depth < 8 && base != null; depth++, base = base.getParent()) {
      Path candidate = base.resolve(relative).normalize();
      if (!candidate.startsWith(base)) return null;
      if (Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) return candidate;
    }
    return null;
  }

  /** Path relative to the nearest ancestor holding {@code .git}, else to the working directory. */
  static String repoRelative(Path file, Path workingDirectory) {
    Path root = null;
    for (Path dir = file.getParent(); dir != null; dir = dir.getParent()) {
      if (Files.exists(dir.resolve(".git"), LinkOption.NOFOLLOW_LINKS)) {
        root = dir;
        break;
      }
    }
    if (root == null) root = workingDirectory.toAbsolutePath().normalize();
    if (!file.startsWith(root)) return file.getFileName().toString();
    String relative = root.relativize(file).toString().replace('\\', '/');
    return new String(relative.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
  }

  static int countLines(byte[] bytes) {
    if (bytes.length == 0) return 0;
    int count = 1;
    for (int i = 0; i < bytes.length; i++) {
      if (bytes[i] == '\n' && i + 1 < bytes.length) count++;
    }
    return count;
  }
}
