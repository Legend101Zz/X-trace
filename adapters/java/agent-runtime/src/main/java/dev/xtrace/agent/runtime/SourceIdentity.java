package dev.xtrace.agent.runtime;

import java.io.IOException;
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
 *
 * <p>The canonical source base is the confinement boundary: the explicit project directory, or
 * the application's working directory when none was supplied. Neither case searches ancestors.
 * Every path component must remain inside that boundary, including after following symlinks.
 */
final class SourceIdentity {
  /** Wire value of {@code SOURCE_BINDING_OBSERVED_UNATTESTED}. */
  static final int OBSERVED_UNATTESTED = 6;

  private static final int ATTESTATION_MISSING = 2;
  private static final int DEBUG_METADATA_ABSENT = 4;
  private static final int SOURCE_METADATA_INVALID = 5;
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
    observe(loader, internalName, classBytes, sourceRoots, workingDirectory, file -> {});
  }

  static void observe(
      ClassLoader loader,
      String internalName,
      byte[] classBytes,
      List<String> sourceRoots,
      Path workingDirectory,
      ConfinedSourceFiles.BeforeOpen beforeOpen) {
    observe(loader, internalName, classBytes, sourceRoots, workingDirectory,
        (base, relative) -> ConfinedSourceFiles.read(base, relative, beforeOpen));
  }

  static void observe(
      ClassLoader loader,
      String internalName,
      byte[] classBytes,
      List<String> sourceRoots,
      Path workingDirectory,
      ConfinedSourceFiles.Reader reader) {
    if (loader == null || internalName == null || classBytes == null) return;
    if (classBytes.length > MAX_CLASS_BYTES) return;
    try {
      ClassFacts facts = parse(internalName, classBytes);
      facts.resolve(sourceRoots, workingDirectory, reader);
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
                // Lambda bodies own focused cursors and need the same observed extent as methods.
                if ((access & Opcodes.ACC_BRIDGE) != 0
                    || ((access & Opcodes.ACC_SYNTHETIC) != 0 && !name.startsWith("lambda$"))) {
                  return null;
                }
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
      resolve(sourceRoots, workingDirectory, ConfinedSourceFiles::read);
    }

    void resolve(List<String> sourceRoots, Path workingDirectory,
        ConfinedSourceFiles.Reader reader) {
      if (sourceFile == null || !simpleSourceName(sourceFile)) {
        fileProblem = sourceFile == null ? DEBUG_METADATA_ABSENT : SOURCE_METADATA_INVALID;
        return;
      }
      int slash = internalName.lastIndexOf('/');
      String packagePath = slash < 0 ? "" : internalName.substring(0, slash + 1);
      try {
        if (workingDirectory == null) {
          fileProblem = ATTESTATION_MISSING;
          return;
        }
        Path base = workingDirectory.toRealPath();
        for (String root : sourceRoots) {
          ConfinedSourceFiles.Source found = reader.read(
              base, root + "/" + packagePath + sourceFile);
          if (found == null) continue;
          if (!found.path().getFileName().toString().equals(sourceFile)) {
            fileProblem = SOURCE_METADATA_INVALID;
            return;
          }
          byte[] bytes = found.bytes();
          hash = SourceAttestation.blake3Of(bytes);
          fileLines = countLines(bytes);
          path = found.path().toString().replace('\\', '/');
          return;
        }
      } catch (ConfinedSourceFiles.TooLarge invalid) {
        fileProblem = SOURCE_METADATA_INVALID;
        return;
      } catch (IOException unavailable) {
        // An unsafe or unreadable path must not fall through to a different source root.
        // Provider capability failures also emit XTR-JAVA-SOURCE-UNVERIFIABLE once; the wire
        // binding vocabulary has no platform-unverifiable value.
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

  static int countLines(byte[] bytes) {
    if (bytes.length == 0) return 0;
    int count = 1;
    for (int i = 0; i < bytes.length; i++) {
      if (bytes[i] == '\n' && i + 1 < bytes.length) count++;
    }
    return count;
  }
}
