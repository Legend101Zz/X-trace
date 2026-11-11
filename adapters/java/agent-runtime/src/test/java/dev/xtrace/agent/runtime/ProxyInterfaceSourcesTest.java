package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ProxyInterfaceSourcesTest {
  private static final String INTERNAL = "example/Repository";
  private static final String SOURCE = "src/main/java/example/Repository.java";
  private static final String TEXT =
      "package example;\npublic interface Repository {\n  String save(String value);\n}\n";

  private static class Loader extends ClassLoader {
    Class<?> define(byte[] bytes) {
      return defineClass("example.Repository", bytes, 0, bytes.length);
    }
  }

  private static byte[] classBytes() {
    ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
        INTERNAL, null, "java/lang/Object", null);
    writer.visitSource("Repository.java", null);
    writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "save",
        "(Ljava/lang/String;)Ljava/lang/String;", null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static Path sourceTree(Path project) throws IOException {
    Path source = project.resolve(SOURCE);
    Files.createDirectories(source.getParent());
    return Files.writeString(source, TEXT, StandardCharsets.UTF_8);
  }

  private static SourceAttestation.SourceInfo observe(
      Path project, Runnable afterIdentity, boolean forceFallback) throws Exception {
    Loader loader = new Loader();
    byte[] bytes = classBytes();
    Class<?> type = loader.define(bytes);
    ProxyInterfaceSources.observe(loader, INTERNAL, bytes,
        new ApplicationScope(List.of("example"), List.of("src/main/java"), project), afterIdentity,
        (base, relative) -> ConfinedSourceFiles.read(base, relative, file -> {}, forceFallback));
    return ProxyInterfaceSources.lookup(type.getMethod("save", String.class));
  }

  private static void unavailable(SourceAttestation.SourceInfo info) {
    assertEquals(2, info.binding());
    assertNull(info.path());
    assertNull(info.hash());
    assertEquals(0, info.startLine());
    assertEquals(0, info.endLine());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void unchangedInterfaceSourceHasItsObservedDeclaration(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    SourceAttestation.SourceInfo info = observe(project, () -> {}, forceFallback);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(SOURCE, info.path());
    assertEquals(3, info.startLine());
    assertEquals(3, info.endLine());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(source)), info.hash());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void missingInterfaceSourceNeverUsesAnAncestorDecoy(
      boolean forceFallback, @TempDir Path ancestor) throws Exception {
    sourceTree(ancestor);
    Path project = Files.createDirectory(ancestor.resolve("project"));
    unavailable(observe(project, () -> {}, forceFallback));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void deletedInterfaceSourceCannotFallBackToIdenticalAncestorAfterIdentityRead(
      boolean forceFallback, @TempDir Path ancestor) throws Exception {
    sourceTree(ancestor); // Same hash: the old hash gate alone cannot reject this decoy.
    Path project = ancestor.resolve("project");
    Path source = sourceTree(project);
    boolean[] deleted = {false};
    SourceAttestation.SourceInfo info = observe(project, () -> {
      try {
        Files.delete(source);
        deleted[0] = true;
      } catch (IOException failure) {
        throw new UncheckedIOException(failure);
      }
    }, forceFallback);
    assertTrue(deleted[0], "identity resolution must succeed before removing local source");
    unavailable(info);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void interfaceSourceSwappedToIdenticalExternalDirectoryIsUnavailable(
      boolean forceFallback, @TempDir Path directory) throws Exception {
    Path external = sourceTree(directory.resolve("external"));
    Path project = directory.resolve("project");
    Path source = sourceTree(project);
    boolean[] swapped = {false};
    SourceAttestation.SourceInfo info = observe(project, () -> {
      try {
        Path parent = source.getParent();
        Files.move(parent, parent.resolveSibling("saved-example"));
        Files.createSymbolicLink(parent, external.getParent());
        swapped[0] = true;
      } catch (IOException failure) {
        throw new UncheckedIOException(failure);
      }
    }, forceFallback);
    assertTrue(swapped[0]);
    unavailable(info);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void changedInterfaceContentCannotReuseTheObservedHash(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    boolean[] edited = {false};
    SourceAttestation.SourceInfo info = observe(project, () -> {
      try {
        // The declaration still matches; only the hash gate can reject this edit.
        Files.writeString(source, TEXT.replace("String value", "String other"));
        edited[0] = true;
      } catch (IOException failure) {
        throw new UncheckedIOException(failure);
      }
    }, forceFallback);
    assertTrue(edited[0]);
    unavailable(info);
  }
}
