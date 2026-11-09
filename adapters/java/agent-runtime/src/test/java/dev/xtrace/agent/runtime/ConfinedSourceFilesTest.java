package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ConfinedSourceFilesTest {
  private static final String SOURCE = "src/example/Sample.java";
  private static final String TEXT = "package example;\nclass Sample {}\n";

  private static Path sourceTree(Path project) throws IOException {
    Path file = project.resolve(SOURCE);
    Files.createDirectories(file.getParent());
    return Files.writeString(file, TEXT);
  }

  private static ConfinedSourceFiles.Source read(Path project, boolean forceFallback,
      ConfinedSourceFiles.BeforeOpen beforeOpen) throws IOException {
    return ConfinedSourceFiles.read(project, SOURCE, beforeOpen, forceFallback);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void normalReadReturnsOnlyProjectRelativePathAndObservedBytes(
      boolean forceFallback, @TempDir Path project) throws Exception {
    sourceTree(project);
    ConfinedSourceFiles.Source source = read(project, forceFallback, file -> {});
    assertNotNull(source);
    assertEquals(Path.of(SOURCE), source.path());
    assertArrayEquals(TEXT.getBytes(StandardCharsets.UTF_8), source.bytes());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void projectAndSourceAliasesWithinTheBoundaryStillBind(
      boolean forceFallback, @TempDir Path directory) throws Exception {
    Path project = directory.resolve("project");
    sourceTree(project);
    Path alias = Files.createSymbolicLink(directory.resolve("alias"), project);
    Files.createSymbolicLink(project.resolve("sources"), project.resolve("src"));
    ConfinedSourceFiles.Source source = ConfinedSourceFiles.read(
        alias, "sources/example/Sample.java", file -> {}, forceFallback);
    assertEquals(Path.of(SOURCE), source.path());
    assertArrayEquals(TEXT.getBytes(StandardCharsets.UTF_8), source.bytes());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void missingLocalSourceNeverUsesAnIdenticalAncestorDecoy(
      boolean forceFallback, @TempDir Path ancestor) throws Exception {
    sourceTree(ancestor);
    Path project = Files.createDirectory(ancestor.resolve("project"));
    assertNull(read(project, forceFallback, file -> {}));
    assertThrows(IOException.class, () -> ConfinedSourceFiles.read(
        project, "../" + SOURCE, file -> {}, forceFallback));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void fileSymlinkSwapCannotReadAnIdenticalExternalDecoy(
      boolean forceFallback, @TempDir Path directory) throws Exception {
    Path outside = sourceTree(directory.resolve("outside"));
    Path project = directory.resolve("project");
    Path source = sourceTree(project);
    boolean[] swapped = {false};
    assertThrows(IOException.class, () -> read(project, forceFallback, file -> {
      Files.delete(source);
      Files.createSymbolicLink(source, outside);
      swapped[0] = true;
    }));
    assertTrue(swapped[0]);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void directorySymlinkSwapCannotReadAnIdenticalExternalDecoy(
      boolean forceFallback, @TempDir Path directory) throws Exception {
    Path outside = sourceTree(directory.resolve("outside"));
    Path project = directory.resolve("project");
    Path source = sourceTree(project);
    boolean[] swapped = {false};
    assertThrows(IOException.class, () -> read(project, forceFallback, file -> {
      Path parent = source.getParent();
      Files.move(parent, parent.resolveSibling("saved"));
      Files.createSymbolicLink(parent, outside.getParent());
      swapped[0] = true;
    }));
    assertTrue(swapped[0]);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void replacementWithTheSameSizeAndTimeStillFailsTheFileKeyCheck(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    boolean[] replaced = {false};
    assertThrows(IOException.class, () -> read(project, forceFallback, file -> {
      Path saved = Files.move(source, source.resolveSibling("saved.java"));
      Files.copy(saved, source, StandardCopyOption.COPY_ATTRIBUTES);
      replaced[0] = true;
    }));
    assertTrue(replaced[0]);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void directoryIdentityIsCheckedAfterReadingEvenWhenTheFileIdentityIsUnchanged(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    boolean[] replaced = {false};
    assertThrows(IOException.class, () -> read(project, forceFallback,
        new ConfinedSourceFiles.BeforeOpen() {
          @Override
          public void run(Path file) {}

          @Override
          public void afterRead(Path file) throws IOException {
            Path parent = source.getParent();
            Path saved = Files.move(parent, parent.resolveSibling("saved"));
            Files.createDirectory(parent);
            Files.createLink(source, saved.resolve(source.getFileName()));
            replaced[0] = true;
          }
        }));
    assertTrue(replaced[0], "replacement must happen after bytes were read");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void sameSizeEditAfterReadingFailsTheModifiedTimeCheck(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    FileTime changed = FileTime.fromMillis(Files.getLastModifiedTime(source).toMillis() + 10_000);
    boolean[] edited = {false};
    assertThrows(IOException.class, () -> read(project, forceFallback,
        new ConfinedSourceFiles.BeforeOpen() {
          @Override
          public void run(Path file) {}

          @Override
          public void afterRead(Path file) throws IOException {
            Files.writeString(source, TEXT.replace("Sample", "Decoy_"));
            Files.setLastModifiedTime(source, changed);
            edited[0] = true;
          }
        }));
    assertTrue(edited[0]);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void sourceRootAliasIsCheckedAgainAfterReading(
      boolean forceFallback, @TempDir Path project) throws Exception {
    sourceTree(project);
    Files.createDirectories(project.resolve("other/example"));
    Files.writeString(project.resolve("other/example/Sample.java"), TEXT);
    Path alias = Files.createSymbolicLink(project.resolve("sources"), project.resolve("src"));
    boolean[] swapped = {false};
    assertThrows(IOException.class, () -> ConfinedSourceFiles.read(
        project, "sources/example/Sample.java", new ConfinedSourceFiles.BeforeOpen() {
          @Override
          public void run(Path file) {}

          @Override
          public void afterRead(Path file) throws IOException {
            Files.delete(alias);
            Files.createSymbolicLink(alias, project.resolve("other"));
            swapped[0] = true;
          }
        }, forceFallback));
    assertTrue(swapped[0]);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void searchOnlyAncestorNeedsNoDirectoryReadPermission(
      boolean forceFallback, @TempDir Path ancestor) throws Exception {
    Path project = ancestor.resolve("project");
    sourceTree(project);
    var permissions = Files.getPosixFilePermissions(ancestor);
    try {
      Files.setPosixFilePermissions(ancestor, PosixFilePermissions.fromString("--x------"));
      assertArrayEquals(TEXT.getBytes(StandardCharsets.UTF_8),
          read(project, forceFallback, file -> {}).bytes());
    } finally {
      Files.setPosixFilePermissions(ancestor, permissions);
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void searchOnlyProjectAndSourceDirectoriesNeedNoReadPermission(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    for (Path directory : new Path[] {project, source.getParent()}) {
      var permissions = Files.getPosixFilePermissions(directory);
      try {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("--x------"));
        int[] opens = {0};
        assertArrayEquals(TEXT.getBytes(StandardCharsets.UTF_8),
            read(project, forceFallback, file -> opens[0]++).bytes());
        assertEquals(1, opens[0], "select fallback before opening the source, without retrying it");
      } finally {
        Files.setPosixFilePermissions(directory, permissions);
      }
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void boundedReadAllowsTheLimitAndRejectsGrowthBeyondIt(
      boolean forceFallback, @TempDir Path project) throws Exception {
    Path source = sourceTree(project);
    byte[] limit = new byte[ConfinedSourceFiles.MAX_SOURCE_BYTES];
    Files.write(source, limit);
    assertArrayEquals(limit, read(project, forceFallback, file -> {}).bytes());
    assertThrows(IOException.class, () -> read(project, forceFallback, file ->
        Files.write(source, new byte[limit.length + 1])));
    assertThrows(ConfinedSourceFiles.TooLarge.class,
        () -> read(project, forceFallback, file -> {}));
  }

  @Test
  @ResourceLock(Resources.SYSTEM_ERR)
  void unverifiableProviderHasADistinctDiagnosticWithoutPathsOrContent(@TempDir Path directory)
      throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    PrintStream original = System.err;
    ConfinedSourceFiles.resetDiagnosticForTest();
    try (var fs = FileSystems.newFileSystem(directory.resolve("sources.zip"), Map.of("create", "true"));
        PrintStream diagnostic = new PrintStream(output, true, StandardCharsets.UTF_8)) {
      Path project = fs.getPath("/project");
      sourceTree(project);
      System.setErr(diagnostic);
      assertThrows(ConfinedSourceFiles.CannotVerify.class,
          () -> read(project, true, file -> {}));
      assertThrows(ConfinedSourceFiles.CannotVerify.class,
          () -> read(project, true, file -> {}));
      assertEquals("{\"code\":\"XTR-JAVA-SOURCE-UNVERIFIABLE\","
          + "\"message\":\"Source unavailable: the platform cannot verify this read.\"}"
          + System.lineSeparator(), output.toString(StandardCharsets.UTF_8));
    } finally {
      System.setErr(original);
      ConfinedSourceFiles.resetDiagnosticForTest();
    }
  }
}
