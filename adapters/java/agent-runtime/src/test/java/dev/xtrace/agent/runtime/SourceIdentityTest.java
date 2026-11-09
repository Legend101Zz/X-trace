package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.testapp.SampleService;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SourceIdentityTest {
  private static final String CLASS_NAME = "dev.xtrace.agent.runtime.testapp.SampleService";
  private static final String INTERNAL = CLASS_NAME.replace('.', '/');
  private static final String PLACE = "(Ljava/lang/String;)Ljava/lang/String;";
  private static final String SOURCE =
      "src/main/java/dev/xtrace/agent/runtime/testapp/SampleService.java";

  @AfterEach
  void reset() {
    SourceIdentity.resetForTest();
  }

  private static byte[] classBytes() throws Exception {
    try (InputStream in =
        SampleService.class.getClassLoader().getResourceAsStream(INTERNAL + ".class")) {
      return in.readAllBytes();
    }
  }

  private static Path sourceTree(Path repo, int lines) throws Exception {
    Files.createDirectories(repo.resolve(".git"));
    Path dir = repo.resolve("src/main/java/dev/xtrace/agent/runtime/testapp");
    Files.createDirectories(dir);
    Path file = dir.resolve("SampleService.java");
    Files.writeString(file, "// line\n".repeat(lines), StandardCharsets.UTF_8);
    return file;
  }

  @Test
  void observedUnattestedHashEqualsBlake3OfTheSourceFile(@TempDir Path repo) throws Exception {
    Path file = sourceTree(repo, 200);
    SourceIdentity.observe(
        SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java"), repo);
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(
        "src/main/java/dev/xtrace/agent/runtime/testapp/SampleService.java", info.path());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash());
    assertTrue(info.startLine() >= 1 && info.endLine() > info.startLine(), info.toString());
  }

  @Test
  void methodRangeComesFromTheClassDebugLineTable() throws Exception {
    SourceIdentity.ClassFacts facts = SourceIdentity.parse(INTERNAL, classBytes());
    int[] place = facts.range("place" + PLACE);
    int[] shout = facts.range("shout" + PLACE);
    assertNotNull(place);
    assertNotNull(shout);
    assertTrue(place[0] >= 1 && place[1] > place[0]);
    assertEquals(shout[0], shout[1], "single-statement method has one line");
    assertEquals("SampleService.java", facts.sourceFile());
    assertNull(facts.range("noSuchMethod()V"));
  }

  @Test
  void linePastEndOfFileDowngradesToMetadataInvalid(@TempDir Path repo) throws Exception {
    sourceTree(repo, 3);
    SourceIdentity.observe(
        SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java"), repo);
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(5, info.binding());
    assertNull(info.path());
    assertNull(info.hash());
  }

  @Test
  void missingSourceFileIsShownAsMissingNotAsMatch(@TempDir Path repo) throws Exception {
    Files.createDirectories(repo.resolve(".git"));
    SourceIdentity.observe(
        SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java"), repo);
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(2, info.binding());
    assertNull(info.path());
    assertSourceUnavailable();
  }

  @Test
  void explicitProjectNeverUsesAnAncestorDecoy(@TempDir Path ancestor) throws Exception {
    sourceTree(ancestor, 200);
    Path project = Files.createDirectory(ancestor.resolve("project"));
    String escaped = project.toString().replace("\\", "\\\\").replace("\"", "\\\"");
    CaptureConfig config = CaptureConfig.parse(
        ("{\"capture_schema_version\":1,\"project_dir\":\"" + escaped + "\","
            + "\"application_scope\":{\"application_packages\":[\"dev.xtrace.agent.runtime.testapp\"],"
            + "\"source_roots\":[\"src/main/java\"]}}")
            .getBytes(StandardCharsets.UTF_8));
    assertEquals(project, config.scope().sourceBase());
    observe(config.scope().sourceBase(), config.scope().sourceRoots());
    assertSourceUnavailable();
  }

  @Test
  void workingDirectoryBoundaryNeverUsesAnAncestorDecoy(@TempDir Path ancestor) throws Exception {
    sourceTree(ancestor, 200);
    Path workingDirectory = Files.createDirectory(ancestor.resolve("working-directory"));
    observe(workingDirectory, List.of("src/main/java"));
    assertSourceUnavailable();
  }

  @Test
  void symlinkedDirectoryEscapeStopsLookupBeforeAnotherRoot(@TempDir Path directory)
      throws Exception {
    Path external = directory.resolve("external");
    sourceTree(external, 200);
    Path project = Files.createDirectory(directory.resolve("project"));
    sourceTree(project.resolve("fallback"), 200);
    Files.createSymbolicLink(project.resolve("src"), external.resolve("src"));
    observe(project, List.of("src/main/java", "fallback/src/main/java"));
    assertSourceUnavailable();
  }

  @Test
  void symlinkedFileEscapeStopsLookupBeforeAnotherRoot(@TempDir Path directory) throws Exception {
    Path external = sourceTree(directory.resolve("external"), 200);
    Path project = directory.resolve("project");
    Path file = sourceTree(project, 200);
    Files.delete(file);
    Files.createSymbolicLink(file, external);
    sourceTree(project.resolve("fallback"), 200);
    observe(project, List.of("src/main/java", "fallback/src/main/java"));
    assertSourceUnavailable();
  }

  @Test
  void fileSwappedForExternalSymlinkAfterValidationIsUnavailable(@TempDir Path directory)
      throws Exception {
    Path external = sourceTree(directory.resolve("external"), 200);
    Path project = directory.resolve("project");
    Path file = sourceTree(project, 200);
    sourceTree(project.resolve("fallback"), 200);
    boolean[] swapped = {false};
    SourceIdentity.observe(SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java", "fallback/src/main/java"), project, validated -> {
          assertEquals(file.toRealPath(), validated);
          Files.delete(file);
          Files.createSymbolicLink(file, external);
          swapped[0] = true;
        });
    assertTrue(swapped[0], "swap must occur between validation and opening");
    assertSourceUnavailable();
  }

  @Test
  void directorySwappedForExternalSymlinkAfterValidationIsUnavailable(@TempDir Path directory)
      throws Exception {
    Path external = sourceTree(directory.resolve("external"), 200);
    Path project = directory.resolve("project");
    Path file = sourceTree(project, 200);
    sourceTree(project.resolve("fallback"), 200);
    boolean[] swapped = {false};
    SourceIdentity.observe(SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java", "fallback/src/main/java"), project, validated -> {
          Path parent = file.getParent();
          Files.move(parent, parent.resolveSibling("saved-testapp"));
          Files.createSymbolicLink(parent, external.getParent());
          swapped[0] = true;
        });
    assertTrue(swapped[0], "the opened parent must be replaced during the read");
    assertSourceUnavailable();
  }

  @Test
  void sameSizedFileReplacementAfterValidationIsUnavailable(@TempDir Path project)
      throws Exception {
    Path file = sourceTree(project, 200);
    boolean[] swapped = {false};
    SourceIdentity.observe(SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java"), project, validated -> {
          // Keep the original inode alive, and preserve size/mtime: fileKey must catch this.
          Path original = Files.move(file, file.resolveSibling("original.java"));
          Files.copy(original, file, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
          swapped[0] = true;
        });
    assertTrue(swapped[0]);
    assertSourceUnavailable();
  }

  @Test
  void fileGrowthAfterValidationIsUnavailable(@TempDir Path project) throws Exception {
    Path file = sourceTree(project, 200);
    boolean[] edited = {false};
    SourceIdentity.observe(SampleService.class.getClassLoader(), INTERNAL, classBytes(),
        List.of("src/main/java"), project, validated -> {
          Files.writeString(file, "// growth\n", java.nio.file.StandardOpenOption.APPEND);
          edited[0] = true;
        });
    assertTrue(edited[0]);
    assertSourceUnavailable();
  }

  @Test
  void oversizedSourceIsMetadataInvalid(@TempDir Path project) throws Exception {
    Path file = sourceTree(project, 200);
    Files.write(file, new byte[1024 * 1024 + 1]);
    observe(project, List.of("src/main/java"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(5, info.binding());
    assertNull(info.path());
    assertNull(info.hash());
  }

  @Test
  void sourceDirectoryAliasWithinProjectKeepsTheHappyPath(@TempDir Path project)
      throws Exception {
    Path file = sourceTree(project, 200);
    Files.createSymbolicLink(project.resolve("sources"), project.resolve("src/main/java"));
    observe(project, List.of("sources"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(SOURCE, info.path());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash());
  }

  @Test
  void sourceRootCannotTraverseOrNameAnAbsoluteOutsidePath(@TempDir Path directory)
      throws Exception {
    Path external = directory.resolve("external");
    sourceTree(external, 200);
    Path project = Files.createDirectory(directory.resolve("project"));
    sourceTree(project.resolve("fallback"), 200);
    for (String root : List.of(
        "../external/src/main/java", external.resolve("src/main/java").toString())) {
      observe(project, List.of(root, "fallback/src/main/java"));
      assertSourceUnavailable();
    }
  }

  @Test
  void canonicalProjectAliasBindsOnlyItsOwnSource(@TempDir Path directory) throws Exception {
    Path project = directory.resolve("project");
    Path file = sourceTree(project, 200);
    Path alias = Files.createSymbolicLink(directory.resolve("project-alias"), project);
    observe(alias, List.of("src/main/java"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(SOURCE, info.path());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash());
  }

  @Test
  void symlinkWithinTheProjectCannotHideASourceFileNameMismatch(@TempDir Path project)
      throws Exception {
    Path file = sourceTree(project, 200);
    Path renamed = Files.move(file, file.resolveSibling("Different.java"));
    Files.createSymbolicLink(file, renamed);
    observe(project, List.of("src/main/java"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(5, info.binding());
    assertNull(info.path());
    assertNull(info.hash());
    assertNull(SourceIdentity.lookupLine(INTERNAL, 1));
  }

  @Test
  void pathIsRelativeToTheProjectEvenWhenGitIsAboveIt(@TempDir Path directory) throws Exception {
    Files.createDirectory(directory.resolve(".git"));
    Path project = directory.resolve("project");
    Path file = sourceTree(project, 200);
    Files.delete(project.resolve(".git"));
    observe(project, List.of("src/main/java"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(SOURCE, info.path());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash());
  }

  @Test
  void missingFirstRootStillAllowsAnotherProjectLocalRoot(@TempDir Path project) throws Exception {
    Path file = sourceTree(project, 200);
    observe(project, List.of("absent/src/main/java", "src/main/java"));
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertEquals(SOURCE, info.path());
    assertArrayEquals(SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash());
  }

  @Test
  void sourceHashStaysBoundToTheBytesObservedAtClassLoad(@TempDir Path project) throws Exception {
    Path file = sourceTree(project, 200);
    byte[] observedHash = SourceAttestation.blake3Of(Files.readAllBytes(file));
    observe(project, List.of("src/main/java"));
    Files.writeString(file, "// edited\n".repeat(200), StandardCharsets.UTF_8);
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, info.binding());
    assertArrayEquals(observedHash, info.hash());
    assertFalse(java.util.Arrays.equals(
        SourceAttestation.blake3Of(Files.readAllBytes(file)), info.hash()));
  }

  private static void observe(Path base, List<String> roots) throws Exception {
    SourceIdentity.observe(SampleService.class.getClassLoader(), INTERNAL, classBytes(), roots, base);
  }

  private static void assertSourceUnavailable() {
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(2, info.binding());
    assertNull(info.path());
    assertNull(info.hash());
    assertEquals(0, info.startLine());
    assertEquals(0, info.endLine());
    assertNull(SourceIdentity.lookupLine(INTERNAL, 1));
  }

  @Test
  void sourceFileNameMustBeASimpleJavaName() {
    SourceIdentity.ClassFacts facts = new SourceIdentity.ClassFacts("a.B", "a/B");
    facts.resolve(List.of("src/main/java"), Path.of("."));
    assertEquals(4, facts.info("m()V").binding(), "absent SourceFile attribute");
  }

  @Test
  void unobservedClassHasNoSourceIdentity() {
    SourceAttestation.SourceInfo info = SourceIdentity.lookup(SampleService.class, "place", PLACE);
    assertEquals(2, info.binding());
  }

  @Test
  void lineCountMatchesEditorConvention() {
    assertEquals(0, SourceIdentity.countLines(new byte[0]));
    assertEquals(1, SourceIdentity.countLines("a".getBytes(StandardCharsets.UTF_8)));
    assertEquals(1, SourceIdentity.countLines("a\n".getBytes(StandardCharsets.UTF_8)));
    assertEquals(2, SourceIdentity.countLines("a\nb".getBytes(StandardCharsets.UTF_8)));
    assertEquals(2, SourceIdentity.countLines("a\nb\n".getBytes(StandardCharsets.UTF_8)));
  }
}
