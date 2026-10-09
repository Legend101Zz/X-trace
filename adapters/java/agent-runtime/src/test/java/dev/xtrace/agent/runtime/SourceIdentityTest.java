package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
