package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CaptureConfigTest {
  private static byte[] json(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  void parsesApplicationScopeAndIgnoresUnknownFields() {
    CaptureConfig config =
        CaptureConfig.parse(
            json(
                "{\"capture_schema_version\":1,\"future\":{\"x\":[1,2,{\"y\":null}]},"
                    + "\"launch\":{\"kind\":\"direct\",\"package_manager\":null},"
                    + "\"application_scope\":{\"application_packages\":[\"com.acme\",\"java.lang\"],"
                    + "\"application_roots\":[\"/private/abs\"],"
                    + "\"source_roots\":[\"src/main/java\",\"../escape\",\"/abs\"],"
                    + "\"deny_packages\":[]}}"));
    assertEquals(List.of("com.acme"), config.scope().packages());
    assertEquals(List.of("src/main/java"), config.scope().sourceRoots());
  }

  @Test
  void focusedModeIsOptInAndNeverImplied() {
    String scope = "\"application_scope\":{\"application_packages\":[\"com.acme\"]}";
    assertTrue(
        CaptureConfig.parse(
                json("{\"capture_schema_version\":1,\"capture\":{\"mode\":\"focused\"}," + scope + "}"))
            .focused());
    for (String other :
        new String[] {
          "{\"capture_schema_version\":1," + scope + "}",
          "{\"capture_schema_version\":1,\"capture\":{\"mode\":\"standard\"}," + scope + "}",
          "{\"capture_schema_version\":1,\"capture\":{\"mode\":\"FOCUSED\"}," + scope + "}",
          "{\"capture_schema_version\":1,\"capture\":\"focused\"," + scope + "}",
          "{\"capture_schema_version\":1,\"capture\":{\"mode\":true}," + scope + "}",
        }) {
      assertFalse(CaptureConfig.parse(json(other)).focused(), other);
    }
    assertFalse(CaptureConfig.defaults().focused());
  }

  @Test
  void malformedOrWrongVersionYieldsDefaults() {
    for (String bad :
        new String[] {
          "", "{", "[]", "{\"capture_schema_version\":2,\"application_scope\":{}}",
          "{\"capture_schema_version\":1}",
          "{\"capture_schema_version\":1,\"application_scope\":{\"application_packages\":[\"a\"]}} x"
        }) {
      CaptureConfig config = CaptureConfig.parse(json(bad));
      assertFalse(config.scope().configured(), bad);
      assertEquals(List.of("src/main/java"), config.scope().sourceRoots(), bad);
    }
  }

  @Test
  void deeplyNestedInputIsRejected() {
    String deep = "[".repeat(20) + "]".repeat(20);
    CaptureConfig config =
        CaptureConfig.parse(
            json("{\"capture_schema_version\":1,\"application_scope\":{\"x\":" + deep + "}}"));
    assertFalse(config.scope().configured());
  }

  @Test
  void missingFileMeansDefaults(@TempDir Path directory) {
    CaptureConfig config = CaptureConfig.readBeside(directory.resolve("bootstrap.json"));
    assertFalse(config.scope().configured());
  }

  @Test
  void ownerOnlyFileIsReadAndGroupReadableFileIsIgnored(@TempDir Path directory) throws Exception {
    Path file = directory.resolve("capture.json");
    Files.write(
        file,
        json(
            "{\"capture_schema_version\":1,\"application_scope\":"
                + "{\"application_packages\":[\"com.acme\"]}}"));
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    assertTrue(CaptureConfig.readBeside(directory.resolve("bootstrap.json")).scope().configured());
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----"));
    assertFalse(CaptureConfig.readBeside(directory.resolve("bootstrap.json")).scope().configured());
  }

  @Test
  void symlinkedFileIsIgnored(@TempDir Path directory) throws Exception {
    Path real = directory.resolve("real.json");
    Files.write(
        real,
        json(
            "{\"capture_schema_version\":1,\"application_scope\":"
                + "{\"application_packages\":[\"com.acme\"]}}"));
    Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rw-------"));
    Files.createSymbolicLink(directory.resolve("capture.json"), real);
    assertFalse(CaptureConfig.readBeside(directory.resolve("bootstrap.json")).scope().configured());
  }

  @Test
  void projectDirectoryIsTheSourceBaseWhenItNamesAnExistingAbsoluteDirectory(@TempDir Path directory) {
    String scope = "\"application_scope\":{\"application_packages\":[\"com.acme\"]}";
    String escaped = directory.toString().replace("\\", "\\\\");
    CaptureConfig config =
        CaptureConfig.parse(
            json("{\"capture_schema_version\":1,\"project_dir\":\"" + escaped + "\"," + scope + "}"));
    assertEquals(directory.normalize(), config.scope().sourceBase());
    for (String bad : new String[] {"relative/dir", "", "/does/not/exist/anywhere", "/tmp\\u0000x"}) {
      CaptureConfig ignored =
          CaptureConfig.parse(
              json("{\"capture_schema_version\":1,\"project_dir\":\"" + bad + "\"," + scope + "}"));
      assertEquals(
          Path.of(System.getProperty("user.dir", ".")), ignored.scope().sourceBase(), bad);
    }
    assertEquals(
        Path.of(System.getProperty("user.dir", ".")),
        CaptureConfig.parse(json("{\"capture_schema_version\":1," + scope + "}")).scope().sourceBase());
  }
}
