package dev.xtrace.adapter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class BootstrapReaderTest {
  @TempDir Path temporary;

  @Test
  void validatesPrivateBootstrapAndClosesSecret() throws Exception {
    assumeUnixFilesystem();
    Path file = temporary.resolve("bootstrap.json");
    Files.writeString(file, validJson(), StandardCharsets.UTF_8);
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    Bootstrap bootstrap = BootstrapReader.read(file);
    byte[] expected = new byte[32];
    java.util.Arrays.fill(expected, (byte) 0x5a);
    assertArrayEquals(expected, bootstrap.copySessionSecret());
    assertEquals("127.0.0.1", bootstrap.host());
    var secretField = Bootstrap.class.getDeclaredField("sessionSecret");
    secretField.setAccessible(true);
    byte[] ownedSecret = (byte[]) secretField.get(bootstrap);
    bootstrap.close();
    assertArrayEquals(new byte[32], ownedSecret);
    assertThrows(IllegalStateException.class, bootstrap::copySessionSecret);
  }

  @Test
  void rejectsLoosePermissionsSymlinkHardlinkAndNonCanonicalFields() throws Exception {
    assumeUnixFilesystem();
    Path loose = temporary.resolve("loose.json");
    Files.writeString(loose, validJson());
    Files.setPosixFilePermissions(loose, PosixFilePermissions.fromString("rw-r--r--"));
    assertThrows(ClientException.class, () -> BootstrapReader.read(loose));

    Path privateFile = temporary.resolve("private.json");
    Files.writeString(privateFile, validJson());
    Files.setPosixFilePermissions(privateFile, PosixFilePermissions.fromString("rw-------"));
    Path symlink = temporary.resolve("link.json");
    Files.createSymbolicLink(symlink, privateFile.getFileName());
    assertThrows(ClientException.class, () -> BootstrapReader.read(symlink));
    Path hardlink = temporary.resolve("hard.json");
    Files.createLink(hardlink, privateFile);
    assertThrows(ClientException.class, () -> BootstrapReader.read(privateFile));

    Path oversized = temporary.resolve("oversized.json");
    Files.write(oversized, new byte[64 * 1024 + 1]);
    Files.setPosixFilePermissions(oversized, PosixFilePermissions.fromString("rw-------"));
    assertThrows(ClientException.class, () -> BootstrapReader.read(oversized));

    byte[] invalid = validJson().replace("127.0.0.1", "localhost").getBytes(StandardCharsets.UTF_8);
    assertThrows(ClientException.class, () -> BootstrapReader.parse(invalid));
  }

  @Test
  void rejectsMalformedOversizedAndNonCanonicalSecret() {
    assertThrows(
        ClientException.class, () -> BootstrapReader.parse("[]".getBytes(StandardCharsets.UTF_8)));
    String duplicate = validJson().replace("{", "{\"host\":\"127.0.0.1\",");
    assertThrows(
        ClientException.class,
        () -> BootstrapReader.parse(duplicate.getBytes(StandardCharsets.UTF_8)));
    String invalidSecret =
        validJson()
            .replace(
                Base64.getEncoder().encodeToString(secret()),
                Base64.getEncoder().encodeToString(new byte[31]));
    assertThrows(
        ClientException.class,
        () -> BootstrapReader.parse(invalidSecret.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void rejectsPermissiveSymlinkedOrReplacedParent() throws Exception {
    assumeUnixFilesystem();
    Path permissive = temporary.resolve("permissive-parent");
    Files.createDirectory(permissive);
    Files.setPosixFilePermissions(permissive, PosixFilePermissions.fromString("rwxr-xr-x"));
    Path permissiveBootstrap = permissive.resolve("bootstrap.json");
    Files.writeString(permissiveBootstrap, validJson());
    Files.setPosixFilePermissions(
        permissiveBootstrap, PosixFilePermissions.fromString("rw-------"));
    assertThrows(ClientException.class, () -> BootstrapReader.read(permissiveBootstrap));

    Path actual = temporary.resolve("actual-parent");
    Files.createDirectory(actual);
    Files.setPosixFilePermissions(actual, PosixFilePermissions.fromString("rwx------"));
    Path linkedBootstrap = actual.resolve("bootstrap.json");
    Files.writeString(linkedBootstrap, validJson());
    Files.setPosixFilePermissions(linkedBootstrap, PosixFilePermissions.fromString("rw-------"));
    Path linkedParent = temporary.resolve("linked-parent");
    Files.createSymbolicLink(linkedParent, actual.getFileName());
    assertThrows(
        ClientException.class, () -> BootstrapReader.read(linkedParent.resolve("bootstrap.json")));

    Path replaceable = temporary.resolve("replaceable-parent");
    Files.createDirectory(replaceable);
    Files.setPosixFilePermissions(replaceable, PosixFilePermissions.fromString("rwx------"));
    BootstrapReader.ParentIdentity identity = BootstrapReader.inspectParent(replaceable);
    Files.move(replaceable, temporary.resolve("original-parent"));
    Files.createDirectory(replaceable);
    Files.setPosixFilePermissions(replaceable, PosixFilePermissions.fromString("rwx------"));
    assertThrows(ClientException.class, () -> BootstrapReader.verifyParent(replaceable, identity));
  }

  @Test
  void nonUnixPlatformsRejectBootstrapFileReads() {
    Assumptions.assumeFalse(isUnixFilesystem(), "exercises the non-Unix fail-closed branch");
    ClientException error =
        assertThrows(ClientException.class, () -> BootstrapReader.read(temporary.resolve("x")));
    assertEquals("XTR-JAVA-PLATFORM", error.code());
  }

  private static void assumeUnixFilesystem() {
    Assumptions.assumeTrue(isUnixFilesystem(), "requires Unix ownership and POSIX mode checks");
  }

  private static boolean isUnixFilesystem() {
    return java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("unix");
  }

  private static String validJson() {
    return """
    {"schema_version":1,"host":"127.0.0.1","port":32123,
    "certificate_sha256_pin":"%s",
    "runtime_session_id":"01900000-0000-7000-8000-000000000001",
    "session_secret_base64":"%s",
    "project_id":"01900000-0000-7000-8000-000000000002",
    "expected_repository_fingerprint":"b3:%s",
    "max_protocol_major":1,"max_protocol_minor":0}
    """
        .formatted("1".repeat(64), Base64.getEncoder().encodeToString(secret()), "2".repeat(64));
  }

  private static byte[] secret() {
    byte[] value = new byte[32];
    java.util.Arrays.fill(value, (byte) 0x5a);
    return value;
  }
}
