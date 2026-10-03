package io.xtrace.attach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AttachCommandsTest {
  private static final String SECRET_CANARY = "xtrace-private-canary-7f38";

  @TempDir Path temporaryDirectory;

  @Test
  void invalidArgumentsReturnStableJsonWithoutEchoingArguments() {
    String privateArgument = "/private/path/" + SECRET_CANARY;
    AttachCommands.Result result =
        AttachCommands.execute(new String[] {"attach", "--options-file", privateArgument});

    assertEquals(2, result.exitCode());
    assertTrue(result.toJson().contains("XTR-ATTACH-INVALID-ARGUMENTS"));
    assertFalse(result.toJson().contains(privateArgument));
    assertFalse(result.toJson().contains(SECRET_CANARY));
  }

  @Test
  void processFactsExcludeArgumentAndEnvironmentSecrets() throws Exception {
    ProcessIdentity identity = ProcessIdentity.read(ProcessHandle.current().pid());
    Properties properties = new Properties();
    properties.setProperty("java.specification.version", "17");
    properties.setProperty("java.vendor", SECRET_CANARY);
    properties.setProperty("java.vm.name", "OpenJDK 64-Bit Server VM");

    String json = Json.encode(identity.toJson(properties, true, "test-provider"));

    assertTrue(json.contains("\"pid\":"));
    assertTrue(json.contains("\"startTime\":"));
    assertTrue(json.contains("\"owner\":"));
    assertEquals("17", identity.toJson(properties, true, "test-provider").get("jdkVersion"));
    assertFalse(json.contains(SECRET_CANARY));
    assertFalse(json.contains("commandLine"));
    assertFalse(json.contains("environment"));
  }

  @Test
  void privateBootstrapAcceptsOnlyPrivateBoundedRegularFile() throws Exception {
    assumePosix();
    Path privateDirectory =
        Files.createDirectory(
            temporaryDirectory.resolve("private"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    Path bootstrap = privateDirectory.resolve("bootstrap.json");
    Files.writeString(bootstrap, "{\"sessionId\":\"" + SECRET_CANARY + "\"}");
    Files.setPosixFilePermissions(bootstrap, PosixFilePermissions.fromString("rw-------"));

    assertEquals(bootstrap.toRealPath(), PrivateBootstrap.validate(bootstrap));

    Files.setPosixFilePermissions(bootstrap, PosixFilePermissions.fromString("rw-r--r--"));
    AttachCommands.Failure failure =
        assertThrows(AttachCommands.Failure.class, () -> PrivateBootstrap.validate(bootstrap));
    assertTrue(failure.getMessage().contains("owner-readable"));
    assertFalse(failure.getMessage().contains(SECRET_CANARY));
  }

  @Test
  void privateBootstrapRejectsSymlinksMalformedDocumentsAndOversizedReads() throws Exception {
    assumePosix();
    Path privateDirectory =
        Files.createDirectory(
            temporaryDirectory.resolve("private"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    Path target = privateDirectory.resolve("target.json");
    Files.writeString(target, "{\"ok\":true}");
    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
    Path link = privateDirectory.resolve("link.json");
    Files.createSymbolicLink(link, target.getFileName());
    assertThrows(AttachCommands.Failure.class, () -> PrivateBootstrap.validate(link));

    Path malformed = privateDirectory.resolve("malformed.json");
    Files.writeString(malformed, "not-json");
    Files.setPosixFilePermissions(malformed, PosixFilePermissions.fromString("rw-------"));
    assertThrows(AttachCommands.Failure.class, () -> PrivateBootstrap.validate(malformed));

    Path oversized = privateDirectory.resolve("oversized.json");
    Files.write(oversized, new byte[64 * 1024 + 1]);
    Files.setPosixFilePermissions(oversized, PosixFilePermissions.fromString("rw-------"));
    AttachCommands.Failure failure =
        assertThrows(AttachCommands.Failure.class, () -> PrivateBootstrap.validate(oversized));
    assertFalse(failure.getMessage().contains(oversized.toString()));
  }

  @Test
  void xtraceAgentRequiresACompleteIntegrityVerifiedDistribution() throws Exception {
    assumePosix();
    Path distribution = Files.createDirectory(temporaryDirectory.resolve("agent"));
    Path runtime = Files.createDirectory(distribution.resolve("runtime"));
    Path agent = distribution.resolve("xtrace-java-agent.jar");
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest
        .getMainAttributes()
        .putValue("Agent-Class", "dev.xtrace.agent.bootstrap.XTraceAgent");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(agent), manifest)) {
      // A valid empty agent JAR manifest is enough to test distribution identity validation.
    }
    Files.write(runtime.resolve("agent-runtime.jar"), new byte[] {1, 2, 3});
    Files.setPosixFilePermissions(agent, PosixFilePermissions.fromString("rw-r--r--"));
    Files.setPosixFilePermissions(runtime.resolve("agent-runtime.jar"), PosixFilePermissions.fromString("rw-r--r--"));
    Files.writeString(
        distribution.resolve("manifest.sha256"),
        "0".repeat(64) + "  xtrace-java-agent.jar\n" + "0".repeat(64) + "  runtime/agent-runtime.jar\n");
    Files.setPosixFilePermissions(
        distribution.resolve("manifest.sha256"), PosixFilePermissions.fromString("rw-r--r--"));

    AttachCommands.Failure failure =
        assertThrows(AttachCommands.Failure.class, () -> AgentArtifact.validate(agent));
    assertTrue(failure.getMessage().contains("digest does not match"));
    assertFalse(failure.getMessage().contains(distribution.toString()));
  }

  @Test
  void processIdentityUsesOnlyKnownExecutableAndSafeJdkFacts() throws Exception {
    Properties target = new Properties();
    target.setProperty("java.specification.version", "21");
    target.setProperty("java.vendor", "Eclipse Adoptium");
    target.setProperty("java.vm.name", "OpenJDK 64-Bit Server VM");
    ProcessIdentity identity = ProcessIdentity.read(ProcessHandle.current().pid());
    Map<String, Object> facts = identity.toJson(target, true, "sun.tools.attach.VirtualMachineImpl");

    assertEquals("21", facts.get("jdkVersion"));
    assertEquals("eclipse_adoptium", facts.get("jdkVendor"));
    assertEquals("hotspot", facts.get("vmKind"));
    assertEquals("sun.tools.attach.VirtualMachineImpl", facts.get("attachProvider"));
    assertEquals("best_effort", facts.get("attachEligibility"));
    assertNotNull(facts.get("startTime"));
  }

  private void assumePosix() throws Exception {
    assumeTrue(Files.getFileStore(temporaryDirectory).supportsFileAttributeView("posix"));
  }
}
