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
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AttachCommandsTest {
  @Test
  void helperWorkerReceivesTheAdmittedTemporaryDirectoryProperty() throws Exception {
    HelperSupervisor.Result result = HelperSupervisor.runWorker(
        SupervisorTestProgram.class.getName(),
        new String[] {"inspect", "tmpdir"},
        java.time.Duration.ofSeconds(5),
        supervisorTestClassPath());

    assertEquals(System.getProperty("java.io.tmpdir"), result.json());
    assertFalse(result.reliable());
  }

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
  void acceptanceFailureSanitizerRemovesPathsAndCanaries() {
    String canary = "ATTACH_BODY_CANARY_2A7";
    String root = temporaryDirectory.toAbsolutePath().toString();
    String source = "request " + canary + " in " + root + " bootstrap_path=/private/options.json";

    String safe = JavaAttachAcceptanceTest.sanitize(source, Path.of(root));

    assertFalse(safe.contains(canary));
    assertFalse(safe.contains(root));
    assertFalse(safe.contains("/private/options.json"));
    assertTrue(safe.contains("[redacted sensitive log line]"));
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
  void compressedOversizedJarManifestIsRejectedBeforeParsing() throws Exception {
    assumePosix();
    Path distribution = Files.createDirectory(temporaryDirectory.resolve("oversized-agent"));
    Path agent = distribution.resolve("xtrace-java-agent.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(agent))) {
      output.putNextEntry(new java.util.jar.JarEntry("META-INF/MANIFEST.MF"));
      output.write(("Manifest-Version: 1.0\nAgent-Class: "
              + "dev.xtrace.agent.bootstrap.XTraceAgent\nX-Pad: "
              + "A".repeat(96 * 1024)
              + "\n\n")
          .getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    Files.setPosixFilePermissions(agent, PosixFilePermissions.fromString("rw-r--r--"));

    AttachCommands.Failure failure =
        assertThrows(AttachCommands.Failure.class, () -> AgentArtifact.validate(agent));

    assertEquals("XTR-ATTACH-AGENT-INVALID", failure.code());
    assertTrue(failure.getMessage().contains("manifest exceeds its size limit"));
    assertFalse(failure.getMessage().contains(distribution.toString()));
  }

  @Test
  void verifiedDistributionSnapshotSurvivesSelectedArtifactReplacement() throws Exception {
    assumePosix();
    Path distribution = Files.createDirectory(temporaryDirectory.resolve("snapshot-source"));
    Path runtime = Files.createDirectory(distribution.resolve("runtime"));
    Path agent = distribution.resolve("xtrace-java-agent.jar");
    Path runtimeJar = runtime.resolve("agent-runtime.jar");
    writeAgentJar(agent, "original-agent-payload");
    Files.write(runtimeJar, "runtime-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Files.setPosixFilePermissions(runtimeJar, PosixFilePermissions.fromString("rw-r--r--"));
    writeDistributionManifest(distribution, agent, runtimeJar);
    Files.setPosixFilePermissions(distribution, PosixFilePermissions.fromString("rwxr-xr-x"));
    Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwxr-xr-x"));

    ProcessIdentity target = ProcessIdentity.read(ProcessHandle.current().pid(), "attach");
    AgentSnapshot snapshot = AgentArtifact.snapshot(agent, target.pid(), target.startTime());
    byte[] expectedAgent = Files.readAllBytes(snapshot.agentJar());
    try {
      writeAgentJar(agent, "replacement-agent-payload");

      assertTrue(java.util.Arrays.equals(expectedAgent, Files.readAllBytes(snapshot.agentJar())));
      assertTrue(Files.isRegularFile(snapshot.root().resolve("distribution/runtime/agent-runtime.jar")));
      assertEquals(
          0,
          (int) Files.getAttribute(snapshot.root(), "unix:mode") & 0077,
          "snapshot root permissions must exclude group and other users");
    } finally {
      java.util.Arrays.fill(expectedAgent, (byte) 0);
      AgentSnapshot.deleteOwnedSnapshot(snapshot.root(), target.pid(), target.startTime());
    }
    assertFalse(Files.exists(snapshot.root()), "readonly snapshot directories must be removable");
  }

  @Test
  void snapshotEntryBoundCountsZeroByteFiles() throws Exception {
    Path tree = Files.createDirectory(temporaryDirectory.resolve("many-empty-files"));
    for (int index = 0; index < 257; index++) {
      Files.createFile(tree.resolve("entry-" + index));
    }

    AttachCommands.Failure failure = assertThrows(
        AttachCommands.Failure.class, () -> AgentSnapshot.treeSize(tree, 1024));

    assertTrue(failure.getMessage().contains("entry or depth bound"));
  }

  private static void writeAgentJar(Path path, String payload) throws Exception {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue(
        "Agent-Class", "dev.xtrace.agent.bootstrap.XTraceAgent");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      output.putNextEntry(new java.util.jar.JarEntry("payload.txt"));
      output.write(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
  }

  private static void writeDistributionManifest(Path root, Path agent, Path runtime)
      throws Exception {
    String agentHash = java.util.HexFormat.of().formatHex(
        java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(agent)));
    String runtimeHash = java.util.HexFormat.of().formatHex(
        java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(runtime)));
    Path manifest = root.resolve("manifest.sha256");
    Files.writeString(
        manifest,
        agentHash + "  xtrace-java-agent.jar\n"
            + runtimeHash + "  runtime/agent-runtime.jar\n");
    Files.setPosixFilePermissions(manifest, PosixFilePermissions.fromString("rw-r--r--"));
  }

  @Test
  void helperSupervisorKillsOnlyItsTimedOutWorkerAndReportsUncertainty() throws Exception {
    String classPath = supervisorTestClassPath();
    Process target = new ProcessBuilder(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-cp",
        classPath,
        SupervisorTestProgram.class.getName(),
        "target")
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .start();
    try {
      ProcessIdentity identity = ProcessIdentity.read(target.pid(), "attach");
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (target.isAlive() && System.nanoTime() < deadline) Thread.sleep(10);
      assertTrue(target.isAlive());

      HelperSupervisor.TimeoutException timedOut =
          assertThrows(
              HelperSupervisor.TimeoutException.class,
              () ->
                  HelperSupervisor.runWorker(
                      SupervisorTestProgram.class.getName(),
                      new String[] {"hang"},
                      java.time.Duration.ofMillis(400),
                      classPath));

      assertTrue(target.isAlive(), "timeout must not kill or signal the target JVM");
      assertFalse(ProcessHandle.of(timedOut.workerPid()).map(ProcessHandle::isAlive).orElse(false));
      String result = HelperSupervisor.timeout("attach", target.pid(), identity).json();
      assertTrue(result.contains("XTR-ATTACH-TIMEOUT"));
      assertTrue(result.contains("unknown_after_timeout"));
      assertTrue(result.contains("\"targetIdentityStatus\":\"same\""));
    } finally {
      target.destroyForcibly();
      target.waitFor(5, TimeUnit.SECONDS);
    }
  }

  @Test
  void malformedSingleLineWorkerJsonProducesUncertainAttachResult() throws Exception {
    ProcessIdentity target = ProcessIdentity.read(ProcessHandle.current().pid(), "attach");
    HelperSupervisor.Result raw = HelperSupervisor.runWorker(
        SupervisorTestProgram.class.getName(),
        new String[] {"attach", "malformed-json"},
        java.time.Duration.ofSeconds(5),
        supervisorTestClassPath());

    HelperSupervisor.Result accepted = HelperSupervisor.acceptWorkerResult(
        "attach", target.pid(), target, raw);

    assertFalse(raw.reliable());
    assertEquals("{\"schemaVersion\":1,\"ok\":true", raw.json());
    assertEquals(7, accepted.exitCode());
    assertTrue(accepted.json().contains("unknown_after_helper_failure"));
    assertFalse(accepted.json().contains("{\"schemaVersion\":1,\"ok\":true"));
  }

  @Test
  void workerSuccessEnvelopeMustAgreeWithExitStatus() throws Exception {
    ProcessIdentity target = ProcessIdentity.read(ProcessHandle.current().pid(), "attach");
    HelperSupervisor.Result raw = HelperSupervisor.runWorker(
        SupervisorTestProgram.class.getName(),
        new String[] {"attach", "mismatched-exit"},
        java.time.Duration.ofSeconds(5),
        supervisorTestClassPath());

    HelperSupervisor.Result accepted = HelperSupervisor.acceptWorkerResult(
        "attach", target.pid(), target, raw);

    assertFalse(raw.reliable());
    assertEquals(7, accepted.exitCode());
    assertTrue(accepted.json().contains("unknown_after_helper_failure"));
  }

  @Test
  void survivingOwnedWorkerReportsIdentityAndRetainsPrimaryFailure() throws Exception {
    UnstoppableProcess worker = new UnstoppableProcess();
    ProcessIdentity identity = ProcessIdentity.read(worker.pid(), "attach");

    HelperSupervisor.WorkerCleanupException cleanup = assertThrows(
        HelperSupervisor.WorkerCleanupException.class,
        () -> HelperSupervisor.ensureWorkerStopped(
            worker,
            new HelperSupervisor.TimeoutException(worker.pid()),
            java.time.Duration.ofMillis(10)));
    HelperSupervisor.Result result = HelperSupervisor.workerCleanupFailure(
        "attach", identity.pid(), identity, cleanup);

    assertTrue(worker.destroyRequested());
    assertTrue(worker.isAlive(), "the double models a still-running owned worker");
    assertTrue(cleanup.getSuppressed()[0] instanceof HelperSupervisor.TimeoutException);
    assertEquals(identity.pid(), cleanup.workerPid());
    assertEquals(identity.startTime(), cleanup.workerStartTime());
    assertTrue(result.json().contains("XTR-ATTACH-WORKER-UNCONFIRMED"));
    assertTrue(result.json().contains("unknown_after_helper_cleanup_failure"));
    assertTrue(result.json().contains("\"helperWorkerPid\":" + identity.pid()));
    assertTrue(result.json().contains("\"helperWorkerStartTime\":"));
    assertFalse(result.json().contains("test timeout"));
    assertTrue(result.json().contains("\"helperWorkerFailureKind\":\"timeout\""));
  }

  @Test
  void boundedJsonRequiresCompleteUniqueTypedWorkerEnvelope() {
    String good = "{\"schemaVersion\":1,\"ok\":true,\"command\":\"attach\","
        + "\"code\":\"XTR-ATTACH-OK\",\"message\":\"completed\"}";

    assertTrue(BoundedJson.isWorkerResponse(good, "attach", 0));
    assertFalse(BoundedJson.isWorkerResponse(good + " trailing", "attach", 0));
    assertFalse(BoundedJson.isWorkerResponse(
        good.replace("completed", "\\u" + "\uff26\uff10\uff10\uff10"),
        "attach",
        0));
    assertFalse(BoundedJson.isWorkerResponse(
        good.replace("\"message\":\"completed\"", "\"message\":\"ok\",\"process\":{\"pid\":1,\"unknown\":{\"field\":true}}"),
        "attach",
        0));
    assertFalse(BoundedJson.isWorkerResponse(
        "{\"schemaVersion\":1,\"schemaVersion\":1,\"ok\":true,"
            + "\"command\":\"attach\",\"code\":\"XTR-ATTACH-OK\",\"message\":\"ok\"}",
        "attach",
        0));
    assertFalse(BoundedJson.isWorkerResponse(
        "{\"schemaVersion\":\"1\",\"ok\":true,\"command\":\"attach\","
            + "\"code\":\"XTR-ATTACH-OK\",\"message\":\"ok\"}",
        "attach",
        0));
    assertFalse(BoundedJson.isWorkerResponse(
        "{\"schemaVersion\":1,\"ok\":false,\"command\":\"attach\","
            + "\"code\":\"XTR-ATTACH-FAILED\",\"message\":\"failed\"}",
        "attach",
        0));
    assertFalse(BoundedJson.isWorkerResponse(good, "inspect", 0));
  }

  private String supervisorTestClassPath() throws Exception {
    return Path.of(
            SupervisorTestProgram.class.getProtectionDomain().getCodeSource().getLocation().toURI())
        + java.io.File.pathSeparator
        + Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
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
