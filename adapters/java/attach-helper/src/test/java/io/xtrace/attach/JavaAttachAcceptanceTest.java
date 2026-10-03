package io.xtrace.attach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.PosixFileAttributeView;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Genuine attach journey against a disposable, already-running Spring fixture and X-trace daemon. */
@Tag("acceptance")
class JavaAttachAcceptanceTest {
  private static final String BODY_CANARY = "ATTACH_BODY_CANARY_2A7";
  private static final Pattern RECORDING_ID =
      Pattern.compile("\\\"recording_id\\\":\\\"([0-9a-f-]{36})\\\"");
  private static final Pattern STRING_FIELD =
      Pattern.compile("\\\"%s\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"");

  @Test
  void attachesToRunningSpringJvmAndPersistsVerifiedSourceEvidence() throws Exception {
    Path cli = requiredPath("xtrace.cli");
    Path targetJava = requiredPath("xtrace.target.java");
    Path helperJava = Path.of(
        System.getProperty(
            "xtrace.helper.java", Path.of(System.getProperty("java.home"), "bin", "java").toString()));
    Path agent = requiredPath("xtrace.agent");
    Path fixture = requiredPath("xtrace.fixture");
    Path helper = requiredPath("xtrace.helper");
    Path workspace = requiredPath("xtrace.workspace");
    Path evidenceDirectory = requiredPath("xtrace.attach.evidence.dir");

    Path root = Files.createTempDirectory("xtrace-java-attach-");
    setPrivateDirectory(root);
    Path repository = Files.createDirectory(root.resolve("repository"));
    Path dataHome = Files.createDirectory(root.resolve("data"));
    Path secondRepository = Files.createDirectory(root.resolve("second-repository"));
    Path secondDataHome = Files.createDirectory(root.resolve("second-data"));
    Path logs = Files.createDirectory(root.resolve("logs"));
    Process daemon = null;
    Process secondDaemon = null;
    Process fixtureProcess = null;
    String[] stage = {"initialize"};
    Throwable[] failure = {null};
    try {
      runCli(cli, List.of("init", "--project-dir", repository.toString()), dataHome, root);
      runCli(cli, List.of("init", "--project-dir", secondRepository.toString()), secondDataHome, root);
      copyAllowedApplicationSources(workspace, repository);
      copyAllowedApplicationSources(workspace, secondRepository);

      stage[0] = "start-first-daemon";
      Path daemonOutput = logs.resolve("daemon.out");
      daemon = startDaemon(cli, repository, dataHome, daemonOutput, logs.resolve("daemon.err"));
      String ready = waitForFirstLine(daemonOutput, daemon, Duration.ofSeconds(15));
      String bootstrapValue = stringField(ready, "bootstrap_path");
      assertFalse(bootstrapValue.isBlank());
      Path bootstrap = Path.of(bootstrapValue);

      stage[0] = "start-second-daemon";
      Path secondDaemonOutput = logs.resolve("second-daemon.out");
      secondDaemon = startDaemon(
          cli, secondRepository, secondDataHome, secondDaemonOutput, logs.resolve("second-daemon.err"));
      String secondReady = waitForFirstLine(secondDaemonOutput, secondDaemon, Duration.ofSeconds(15));
      Path secondBootstrap = Path.of(stringField(secondReady, "bootstrap_path"));

      int port = freePort();
      stage[0] = "start-spring-fixture";
      fixtureProcess =
          new ProcessBuilder(
                  targetJava.toString(),
                  "-jar",
                  fixture.toString(),
                  "--server.address=127.0.0.1",
                  "--server.port=" + port,
                  "--spring.main.banner-mode=off")
              .redirectOutput(logs.resolve("fixture.out").toFile())
              .redirectError(logs.resolve("fixture.err").toFile())
              .start();
      waitForFixture(port, fixtureProcess, Duration.ofSeconds(45));

      String inspected =
          runHelper(
              helperJava,
              helper,
              List.of("inspect", "--pid", Long.toString(fixtureProcess.pid()), "--json"),
              root);
      assertTrue(inspected.contains("\"attachEligibility\":\"best_effort\""));
      assertTrue(inspected.contains("\"startTime\":"));
      assertTrue(inspected.contains("\"owner\":"));
      assertTrue(inspected.contains("\"jdkVersion\":"));
      assertFalse(inspected.contains(bootstrap.toString()));

      stage[0] = "reject-malformed-bootstrap-without-poisoning-target";
      Path malformedDirectory = Files.createDirectory(logs.resolve("bad-options"));
      setPrivateDirectory(malformedDirectory);
      Path malformedBootstrap = malformedDirectory.resolve("malformed.json");
      Files.writeString(malformedBootstrap, Files.readString(bootstrap) + " trailing-junk");
      Files.setPosixFilePermissions(malformedBootstrap, PosixFilePermissions.fromString("rw-------"));
      HelperResult malformed = runHelperResult(
          helperJava, helper, attachArguments(fixtureProcess.pid(), agent, malformedBootstrap), root);
      assertTrue(malformed.exitCode() != 0);
      assertTrue(malformed.json().contains("XTR-ATTACH"));
      assertFalse(malformed.json().contains("trailing-junk"));
      Files.deleteIfExists(malformedBootstrap);

      stage[0] = "attach-first-session";
      String attached =
          runHelper(
              helperJava,
              helper,
              attachArguments(fixtureProcess.pid(), agent, bootstrap),
              root);
      assertTrue(attached.contains("XTR-ATTACH-OK"));
      assertTrue(attached.contains("active_or_already_active"));
      assertFalse(attached.contains(bootstrap.toString()));
      assertFalse(attached.contains(BODY_CANARY));

      stage[0] = "same-session-idempotent-attach";
      String duplicate = runHelper(
          helperJava, helper, attachArguments(fixtureProcess.pid(), agent, bootstrap), root);
      assertTrue(duplicate.contains("XTR-ATTACH-OK"));

      stage[0] = "reject-different-daemon-session";
      HelperResult otherSession = runHelperResult(
          helperJava, helper, attachArguments(fixtureProcess.pid(), agent, secondBootstrap), root);
      assertTrue(otherSession.exitCode() != 0);
      assertFalse(otherSession.json().contains("XTR-ATTACH-OK"));
      assertFalse(otherSession.json().contains(secondBootstrap.toString()));

      stage[0] = "exercise-spring-request";
      HttpResponse<String> response = postOrder(port);
      assertEquals(201, response.statusCode());
      assertEquals("{\"status\":\"created\"}", response.body());

      stage[0] = "verify-first-session-recording";
      String recordingId = waitForRecording(cli, repository, dataHome, Duration.ofSeconds(20));
      String showing =
          runCli(
              cli,
              List.of("recording", "show", "--project-dir", repository.toString(), recordingId,
                  "--limit", "200"),
              dataHome,
              root);
      assertTrue(showing.contains("OrderController.create"));
      assertTrue(showing.contains("OrderService.place"));
      assertTrue(showing.contains("OrderRepository.save"));
      assertTrue(showing.contains("\"source_binding\":\"verified\""));
      assertTrue(showing.contains("\"status\":\"matched\""));
      assertTrue(showing.contains("/adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/"));
      assertTrue(showing.contains("\"startLine\":"));
      assertFalse(showing.contains(repository.toString()));
      assertFalse(showing.contains(BODY_CANARY));
      assertFalse(showing.contains(bootstrap.toString()));
      String secondListings = runCli(
          cli,
          List.of("recording", "list", "--project-dir", secondRepository.toString(), "--limit", "50"),
          secondDataHome,
          root);
      assertFalse(RECORDING_ID.matcher(secondListings).find());
      assertFalse(secondListings.contains("OrderController.create"));
    } catch (Exception | AssertionError error) {
      failure[0] = error;
      throw error;
    } finally {
      Throwable primaryFailure = failure[0];
      List<ChildCleanup> cleanupStates = new ArrayList<>();
      for (NamedProcess child : List.of(
          new NamedProcess("fixture", fixtureProcess),
          new NamedProcess("daemon", daemon),
          new NamedProcess("second-daemon", secondDaemon))) {
        Process process = child.process();
        if (process == null) continue;
        boolean wasAlive = process.isAlive();
        try {
          stop(process);
        } catch (InterruptedException | IOException error) {
          if (error instanceof InterruptedException) Thread.currentThread().interrupt();
          if (primaryFailure == null) primaryFailure = error;
          else primaryFailure.addSuppressed(error);
        } finally {
          cleanupStates.add(childCleanup(child.name(), process, wasAlive));
        }
      }
      if (primaryFailure == null) {
        deleteTree(root);
      } else {
        boolean evidenceSaved = false;
        try {
          preserveFailureEvidence(
              evidenceDirectory, root, logs, stage[0], primaryFailure, cleanupStates);
          evidenceSaved = true;
        } catch (IOException evidenceError) {
          primaryFailure.addSuppressed(
              new IOException("private failure evidence could not be persisted; fixture files were retained"));
          primaryFailure.addSuppressed(evidenceError);
        }
        if (shouldDeleteFixtureRoot(evidenceSaved, cleanupStates)) {
          try {
            deleteTree(root);
          } catch (IOException cleanupError) {
            primaryFailure.addSuppressed(cleanupError);
          }
        } else if (!allChildrenStopped(cleanupStates)) {
          primaryFailure.addSuppressed(new IOException(
              "a disposable child may still be using the fixture; its root was retained"));
        }
        if (failure[0] == null) {
          if (primaryFailure instanceof Exception exception) throw exception;
          if (primaryFailure instanceof Error error) throw error;
        }
      }
    }
  }

  @Test
  void unconfirmedOwnedChildRetainsFixtureRootAndPrivateRecoveryReceipt() throws Exception {
    Path root = Files.createTempDirectory("xtrace-java-attach-cleanup-test-");
    setPrivateDirectory(root);
    Path logs = Files.createDirectory(root.resolve("logs"));
    Path evidenceDirectory = Files.createDirectory(root.resolve("evidence"));
    setPrivateDirectory(evidenceDirectory);
    Path childOutput = logs.resolve("child.out");
    Path testClasses = Path.of(
        UnstoppableChild.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    Process child = null;
    try {
      child = new ProcessBuilder(
          Path.of(System.getProperty("java.home"), "bin", "java").toString(),
          "-cp",
          testClasses.toString(),
          UnstoppableChild.class.getName())
          .redirectErrorStream(true)
          .redirectOutput(childOutput.toFile())
          .start();
      assertEquals("READY", waitForFirstLine(childOutput, child, Duration.ofSeconds(10)));
      long pid = child.pid();
      Process ownedChild = child;
      Instant startTime = child.toHandle().info().startInstant()
          .orElseThrow(() -> new AssertionError("owned child start identity is unavailable"));

      IOException injected = assertThrows(IOException.class, () -> stop(ownedChild, true));
      assertTrue(injected.getMessage().contains("injected"));
      assertTrue(child.isAlive(), "the injected path must not signal the child");
      List<ChildCleanup> cleanup = List.of(childCleanup("fixture", child, true));
      assertFalse(allChildrenStopped(cleanup));
      assertFalse(shouldDeleteFixtureRoot(true, cleanup));

      Path bundle = preserveFailureEvidence(
          evidenceDirectory, root, logs, "injected-stop-failure", injected, cleanup);
      Map<String, Object> receipt = BoundedJson.parseObject(
          Files.readString(bundle.resolve("receipt.json")));
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> children = (List<Map<String, Object>>) receipt.get("childCleanup");
      assertEquals(1, children.size());
      assertEquals(pid, ((java.math.BigDecimal) children.get(0).get("pid")).longValue());
      assertEquals(startTime.toString(), children.get(0).get("startTime"));
      assertEquals("termination_unconfirmed", children.get(0).get("state"));
      assertTrue(Files.isDirectory(root), "the fixture root must remain for the live child");
    } finally {
      try {
        if (child != null) stop(child);
      } finally {
        if (child != null && child.isAlive()) {
          child.destroyForcibly();
          if (!child.waitFor(5, TimeUnit.SECONDS)) {
            throw new IOException("the owned cleanup-test child could not be stopped");
          }
        }
        deleteTree(root);
      }
    }
  }

  private static List<String> attachArguments(long pid, Path agent, Path bootstrap) {
    return List.of(
        "attach", "--pid", Long.toString(pid), "--agent", agent.toString(),
        "--options-file", bootstrap.toString(), "--json");
  }

  private static Process startDaemon(
      Path cli, Path repository, Path dataHome, Path stdout, Path stderr) throws IOException {
    return startDaemonProcess(cli, repository, dataHome, stdout, stderr);
  }

  private static Process startDaemonProcess(
      Path cli, Path repository, Path dataHome, Path stdout, Path stderr) throws IOException {
    ProcessBuilder builder =
        new ProcessBuilder(cli.toString(), "daemon", "--project-dir", repository.toString());
    builder.environment().put("XTRACE_DATA_HOME", dataHome.toString());
    return builder.redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
  }

  private static void copyAllowedApplicationSources(Path workspace, Path repository)
      throws IOException {
    String sourceRoot = "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/";
    for (String file : List.of("OrderController.java", "OrderService.java", "OrderRepository.java")) {
      Path source = workspace.resolve(sourceRoot).resolve(file);
      Path target = repository.resolve(sourceRoot).resolve(file);
      Files.createDirectories(target.getParent());
      Files.copy(source, target);
    }
  }

  private static void waitForFixture(int port, Process process, Duration timeout)
      throws Exception {
    long deadline = System.nanoTime() + timeout.toNanos();
    IOException lastError = null;
    while (System.nanoTime() < deadline && process.isAlive()) {
      try {
        HttpResponse<String> response = get(port, "/__fixture/count");
        if (response.statusCode() == 200) return;
      } catch (IOException error) {
        lastError = error;
      }
      Thread.sleep(100);
    }
    throw new AssertionError(
        "the disposable Spring fixture did not become ready"
            + (lastError == null ? "" : " (HTTP connection unavailable)"));
  }

  private static HttpResponse<String> postOrder(int port) throws Exception {
    String body =
        "{\"description\":\"safe attach evidence\",\"bodyCanary\":\""
            + BODY_CANARY
            + "\",\"errorCanary\":\"\"}";
    HttpRequest request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/orders"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static HttpResponse<String> get(int port, String path) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
            .timeout(Duration.ofSeconds(2))
            .GET()
            .build();
    return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static String waitForRecording(
      Path cli, Path repository, Path dataHome, Duration timeout) throws Exception {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      String listing =
          runCli(
              cli,
              List.of("recording", "list", "--project-dir", repository.toString(), "--limit", "50"),
              dataHome,
              repository.getParent());
      Matcher matcher = RECORDING_ID.matcher(listing);
      if (matcher.find()) return matcher.group(1);
      Thread.sleep(200);
    }
    throw new AssertionError("the attached request did not produce a persisted recording");
  }

  private static String runHelper(
      Path helperJava, Path helper, List<String> arguments, Path root)
      throws Exception {
    List<String> command = new java.util.ArrayList<>();
    command.add(helperJava.toString());
    command.add("-jar");
    command.add(helper.toString());
    command.addAll(arguments);
    return run(command, root, null);
  }

  private static HelperResult runHelperResult(
      Path helperJava, Path helper, List<String> arguments, Path root) throws Exception {
    List<String> command = new java.util.ArrayList<>();
    command.add(helperJava.toString());
    command.add("-jar");
    command.add(helper.toString());
    command.addAll(arguments);
    return runResult(command, root, null);
  }

  private static String runCli(Path cli, List<String> arguments, Path dataHome, Path root)
      throws Exception {
    List<String> command = new java.util.ArrayList<>();
    command.add(cli.toString());
    command.addAll(arguments);
    return run(command, root, dataHome);
  }

  private static String run(List<String> command, Path root, Path dataHome) throws Exception {
    HelperResult result = runResult(command, root, dataHome);
    if (result.exitCode() != 0) {
      throw new AssertionError("a local X-trace command failed with exit code " + result.exitCode());
    }
    return result.json();
  }

  private static HelperResult runResult(List<String> command, Path root, Path dataHome)
      throws Exception {
    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    if (dataHome != null) builder.environment().put("XTRACE_DATA_HOME", dataHome.toString());
    Path captured = root.resolve("command-output-" + java.util.UUID.randomUUID());
    Process process = builder.redirectOutput(captured.toFile()).start();
    try {
      if (!process.waitFor(20, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        process.waitFor(5, TimeUnit.SECONDS);
        storeCommandTail(captured, root);
        throw new AssertionError("a bounded local X-trace command timed out");
      }
      long size = Files.size(captured);
      if (size > 256 * 1024) {
        storeCommandTail(captured, root);
        throw new AssertionError("a local X-trace command exceeded the output bound");
      }
      String text = Files.readString(captured, StandardCharsets.UTF_8);
      if (process.exitValue() != 0) {
        Files.copy(
            captured,
            root.resolve("failure-command.out"),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      }
      return new HelperResult(text, process.exitValue());
    } finally {
      Files.deleteIfExists(captured);
    }
  }

  private static Path preserveFailureEvidence(
      Path evidenceDirectory,
      Path root,
      Path logs,
      String stage,
      Throwable failure,
      List<ChildCleanup> cleanupStates)
      throws IOException {
    if (!Files.isDirectory(evidenceDirectory, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(evidenceDirectory)
        || ((((Number) Files.getAttribute(
            evidenceDirectory, "unix:mode", java.nio.file.LinkOption.NOFOLLOW_LINKS)).intValue()) & 0077) != 0
        || !Files.getOwner(evidenceDirectory, java.nio.file.LinkOption.NOFOLLOW_LINKS).getName()
            .equals(ProcessHandle.current().info().user().orElse(""))) {
      throw new IOException("the failure evidence directory is not owner-private");
    }
    Path bundle = Files.createDirectory(
        evidenceDirectory.resolve("java-attach-failure-" + UUID.randomUUID()),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    for (String name : List.of(
        "daemon.out", "daemon.err", "second-daemon.out", "second-daemon.err",
        "fixture.out", "fixture.err", "failure-command.out")) {
      Path source = name.startsWith("daemon") || name.startsWith("second-daemon") || name.startsWith("fixture")
          ? logs.resolve(name)
          : root.resolve(name);
      if (Files.isRegularFile(source, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
        String text = readTailText(source);
        writePrivateEvidence(bundle.resolve(name), sanitize(text, root));
      }
    }
    Map<String, Object> receiptValues = new LinkedHashMap<>();
    receiptValues.put("stage", stage);
    receiptValues.put("failureType", failure.getClass().getSimpleName());
    receiptValues.put("jdk", System.getProperty("java.version"));
    List<Map<String, Object>> childValues = new ArrayList<>();
    for (ChildCleanup child : cleanupStates) {
      Map<String, Object> value = new LinkedHashMap<>();
      value.put("name", child.name());
      value.put("ownedByHarness", true);
      value.put("pid", child.pid());
      value.put("startTime", child.startTime() == null ? null : child.startTime().toString());
      value.put("state", child.state());
      childValues.add(value);
    }
    receiptValues.put("childCleanup", childValues);
    String receipt = Json.encode(receiptValues) + "\n";
    writePrivateEvidence(bundle.resolve("receipt.json"), receipt);
    if (!Files.isDirectory(bundle, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(bundle)
        || !Files.isRegularFile(bundle.resolve("receipt.json"), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("private failure evidence could not be verified");
    }
    forceDirectory(bundle);
    forceDirectory(evidenceDirectory);
    return bundle;
  }

  private static ChildCleanup childCleanup(String name, Process process, boolean wasAlive) {
    boolean alive;
    try {
      alive = process.isAlive();
    } catch (RuntimeException unavailable) {
      alive = true;
    }
    long pid;
    try {
      pid = process.pid();
    } catch (RuntimeException unavailable) {
      pid = -1;
    }
    Instant startTime = null;
    if (pid > 0) {
      try {
        startTime = process.toHandle().info().startInstant().orElse(null);
      } catch (RuntimeException ignored) {
        // Keep the PID and explicitly report an unconfirmed state when identity is unavailable.
      }
    }
    return new ChildCleanup(
        name, pid, startTime, alive ? "termination_unconfirmed" : wasAlive ? "stopped" : "already_exited");
  }

  private static boolean allChildrenStopped(List<ChildCleanup> children) {
    return children.stream().allMatch(child ->
        child.state().equals("stopped") || child.state().equals("already_exited"));
  }

  private static boolean shouldDeleteFixtureRoot(
      boolean evidenceSaved, List<ChildCleanup> children) {
    return evidenceSaved && allChildrenStopped(children);
  }

  private record NamedProcess(String name, Process process) {}

  private record ChildCleanup(String name, long pid, Instant startTime, String state) {}

  private static void writePrivateEvidence(Path path, String text) throws IOException {
    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > 64 * 1024) {
      java.util.Arrays.fill(bytes, (byte) 0);
      throw new IOException("private failure evidence exceeded its file bound");
    }
    try {
      Files.createFile(
          path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      try (var channel = java.nio.channels.FileChannel.open(
          path,
          java.util.Set.of(
              java.nio.file.StandardOpenOption.WRITE,
              java.nio.file.LinkOption.NOFOLLOW_LINKS))) {
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) channel.write(buffer);
        channel.force(true);
      }
    } finally {
      java.util.Arrays.fill(bytes, (byte) 0);
    }
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    if (!Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        || Files.size(path) > 64 * 1024) {
      throw new IOException("private failure evidence file could not be verified");
    }
  }

  private static void forceDirectory(Path directory) throws IOException {
    try (var channel = java.nio.channels.FileChannel.open(
        directory, java.nio.file.StandardOpenOption.READ)) {
      channel.force(true);
    }
  }

  static String sanitize(String text, Path root) {
    String[] lines = text.split("\\R", -1);
    StringBuilder safe = new StringBuilder(Math.min(text.length(), 64 * 1024));
    for (String line : lines) {
      String lower = line.toLowerCase(java.util.Locale.ROOT);
      if (lower.contains("secret") || lower.contains("authorization") || lower.contains("token")
          || lower.contains("bootstrap_path")) {
        safe.append("[redacted sensitive log line]\n");
        continue;
      }
      safe.append(line.replace(root.toString(), "[private-fixture-root]")
              .replace(BODY_CANARY, "[request-body-redacted]")
              .replace("ATTACH_BODY_CANARY_2A7", "[request-body-redacted]")
              .replaceAll("(?<![A-Za-z0-9])/(?:Users|Volumes)/[^\\s\\\"']+", "[private-path]"))
          .append('\n');
    }
    return safe.toString();
  }

  private static void storeCommandTail(Path captured, Path root) throws IOException {
    if (!Files.isRegularFile(captured)) return;
    Files.writeString(root.resolve("failure-command.out"), readTailText(captured));
  }

  private static String readTailText(Path path) throws IOException {
    try (var channel = Files.newByteChannel(
        path, java.util.Set.of(java.nio.file.StandardOpenOption.READ, java.nio.file.LinkOption.NOFOLLOW_LINKS))) {
      long size = channel.size();
      int length = (int) Math.min(size, 64 * 1024);
      channel.position(Math.max(0, size - length));
      java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(length);
      while (buffer.hasRemaining() && channel.read(buffer) != -1) {}
      return StandardCharsets.UTF_8.decode(
          java.nio.ByteBuffer.wrap(buffer.array(), 0, buffer.position())).toString();
    }
  }

  private static void setPrivateDirectory(Path directory) throws IOException {
    if (Files.getFileStore(directory).supportsFileAttributeView(PosixFileAttributeView.class)) {
      Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
    }
  }

  private static String waitForFirstLine(Path output, Process process, Duration timeout)
      throws Exception {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline && process.isAlive()) {
      if (Files.isRegularFile(output) && Files.size(output) > 0) {
        String text = Files.readString(output, StandardCharsets.UTF_8);
        int newline = text.indexOf('\n');
        if (newline >= 0) return text.substring(0, newline);
      }
      Thread.sleep(50);
    }
    throw new AssertionError("the disposable daemon did not report readiness");
  }

  private static String stringField(String json, String field) {
    Pattern pattern = Pattern.compile(STRING_FIELD.pattern().formatted(Pattern.quote(field)));
    Matcher matcher = pattern.matcher(json);
    if (!matcher.find()) throw new AssertionError("required JSON field is unavailable");
    return matcher.group(1).replace("\\\\", "\\").replace("\\\"", "\"");
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static Path requiredPath(String property) {
    String value = System.getProperty(property);
    if (value == null || value.isBlank()) {
      throw new AssertionError("missing acceptance input " + property);
    }
    return Path.of(value).toAbsolutePath().normalize();
  }

  private static void stop(Process process) throws InterruptedException, IOException {
    stop(process, false);
  }

  private static void stop(Process process, boolean injectFailureBeforeSignal)
      throws InterruptedException, IOException {
    if (process == null || !process.isAlive()) return;
    if (injectFailureBeforeSignal) throw new IOException("injected child-stop failure");
    process.destroy();
    try {
      if (!process.waitFor(5, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
          throw new IOException("disposable child termination could not be confirmed");
        }
      }
    } catch (InterruptedException interrupted) {
      process.destroyForcibly();
      try {
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
          interrupted.addSuppressed(new IOException("disposable child termination could not be confirmed"));
        }
      } catch (InterruptedException cleanupInterrupted) {
        interrupted.addSuppressed(cleanupInterrupted);
      }
      Thread.currentThread().interrupt();
      throw interrupted;
    }
  }

  private static void deleteTree(Path root) throws IOException {
    if (root == null || !Files.exists(root)) return;
    try (var paths = Files.walk(root)) {
      for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }

  private record HelperResult(String json, int exitCode) {}
}
