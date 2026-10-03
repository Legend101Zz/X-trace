package io.xtrace.attach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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

    Path root = Files.createTempDirectory("xtrace-java-attach-");
    Path repository = Files.createDirectory(root.resolve("repository"));
    Path dataHome = Files.createDirectory(root.resolve("data"));
    Path logs = Files.createDirectory(root.resolve("logs"));
    Process daemon = null;
    Process fixtureProcess = null;
    try {
      runCli(cli, List.of("init", "--project-dir", repository.toString()), dataHome, root);
      copyAllowedApplicationSources(workspace, repository);

      Path daemonOutput = logs.resolve("daemon.out");
      daemon = startDaemon(cli, repository, dataHome, daemonOutput, logs.resolve("daemon.err"));
      String ready = waitForFirstLine(daemonOutput, daemon, Duration.ofSeconds(15));
      String bootstrapValue = stringField(ready, "bootstrap_path");
      assertFalse(bootstrapValue.isBlank());
      Path bootstrap = Path.of(bootstrapValue);

      int port = freePort();
      fixtureProcess =
          new ProcessBuilder(
                  targetJava.toString(),
                  "-jar",
                  fixture.toString(),
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

      String attached =
          runHelper(
              helperJava,
              helper,
              List.of(
                  "attach",
                  "--pid",
                  Long.toString(fixtureProcess.pid()),
                  "--agent",
                  agent.toString(),
                  "--options-file",
                  bootstrap.toString(),
                  "--json"),
              root);
      assertTrue(attached.contains("XTR-ATTACH-OK"));
      assertTrue(attached.contains("active_or_already_active"));
      assertFalse(attached.contains(bootstrap.toString()));
      assertFalse(attached.contains(BODY_CANARY));

      HttpResponse<String> response = postOrder(port);
      assertEquals(201, response.statusCode());
      assertEquals("{\"status\":\"created\"}", response.body());

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
    } finally {
      stop(fixtureProcess);
      stop(daemon);
      deleteTree(root);
    }
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

  private static String runCli(Path cli, List<String> arguments, Path dataHome, Path root)
      throws Exception {
    List<String> command = new java.util.ArrayList<>();
    command.add(cli.toString());
    command.addAll(arguments);
    return run(command, root, dataHome);
  }

  private static String run(List<String> command, Path root, Path dataHome) throws Exception {
    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    if (dataHome != null) builder.environment().put("XTRACE_DATA_HOME", dataHome.toString());
    Path captured = root.resolve("command-output-" + java.util.UUID.randomUUID());
    Process process = builder.redirectOutput(captured.toFile()).start();
    try {
      if (!process.waitFor(20, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        throw new AssertionError("a bounded local X-trace command timed out");
      }
      long size = Files.size(captured);
      if (size > 256 * 1024) {
        throw new AssertionError("a local X-trace command exceeded the output bound");
      }
      String text = Files.readString(captured, StandardCharsets.UTF_8);
      if (process.exitValue() != 0) {
        throw new AssertionError(
            "a local X-trace command failed with exit code " + process.exitValue());
      }
      return text;
    } finally {
      Files.deleteIfExists(captured);
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

  private static void stop(Process process) throws InterruptedException {
    if (process == null || !process.isAlive()) return;
    process.destroy();
    if (!process.waitFor(5, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      process.waitFor(5, TimeUnit.SECONDS);
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
}
