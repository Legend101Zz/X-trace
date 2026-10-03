package io.xtrace.attach;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

/** Runs all potentially blocking Attach API work in a killable helper subprocess. */
final class HelperSupervisor {
  private static final Duration ATTACH_TIMEOUT = Duration.ofSeconds(30);
  private static final int MAX_OUTPUT_BYTES = 256 * 1024;

  private HelperSupervisor() {}

  static Result run(String[] arguments) {
    String command = command(arguments);
    long pid = command.equals("attach") ? optionPid(arguments) : -1;
    ProcessIdentity before = null;
    if (pid > 0) {
      try {
        before = ProcessIdentity.read(pid, command);
      } catch (AttachCommands.Failure ignored) {
        before = null;
      }
    }
    try {
      Result result = runWorker(WorkerMain.class.getName(), arguments, ATTACH_TIMEOUT);
      if (result.reliable()) return result;
      return command.equals("attach")
          ? uncertainFailure(command, pid, before)
          : failure(command, "XTR-ATTACH-HELPER-FAILED", 7,
              "The bounded JVM helper returned no valid result.",
              "Retry once; if the helper remains unavailable, relaunch the application through X-trace.");
    } catch (TimeoutException error) {
      return timeout(command, pid, before);
    } catch (IOException | InterruptedException | ExecutionException | URISyntaxException error) {
      if (error instanceof InterruptedException) Thread.currentThread().interrupt();
      if (command.equals("attach")) {
        return uncertainFailure(command, pid, before);
      }
      return failure(command, "XTR-ATTACH-HELPER-FAILED", 7,
          "The bounded JVM helper could not complete safely.",
          "Retry once; if the helper remains unavailable, relaunch the application through X-trace.");
    }
  }

  static Result runWorker(
      String mainClass,
      String[] arguments,
      Duration timeout)
      throws IOException, InterruptedException, ExecutionException, URISyntaxException,
          TimeoutException {
    String classPath = Path.of(
        Main.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    return runWorker(mainClass, arguments, timeout, classPath);
  }

  static Result runWorker(
      String mainClass,
      String[] arguments,
      Duration timeout,
      String classPath)
      throws IOException, InterruptedException, ExecutionException, URISyntaxException,
          TimeoutException {
    String javaBinary = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    var command = new java.util.ArrayList<String>();
    command.add(javaBinary);
    command.add("--add-modules=jdk.attach");
    command.add("-cp");
    command.add(classPath);
    command.add(mainClass);
    if (arguments != null) command.addAll(java.util.Arrays.asList(arguments));
    ProcessBuilder builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
    builder.environment().remove("JAVA_TOOL_OPTIONS");
    builder.environment().remove("JDK_JAVA_OPTIONS");
    builder.environment().remove("_JAVA_OPTIONS");
    Process worker = builder.start();
    FutureTask<byte[]> output = new FutureTask<>(() -> readBounded(worker.getInputStream()));
    Thread reader = new Thread(output, "xtrace-attach-helper-output");
    reader.setDaemon(true);
    reader.start();
    try {
      if (!worker.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        long workerPid = worker.pid();
        worker.destroyForcibly();
        worker.waitFor(5, TimeUnit.SECONDS);
        reader.interrupt();
        if (worker.isAlive()) throw new IOException("the bounded helper worker did not stop");
        throw new TimeoutException(workerPid);
      }
      byte[] bytes;
      try {
        bytes = output.get(2, TimeUnit.SECONDS);
      } catch (java.util.concurrent.TimeoutException error) {
        long workerPid = worker.pid();
        worker.destroyForcibly();
        worker.waitFor(5, TimeUnit.SECONDS);
        if (worker.isAlive()) throw new IOException("the bounded helper worker did not stop");
        throw new TimeoutException(workerPid);
      }
    String json = new String(bytes, StandardCharsets.UTF_8).strip();
    java.util.Arrays.fill(bytes, (byte) 0);
    if (json.isEmpty() || json.length() > MAX_OUTPUT_BYTES || json.indexOf('\n') >= 0) {
      return new Result("", 7, false);
    }
    return new Result(json, worker.exitValue(), true);
    } finally {
      if (worker.isAlive()) {
        worker.destroyForcibly();
        worker.waitFor(5, TimeUnit.SECONDS);
      }
    }
  }

  private static byte[] readBounded(InputStream input) throws IOException {
    try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) != -1) {
        if (output.size() > MAX_OUTPUT_BYTES - count) {
          throw new IOException("helper output exceeded its limit");
        }
        output.write(buffer, 0, count);
      }
      java.util.Arrays.fill(buffer, (byte) 0);
      return output.toByteArray();
    }
  }

  static Result timeout(String command, long pid, ProcessIdentity before) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("schemaVersion", 1);
    values.put("ok", false);
    values.put("command", command);
    values.put("code", "XTR-ATTACH-TIMEOUT");
    values.put("message", "The bounded JVM operation exceeded its time limit.");
    values.put("remediation", "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.");
    if (command.equals("attach")) {
      values.put("targetAgentState", "unknown_after_timeout");
      values.put("targetIdentityStatus", sameProcess(pid, before) ? "same" : "changed_or_unavailable");
    }
    return new Result(Json.encode(values), 5, true);
  }

  private static Result uncertainFailure(String command, long pid, ProcessIdentity before) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("schemaVersion", 1);
    values.put("ok", false);
    values.put("command", command);
    values.put("code", "XTR-ATTACH-HELPER-FAILED");
    values.put("message", "The helper ended without a reliable attach result.");
    values.put("remediation", "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.");
    values.put("targetAgentState", "unknown_after_helper_failure");
    values.put("targetIdentityStatus", sameProcess(pid, before) ? "same" : "changed_or_unavailable");
    return new Result(Json.encode(values), 7, true);
  }

  private static boolean sameProcess(long pid, ProcessIdentity before) {
    if (pid <= 0 || before == null) return false;
    try {
      before.requireUnchanged(ProcessIdentity.read(pid, "attach"), "attach");
      return true;
    } catch (AttachCommands.Failure ignored) {
      return false;
    }
  }

  private static Result failure(
      String command, String code, int exitCode, String message, String remediation) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("schemaVersion", 1);
    values.put("ok", false);
    values.put("command", command);
    values.put("code", code);
    values.put("message", message);
    values.put("remediation", remediation);
    return new Result(Json.encode(values), exitCode, true);
  }

  private static String command(String[] arguments) {
    if (arguments == null || arguments.length == 0) return "unknown";
    return switch (arguments[0]) {
      case "list", "inspect", "attach" -> arguments[0];
      default -> "unknown";
    };
  }

  private static long optionPid(String[] arguments) {
    if (arguments == null) return -1;
    for (int index = 1; index + 1 < arguments.length; index++) {
      if ("--pid".equals(arguments[index])) {
        try {
          return Long.parseLong(arguments[index + 1]);
        } catch (NumberFormatException ignored) {
          return -1;
        }
      }
    }
    return -1;
  }

  record Result(String json, int exitCode, boolean reliable) {
    Result(String json, int exitCode) {
      this(json, exitCode, true);
    }
  }

  static final class TimeoutException extends Exception {
    private final long workerPid;

    private TimeoutException(long workerPid) {
      this.workerPid = workerPid;
    }

    long workerPid() {
      return workerPid;
    }
  }
}
