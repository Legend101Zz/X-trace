package io.xtrace.attach;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
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
      return acceptWorkerResult(command, pid, before, result);
    } catch (WorkerCleanupException error) {
      return workerCleanupFailure(command, pid, before, error);
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

  static Result acceptWorkerResult(
      String command, long pid, ProcessIdentity before, Result result) {
    if (result.reliable()) return result;
    return command.equals("attach")
        ? uncertainFailure(command, pid, before)
        : failure(command, "XTR-ATTACH-HELPER-FAILED", 7,
            "The bounded JVM helper returned no valid result.",
            "Retry once; if the helper remains unavailable, relaunch the application through X-trace.");
  }

  static Result workerCleanupFailure(
      String command, long pid, ProcessIdentity before, WorkerCleanupException error) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("schemaVersion", 1);
    values.put("ok", false);
    values.put("command", command);
    values.put("code", "XTR-ATTACH-WORKER-UNCONFIRMED");
    values.put("message", "The helper could not confirm that its owned worker stopped.");
    values.put("remediation", "Inspect the helper process and target before retrying; relaunch the application through X-trace if attach state is uncertain.");
    values.put("helperWorkerState", "termination_unconfirmed");
    values.put("helperWorkerPid", error.workerPid());
    values.put("helperWorkerFailureKind", error.failureKind());
    if (error.workerStartTime() != null) {
      values.put("helperWorkerStartTime", error.workerStartTime().toEpochMilli());
    }
    if (command.equals("attach")) {
      values.put("targetAgentState", "unknown_after_helper_cleanup_failure");
      values.put("targetIdentityStatus", sameProcess(pid, before) ? "same" : "changed_or_unavailable");
    }
    return new Result(Json.encode(values), 7, true);
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
    String privateTemp = System.getProperty("java.io.tmpdir");
    if (privateTemp == null || privateTemp.isBlank() || !Path.of(privateTemp).isAbsolute()) {
      throw new IOException("the admitted helper temporary directory is unavailable");
    }
    var command = new java.util.ArrayList<String>();
    command.add(javaBinary);
    command.add("--add-modules=jdk.attach");
    command.add("-Djava.io.tmpdir=" + privateTemp);
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
    Throwable primaryFailure = null;
    try {
      if (!worker.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        throw new TimeoutException(worker.pid());
      }
      byte[] bytes;
      try {
        bytes = output.get(2, TimeUnit.SECONDS);
      } catch (java.util.concurrent.TimeoutException error) {
        throw new TimeoutException(worker.pid());
      }
      String json;
      try {
        json = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
            .strip();
      } catch (CharacterCodingException error) {
        return new Result("", 7, false);
      } finally {
        java.util.Arrays.fill(bytes, (byte) 0);
      }
      if (json.isEmpty() || json.length() > MAX_OUTPUT_BYTES || json.indexOf('\n') >= 0) {
        return new Result("", 7, false);
      }
      int exitCode = worker.exitValue();
      return new Result(
          json,
          exitCode,
          BoundedJson.isWorkerResponse(json, command(arguments), exitCode));
    } catch (InterruptedException | ExecutionException
        | TimeoutException | RuntimeException | Error error) {
      primaryFailure = error;
      throw error;
    } finally {
      ensureWorkerStopped(worker, primaryFailure, Duration.ofSeconds(5));
    }
  }

  static void ensureWorkerStopped(Process worker, Throwable primary, Duration waitBound)
      throws WorkerCleanupException {
    if (!worker.isAlive()) return;
    long pid = worker.pid();
    ProcessIdentity identity = null;
    try {
      identity = ProcessIdentity.read(pid, "attach");
    } catch (AttachCommands.Failure ignored) {
      // Keep PID as the minimum recovery fact when start identity is unavailable.
    }
    Throwable cleanupFailure = null;
    try {
      worker.destroyForcibly();
      if (worker.waitFor(waitBound.toMillis(), TimeUnit.MILLISECONDS) && !worker.isAlive()) return;
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      cleanupFailure = error;
    } catch (RuntimeException error) {
      cleanupFailure = error;
    }
    if (!worker.isAlive()) return;
    WorkerCleanupException failure = new WorkerCleanupException(
        pid,
        identity == null ? null : identity.startTime(),
        failureKind(primary));
    if (cleanupFailure != null) failure.addSuppressed(cleanupFailure);
    if (primary != null) failure.addSuppressed(primary);
    if (primary instanceof InterruptedException) Thread.currentThread().interrupt();
    throw failure;
  }

  private static String failureKind(Throwable failure) {
    if (failure instanceof TimeoutException) return "timeout";
    if (failure instanceof InterruptedException) return "interrupted";
    if (failure instanceof ExecutionException) return "worker_output";
    if (failure instanceof IOException) return "helper_io";
    if (failure instanceof RuntimeException || failure instanceof Error) return "helper_runtime";
    return "unknown";
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

  static final class WorkerCleanupException extends IOException {
    private static final long serialVersionUID = 1L;

    private final long workerPid;
    private final java.time.Instant workerStartTime;
    private final String failureKind;

    WorkerCleanupException(long workerPid, java.time.Instant workerStartTime, String failureKind) {
      super("the bounded helper worker termination could not be confirmed");
      this.workerPid = workerPid;
      this.workerStartTime = workerStartTime;
      this.failureKind = failureKind;
    }

    long workerPid() {
      return workerPid;
    }

    java.time.Instant workerStartTime() {
      return workerStartTime;
    }

    String failureKind() {
      return failureKind;
    }
  }

  static final class TimeoutException extends Exception {
    private static final long serialVersionUID = 1L;

    private final long workerPid;

    private TimeoutException(long workerPid) {
      this.workerPid = workerPid;
    }

    long workerPid() {
      return workerPid;
    }
  }
}
