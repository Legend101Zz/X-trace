package io.xtrace.attach;

import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Safe process facts used to bind an attach attempt to one PID incarnation. */
final class ProcessIdentity {
  private static final Pattern JDK_MAJOR = Pattern.compile("^(?:1\\.)?([0-9]{1,3})(?:[._+-].*)?$");

  private final long pid;
  private final Instant startTime;
  private final String owner;
  private final String executableName;

  private ProcessIdentity(long pid, Instant startTime, String owner, String executableName) {
    this.pid = pid;
    this.startTime = startTime;
    this.owner = owner;
    this.executableName = executableName;
  }

  static ProcessIdentity read(long pid) throws AttachCommands.Failure {
    return read(pid, "inspect");
  }

  static ProcessIdentity read(long pid, String command) throws AttachCommands.Failure {
    ProcessHandle handle =
        ProcessHandle.of(pid)
            .orElseThrow(
                () ->
                    new AttachCommands.Failure(
                        command,
                        "XTR-ATTACH-PROCESS-NOT-FOUND",
                        5,
                        "The selected process no longer exists.",
                        "Refresh the process list and select a currently running JVM."));
    ProcessHandle.Info info = handle.info();
    Instant start = info.startInstant().orElse(null);
    String owner = info.user().orElse(null);
    String executable = info.command().orElse(null);
    String name = null;
    if (executable != null) {
      try {
        Path fileName = Path.of(executable).getFileName();
        if (fileName != null) name = fileName.toString();
      } catch (RuntimeException ignored) {
        name = null;
      }
    }
    return new ProcessIdentity(pid, start, owner, name);
  }

  void requireCurrentOwner(String command) throws AttachCommands.Failure {
    String current = ProcessHandle.current().info().user().orElse(null);
    if (owner == null || current == null) {
      throw new AttachCommands.Failure(
          command,
          "XTR-ATTACH-IDENTITY-UNAVAILABLE",
          5,
          "The helper could not verify the JVM owner.",
          "Run X-trace and the application under the same operating-system user, or relaunch through X-trace.");
    }
    if (!owner.equals(current)) {
      throw new AttachCommands.Failure(
          command,
          "XTR-ATTACH-OWNER-MISMATCH",
          4,
          "The selected JVM belongs to a different operating-system user.",
          "Run the helper as the JVM owner or relaunch the application through X-trace.");
    }
    if (startTime == null) {
      throw new AttachCommands.Failure(
          command,
          "XTR-ATTACH-IDENTITY-UNAVAILABLE",
          5,
          "The operating system did not provide a stable process start time.",
          "Refresh the process list; if start-time identity remains unavailable, relaunch through X-trace.");
    }
  }

  void requireUnchanged(ProcessIdentity current, String command) throws AttachCommands.Failure {
    if (current.pid != pid
        || startTime == null
        || current.startTime == null
        || !startTime.equals(current.startTime)
        || owner == null
        || !owner.equals(current.owner)) {
      throw new AttachCommands.Failure(
          command,
          "XTR-ATTACH-PROCESS-CHANGED",
          5,
          "The selected PID or its owner changed during the attach operation.",
          "Refresh the process list and inspect the current JVM before attaching again.");
    }
  }

  boolean javaExecutable() {
    return "java".equals(executableName)
        || "javaw".equals(executableName)
        || "java.exe".equalsIgnoreCase(executableName == null ? "" : executableName);
  }

  boolean executableKnown() {
    return executableName != null;
  }

  Instant startTime() {
    return startTime;
  }

  long pid() {
    return pid;
  }

  String owner() {
    return owner;
  }

  Map<String, Object> toJson(Properties properties, boolean attachApiProbed, String providerType) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("pid", pid);
    values.put("startTime", startTime == null ? null : startTime.toString());
    values.put("commandSummary", javaExecutable() ? "java" : safeExecutableSummary());
    values.put("owner", safeOwner(owner));
    values.put("jdkVersion", properties == null ? null : jdkMajor(properties));
    values.put("jdkVendor", properties == null ? null : jdkVendor(properties));
    values.put("vmKind", properties == null ? null : vmKind(properties));
    values.put("localAttachApiAvailable", ModuleLayer.boot().findModule("jdk.attach").isPresent());
    values.put("attachProvider", safeProvider(providerType));
    values.put("attachEligibility", attachApiProbed ? "best_effort" : "unverified");
    return values;
  }

  private String safeExecutableSummary() {
    if (executableName == null || !executableName.matches("[A-Za-z0-9_.+-]{1,64}")) {
      return "process";
    }
    return executableName;
  }

  private static String safeOwner(String value) {
    if (value == null || !value.matches("[A-Za-z0-9_.@-]{1,128}")) return "unknown";
    return value;
  }

  private static String safeProvider(String value) {
    if (value == null || !value.matches("[A-Za-z0-9_.-]{1,64}")) return "unknown";
    return value;
  }

  private static String jdkMajor(Properties properties) {
    String version = properties.getProperty("java.specification.version", "");
    Matcher matcher = JDK_MAJOR.matcher(version);
    return matcher.matches() ? matcher.group(1) : "unknown";
  }

  private static String jdkVendor(Properties properties) {
    String vendor = properties.getProperty("java.vendor", "").toLowerCase(java.util.Locale.ROOT);
    if (vendor.contains("oracle")) return "oracle";
    if (vendor.contains("adoptium") || vendor.contains("eclipse")) return "eclipse_adoptium";
    if (vendor.contains("amazon") || vendor.contains("corretto")) return "amazon";
    if (vendor.contains("microsoft")) return "microsoft";
    if (vendor.contains("azul")) return "azul";
    if (vendor.contains("bellsoft")) return "bellsoft";
    if (vendor.contains("openjdk")) return "openjdk";
    return "other";
  }

  private static String vmKind(Properties properties) {
    String vm = properties.getProperty("java.vm.name", "").toLowerCase(java.util.Locale.ROOT);
    if (vm.contains("hotspot") || vm.contains("openjdk")) return "hotspot";
    if (vm.contains("openj9")) return "openj9";
    if (vm.contains("graal")) return "graalvm";
    return "unknown";
  }
}
