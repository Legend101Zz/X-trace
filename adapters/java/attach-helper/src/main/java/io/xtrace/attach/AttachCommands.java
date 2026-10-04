package io.xtrace.attach;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** Implements the bounded command contract without exposing target arguments or environment. */
final class AttachCommands {
  private AttachCommands() {}

  static Result execute(String[] arguments) {
    try {
      return executeChecked(arguments);
    } catch (Failure failure) {
      return Result.failure(
          failure.command,
          failure.code,
          failure.exitCode,
          failure.getMessage(),
          failure.remediation,
          failure.data);
    } catch (SecurityException error) {
      return Result.failure(
          commandName(arguments),
          "XTR-ATTACH-PERMISSION",
          4,
          "The current user is not permitted to inspect or attach to this JVM.",
          "Run X-trace as the JVM owner, or relaunch the application through X-trace.");
    } catch (LinkageError error) {
      return Result.failure(
          commandName(arguments),
          "XTR-ATTACH-JDK-UNAVAILABLE",
          4,
          "This Java runtime does not provide the Attach API required by the helper.",
          "Use a full supported JDK and relaunch the application with X-trace.");
    } catch (IOException error) {
      return Result.failure(
          commandName(arguments),
          "XTR-ATTACH-UNAVAILABLE",
          5,
          "The requested JVM operation is unavailable.",
          "Check that the target is a compatible JVM in the same user and process namespace, or relaunch it with X-trace.");
    } catch (RuntimeException error) {
      return Result.failure(
          commandName(arguments),
          "XTR-ATTACH-FAILED",
          7,
          "The JVM attach operation failed safely.",
          "Relaunch the application through X-trace and retain the helper result code for diagnosis.");
    }
  }

  private static Result executeChecked(String[] arguments) throws IOException, Failure {
    if (arguments == null || arguments.length == 0) throw usage("unknown", "a command is required");
    return switch (arguments[0]) {
      case "list" -> list(arguments);
      case "inspect" -> inspect(arguments);
      case "attach" -> attach(arguments);
      default -> throw usage("unknown", "the requested command is not supported");
    };
  }

  private static final int MAX_LISTED_PROCESSES = 256;

  private static Result list(String[] arguments) throws IOException, Failure {
    if (arguments.length != 2 || !"--json".equals(arguments[1])) {
      throw usage("list", "list requires --json and accepts no other arguments");
    }
    List<Map<String, Object>> processes = new ArrayList<>();
    boolean truncated = false;
    int examined = 0;
    for (VirtualMachineDescriptor descriptor : VirtualMachine.list()) {
      if (processes.size() == MAX_LISTED_PROCESSES || ++examined > 4096) {
        truncated = true;
        break;
      }
      long pid = parseDescriptorPid(descriptor.id());
      try {
        ProcessIdentity identity = ProcessIdentity.read(pid);
        processes.add(identity.toJson(null, false, descriptor.provider().type()));
      } catch (Failure ignored) {
        // A process may exit while the Attach provider enumerates it; omit that stale row.
      }
    }
    processes.sort(Comparator.comparingLong(value -> ((Number) value.get("pid")).longValue()));
    return Result.success("list", Map.of("processes", processes, "truncated", truncated));
  }

  private static Result inspect(String[] arguments) throws IOException, Failure {
    Map<String, String> options = parseOptions(arguments, 1, SetOf.PID);
    long pid = parsePid(options.get("--pid"), "inspect");
    ProcessIdentity before = ProcessIdentity.read(pid);
    before.requireCurrentOwner("inspect");
    VirtualMachineDescriptor descriptor = findDescriptor(pid);
    if (descriptor == null) throw unavailableTarget(before, "inspect");

    Properties properties;
    try (AttachedVm attached = AttachedVm.connect(descriptor)) {
      before.requireUnchanged(ProcessIdentity.read(pid), "inspect");
      properties = attached.machine().getSystemProperties();
    } catch (AttachNotSupportedException error) {
      throw mapAttachFailure("inspect", error);
    }
    ProcessIdentity after = ProcessIdentity.read(pid);
    before.requireUnchanged(after, "inspect");
    return Result.success(
        "inspect",
        Map.of(
            "process",
            before.toJson(properties, true, descriptor.provider().type()),
            "containerHintStatus",
            "not_probed"));
  }

  private static Result attach(String[] arguments) throws IOException, Failure {
    Map<String, String> options = parseOptions(arguments, 1, SetOf.ATTACH);
    long pid = parsePid(options.get("--pid"), "attach");
    Path bootstrap = PrivateBootstrap.validate(Path.of(options.get("--options-file")));
    ProcessIdentity before = ProcessIdentity.read(pid, "attach");
    before.requireCurrentOwner("attach");
    VirtualMachineDescriptor descriptor = findDescriptor(pid);
    if (descriptor == null) throw unavailableTarget(before, "attach");
    AgentSnapshot snapshot = AgentArtifact.snapshot(
        Path.of(options.get("--agent")), pid, before.startTime());

    Properties properties;
    boolean loadAttempted = false;
    try (AttachedVm attached = AttachedVm.connect(descriptor)) {
      properties = attached.machine().getSystemProperties();
      // Keep this identity check adjacent to loadAgent: PIDs can be reused while artifacts are
      // validated or while the Attach handshake runs.
      try {
        before.requireUnchanged(ProcessIdentity.read(pid, "attach"), "attach");
      } catch (Failure changed) {
        // Identity is no longer reliable. Keep the immutable runtime files until a later
        // helper invocation proves this PID incarnation exited or was replaced.
        throw changed;
      }
      loadAttempted = true;
      attached.machine().loadAgent(snapshot.agentJar().toString(), snapshot.agentOptions(bootstrap));
    } catch (AttachNotSupportedException error) {
      AgentSnapshot.deleteOwnedSnapshot(snapshot.root(), pid, before.startTime());
      throw mapAttachFailure("attach", error);
    } catch (AgentLoadException error) {
      // loadAgent may have reached target code before the provider reported failure.
      // Retain the snapshot while target identity is live or uncertain.
      throw uncertainAttach("the helper could not confirm whether the target loaded the agent");
    } catch (AgentInitializationException error) {
      throw mapAttachFailure("attach", error);
    } catch (IOException | RuntimeException error) {
      if (loadAttempted) {
        throw uncertainAttach("the helper lost a reliable result after requesting agent loading");
      }
      if (error instanceof IOException io) throw io;
      throw error;
    }
    try {
      before.requireUnchanged(ProcessIdentity.read(pid, "attach"), "attach");
    } catch (Failure changed) {
      throw uncertainAttach("the target identity changed after agent loading was requested");
    }
    return Result.success(
        "attach",
        Map.of(
            "process",
            before.toJson(properties, true, descriptor.provider().type()),
            "agentState",
            "active_or_already_active"));
  }

  private static Map<String, String> parseOptions(
      String[] arguments, int offset, SetOf allowed) throws Failure {
    if (arguments.length < offset + 1 || !"--json".equals(arguments[arguments.length - 1])) {
      throw usage(commandName(arguments), "the command requires --json");
    }
    Map<String, String> values = new LinkedHashMap<>();
    for (int index = offset; index < arguments.length - 1; index += 2) {
      if (index + 1 >= arguments.length - 1 || !allowed.contains(arguments[index])) {
        throw usage(commandName(arguments), "the command contains an unknown or incomplete option");
      }
      if (values.putIfAbsent(arguments[index], arguments[index + 1]) != null) {
        throw usage(commandName(arguments), "an option was repeated");
      }
    }
    for (String required : allowed.values) {
      if (!values.containsKey(required)) {
        throw usage(commandName(arguments), "a required option is missing");
      }
    }
    return values;
  }

  private static long parsePid(String value, String command) throws Failure {
    if (value == null || !value.matches("[1-9][0-9]{0,9}")) {
      throw usage(command, "PID must be a positive decimal process identifier");
    }
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException error) {
      throw usage(command, "PID is outside the supported range");
    }
  }

  private static long parseDescriptorPid(String value) throws Failure {
    return parsePid(value, "list");
  }

  private static VirtualMachineDescriptor findDescriptor(long pid) throws IOException, Failure {
    String expected = Long.toString(pid);
    return VirtualMachine.list().stream()
        .filter(descriptor -> expected.equals(descriptor.id()))
        .findFirst()
        .orElse(null);
  }

  private static Failure unavailableTarget(ProcessIdentity identity, String command) {
    if (identity.executableKnown() && !identity.javaExecutable()) {
      return new Failure(
          command,
          "XTR-ATTACH-UNSUPPORTED-RUNTIME",
          4,
          "The selected process is not a JVM that accepts Java agents.",
          "Use a JVM build of the application and launch it through X-trace; native-image processes cannot be attached.");
    }
    return new Failure(
        command,
        "XTR-ATTACH-UNAVAILABLE",
        5,
        "The JVM is not visible to the local Attach provider.",
        "Run the helper in the same user and process namespace, or relaunch the application through X-trace.");
  }

  private static Failure mapAttachFailure(String command, Exception error) {
    String detail = String.valueOf(error.getMessage()).toLowerCase(java.util.Locale.ROOT);
    if (detail.contains("dynamic agent loading")
        || detail.contains("dynamic loading is not enabled")
        || detail.contains("disableattachmechanism")) {
      return new Failure(
          command,
          "XTR-ATTACH-DYNAMIC-DISABLED",
          4,
          "The target JVM does not permit dynamic agent loading.",
          "Relaunch with `xtrace run --java-agent <agent> -- java <application arguments>`, or enable dynamic loading for this JVM.");
    }
    if (detail.contains("not supported") || detail.contains("not available")) {
      return new Failure(
          command,
          "XTR-ATTACH-UNAVAILABLE",
          5,
          "The target JVM does not expose a usable Attach provider.",
          "Run the helper beside the target JVM in the same user and process namespace, or relaunch through X-trace.");
    }
    if (error instanceof AgentInitializationException) {
      return new Failure(
          command,
          "XTR-ATTACH-AGENT-REJECTED",
          7,
          "The target JVM rejected agent initialization; an X-trace session may already be active.",
          "Inspect the target's existing X-trace recording. To select another project, relaunch the JVM through X-trace.",
          Map.of("targetAgentState", "unknown_after_agent_rejection"));
    }
    return new Failure(
        command,
        "XTR-ATTACH-FAILED",
        7,
        "The JVM rejected the attach operation.",
        "Check the reported capability facts; if attachment remains unavailable, relaunch through X-trace with premain capture.");
  }

  private static Failure usage(String command, String message) {
    return new Failure(
        command,
        "XTR-ATTACH-INVALID-ARGUMENTS",
        2,
        message,
        "Use `xtrace-attach list --json`, `inspect --pid <pid> --json`, or `attach --pid <pid> --agent <jar> --options-file <path> --json`.");
  }

  private static Failure uncertainAttach(String message) {
    return new Failure(
        "attach",
        "XTR-ATTACH-RESULT-UNCERTAIN",
        7,
        message,
        "Inspect the target before retrying; if its attach state is uncertain, relaunch through X-trace.",
        Map.of("targetAgentState", "unknown_after_load_attempt"));
  }

  private static String commandName(String[] arguments) {
    if (arguments == null || arguments.length == 0) return "unknown";
    return switch (arguments[0]) {
      case "list", "inspect", "attach" -> arguments[0];
      default -> "unknown";
    };
  }

  private enum SetOf {
    PID("--pid"),
    ATTACH("--pid", "--agent", "--options-file");

    private final List<String> values;

    SetOf(String... values) {
      this.values = List.of(values);
    }

    boolean contains(String option) {
      return values.contains(option);
    }
  }

  private static final class AttachedVm implements AutoCloseable {
    private final VirtualMachine machine;

    private AttachedVm(VirtualMachine machine) {
      this.machine = machine;
    }

    static AttachedVm connect(VirtualMachineDescriptor descriptor)
        throws AttachNotSupportedException, IOException {
      return new AttachedVm(VirtualMachine.attach(descriptor));
    }

    VirtualMachine machine() {
      return machine;
    }

    @Override
    public void close() throws IOException {
      machine.detach();
    }
  }

  static final class Result {
    private final String command;
    private final boolean ok;
    private final String code;
    private final int exitCode;
    private final String message;
    private final String remediation;
    private final Map<String, Object> data;

    private Result(
        String command,
        boolean ok,
        String code,
        int exitCode,
        String message,
        String remediation,
        Map<String, Object> data) {
      this.command = command;
      this.ok = ok;
      this.code = code;
      this.exitCode = exitCode;
      this.message = message;
      this.remediation = remediation;
      this.data = data;
    }

    static Result success(String command, Map<String, Object> data) {
      return new Result(command, true, "XTR-ATTACH-OK", 0, "JVM operation completed.", null, data);
    }

    static Result failure(
        String command, String code, int exitCode, String message, String remediation) {
      return failure(command, code, exitCode, message, remediation, Map.of());
    }

    static Result failure(
        String command,
        String code,
        int exitCode,
        String message,
        String remediation,
        Map<String, Object> data) {
      return new Result(command, false, code, exitCode, message, remediation, data);
    }

    int exitCode() {
      return exitCode;
    }

    String toJson() {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("schemaVersion", 1);
      values.put("ok", ok);
      values.put("command", command);
      values.put("code", code);
      values.put("message", message);
      if (remediation != null) values.put("remediation", remediation);
      values.putAll(data);
      return Json.encode(values);
    }
  }

  static final class Failure extends Exception {
    private static final long serialVersionUID = 1L;

    private final String command;
    private final String code;
    private final int exitCode;
    private final String remediation;
    private final Map<String, Object> data;

    Failure(String command, String code, int exitCode, String message, String remediation) {
      this(command, code, exitCode, message, remediation, Map.of());
    }

    Failure(
        String command,
        String code,
        int exitCode,
        String message,
        String remediation,
        Map<String, Object> data) {
      super(message);
      this.command = command;
      this.code = code;
      this.exitCode = exitCode;
      this.remediation = remediation;
      this.data = data;
    }

    String code() {
      return code;
    }
  }
}
