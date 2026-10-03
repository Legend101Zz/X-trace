package io.xtrace.attach;

/** Standalone command entrypoint for best-effort JVM discovery and attach. */
public final class Main {
  private Main() {}

  /** Emits one stable JSON result and exits with the documented helper status. */
  public static void main(String[] arguments) {
    AttachCommands.Result result = AttachCommands.execute(arguments);
    System.out.println(result.toJson());
    if (result.exitCode() != 0) System.exit(result.exitCode());
  }
}
