package io.xtrace.attach;

/** Standalone command entrypoint for best-effort JVM discovery and attach. */
public final class Main {
  private Main() {}

  /** Emits one stable JSON result and exits with the documented helper status. */
  public static void main(String[] arguments) {
    HelperSupervisor.Result result = HelperSupervisor.run(arguments);
    System.out.println(result.json());
    if (result.exitCode() != 0) System.exit(result.exitCode());
  }
}
