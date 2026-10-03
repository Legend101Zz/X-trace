package io.xtrace.attach;

/** Internal bounded subprocess entrypoint. */
public final class WorkerMain {
  private WorkerMain() {}

  public static void main(String[] arguments) {
    AttachCommands.Result result = AttachCommands.execute(arguments);
    System.out.println(result.toJson());
    if (result.exitCode() != 0) System.exit(result.exitCode());
  }
}
