package io.xtrace.attach;

/** Child-process fixture for timeout and target-survival tests. */
public final class SupervisorTestProgram {
  private SupervisorTestProgram() {}

  public static void main(String[] arguments) throws InterruptedException {
    if (arguments.length > 0 && "target".equals(arguments[0])) {
      Thread.sleep(Long.MAX_VALUE);
      return;
    }
    String mode = arguments.length > 1 ? arguments[1] : "hang";
    switch (mode) {
      case "tmpdir" -> System.out.println(System.getProperty("java.io.tmpdir"));
      case "malformed-json" -> System.out.println("{\"schemaVersion\":1,\"ok\":true");
      case "mismatched-exit" -> {
        System.out.println(
            "{\"schemaVersion\":1,\"ok\":true,\"command\":\"attach\","
                + "\"code\":\"XTR-ATTACH-OK\",\"message\":\"completed\"}");
        System.exit(9);
      }
      case "hang" -> Thread.sleep(Long.MAX_VALUE);
      default -> System.exit(10);
    }
  }
}
