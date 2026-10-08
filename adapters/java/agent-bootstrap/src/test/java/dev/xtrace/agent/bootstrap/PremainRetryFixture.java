package dev.xtrace.agent.bootstrap;

/** Child JVM entrypoint for the real premain-to-agentmain permanent-failure regression. */
public final class PremainRetryFixture {
  private PremainRetryFixture() {}

  public static void main(String[] arguments) {
    try {
      XTraceAgent.agentmain("invalid-options", null);
      System.out.println("PREMAIN_PARTIAL_ATTACH_UNEXPECTEDLY_ALLOWED");
      System.exit(2);
    } catch (Exception error) {
      if ("XTR-JAVA-AGENT-RELAUNCH-REQUIRED".equals(error.getMessage())) {
        System.out.println("PREMAIN_PARTIAL_ATTACH_BLOCKED");
        return;
      }
      System.out.println("PREMAIN_PARTIAL_ATTACH_WRONG_FAILURE");
      System.exit(3);
    }
  }
}
