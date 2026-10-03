package io.xtrace.attach;

/** Child-process fixture for timeout and target-survival tests. */
public final class SupervisorTestProgram {
  private SupervisorTestProgram() {}

  public static void main(String[] arguments) throws InterruptedException {
    Thread.sleep(Long.MAX_VALUE);
  }
}
