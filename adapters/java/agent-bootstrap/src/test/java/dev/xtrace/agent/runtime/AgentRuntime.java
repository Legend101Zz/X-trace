package dev.xtrace.agent.runtime;

import java.lang.instrument.Instrumentation;

/** Test-only runtime payload that models a permanent failure after instrumentation mutation. */
public final class AgentRuntime {
  private AgentRuntime() {}

  public static byte[] prepareBootstrap(
      String bootstrapPath, Instrumentation instrumentation, boolean attach) {
    return new byte[] {1};
  }

  public static byte[] start(
      String bootstrapPath,
      Instrumentation instrumentation,
      boolean attach,
      byte[] expectedIdentity)
      throws StartFailure {
    throw new StartFailure();
  }

  public static byte[] bootstrapIdentity(String bootstrapPath) {
    return new byte[] {1};
  }

  public static final class StartFailure extends Exception {
    public boolean permanent() {
      return true;
    }
  }
}
