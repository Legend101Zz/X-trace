package dev.xtrace.agent.runtime;

import java.lang.instrument.Instrumentation;

/** Test-only premain supplies real Instrumentation without dynamic attach or a dependency. */
public final class ProxyProbeAgent {
  static Instrumentation instrumentation;

  public static void premain(String arguments, Instrumentation value) {
    instrumentation = value;
  }
}
