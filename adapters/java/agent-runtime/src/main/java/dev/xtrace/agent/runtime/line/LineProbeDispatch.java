package dev.xtrace.agent.runtime.line;

/**
 * Static probe entry points that instrumented classes call. Lane J wires the production owner (the
 * bootstrap-visible bridge) with the same method names and descriptors; this class is the
 * reference implementation and the one the verifier corpus uses.
 *
 * <p>Every entry point is exception-proof: a failing sink can never break application code.
 */
public final class LineProbeDispatch {
  public static final String INTERNAL_NAME = "dev/xtrace/agent/runtime/line/LineProbeDispatch";

  private static volatile LineProbeSink sink = LineProbeSink.NOOP;

  private LineProbeDispatch() {}

  /** Installs a sink; {@code null} restores the no-op default. */
  public static void install(LineProbeSink next) {
    sink = next == null ? LineProbeSink.NOOP : next;
  }

  public static LineProbeSink current() {
    return sink;
  }

  public static void line(int siteId) {
    try {
      sink.line(siteId);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valuesBegin(int siteId) {
    try {
      sink.valuesBegin(siteId);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueInt(int slot, int nameId, int value) {
    try {
      sink.valueInt(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueLong(int slot, int nameId, long value) {
    try {
      sink.valueLong(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueFloat(int slot, int nameId, float value) {
    try {
      sink.valueFloat(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueDouble(int slot, int nameId, double value) {
    try {
      sink.valueDouble(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueRef(int nameId, int role, Object value) {
    try {
      sink.valueRef(nameId, role, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valuesEnd() {
    try {
      sink.valuesEnd();
    } catch (Throwable ignored) {
      // fail open
    }
  }
}
