package dev.xtrace.agent.runtime.line;

/**
 * Receiver of line and value probe calls. Every method has a no-op default so an implementation
 * overrides only what it needs. Implementations run on application threads: they must be
 * allocation-light, never block, and never throw (the dispatcher swallows throwables anyway).
 */
public interface LineProbeSink {
  /** Execution reached the first instruction of a line table entry (site from {@link SiteRegistry}). */
  default void line(int siteId) {}

  /** Starts the focused-mode value group that belongs to the {@code line} call just made. */
  default void valuesBegin(int siteId) {}

  default void valueInt(int slot, int nameId, int value) {}

  default void valueLong(int slot, int nameId, long value) {}

  default void valueFloat(int slot, int nameId, float value) {}

  default void valueDouble(int slot, int nameId, double value) {}

  /** Reference-typed local. Implementations must never call {@code toString} on {@code value}. */
  default void valueRef(int nameId, int role, Object value) {}

  default void valuesEnd() {}

  /** Role constant passed to {@link #valueRef}: a local variable. */
  int ROLE_LOCAL = 3;

  /** Sink that ignores everything. */
  LineProbeSink NOOP = new LineProbeSink() {};
}
