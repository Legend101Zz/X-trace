package dev.xtrace.agent.bootstrap;

/**
 * JDK-only receiver of focused-mode line probes. The bridge supplies the request context (recording
 * and event identity) so the private runtime never reads the bridge's thread state. Calls run on
 * application threads and must never block or throw; the bridge swallows throwables anyway.
 *
 * <p>Protocol per probe site: {@link #line} opens a pending line event for the calling thread (and
 * completes the previous one), then optionally {@code valuesBegin(site)}, value calls and
 * {@code valuesEnd()} attach locals to it. {@link #flush} completes the pending event; the bridge
 * calls it before any other event of the same request.
 */
public interface LineSink {
  void line(String recordingId, String eventId, String parentEventId, int siteId, long monotonicNs);

  void valuesBegin(int siteId);

  void valueInt(int slot, int nameId, int value);

  void valueLong(int slot, int nameId, long value);

  void valueFloat(int slot, int nameId, float value);

  void valueDouble(int slot, int nameId, double value);

  /** Reference-typed local. Implementations must never call {@code toString} on the value. */
  void valueRef(int nameId, int role, Object value);

  void valuesEnd();

  /** Completes the calling thread's pending line event, if any. */
  void flush();

  /**
   * The bridge ignored the line probe that just ran (budget spent, no request, deferred). The
   * value calls that follow belong to no accepted event and must not attach to the previous one.
   */
  default void lineIgnored() {}
}
