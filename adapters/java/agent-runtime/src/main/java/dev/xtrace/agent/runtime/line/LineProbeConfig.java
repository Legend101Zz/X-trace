package dev.xtrace.agent.runtime.line;

/** Immutable instrumentation policy. Defaults are bench values (ADR 0003 section 5). */
public record LineProbeConfig(
    String probeOwner,
    boolean focusedValues,
    int maxSitesPerMethod,
    int maxValuesPerSite,
    int maxValueCallsPerMethod,
    int maxEstimatedCodeBytes) {

  /** Stays safely under the 64 KiB method limit after ASM's own jump-widening headroom. */
  public static final int DEFAULT_MAX_CODE_BYTES = 56_000;

  public LineProbeConfig {
    if (probeOwner == null || probeOwner.isEmpty() || probeOwner.indexOf('.') >= 0) {
      throw new IllegalArgumentException("probeOwner must be an internal name");
    }
    if (maxSitesPerMethod < 1 || maxValuesPerSite < 0 || maxValueCallsPerMethod < 0
        || maxEstimatedCodeBytes < 1) {
      throw new IllegalArgumentException("budgets must be positive");
    }
  }

  /**
   * Line probes only, no local reads. NOT a standard-mode shape: the standard line budget is 0
   * (CONTRACTS section 4), so wire probes only in effective focused mode. Useful as the retry shape
   * after a class's focused instrumentation failed verification.
   */
  public static LineProbeConfig lineOnly(String probeOwner) {
    return new LineProbeConfig(probeOwner, false, 1024, 0, 0, DEFAULT_MAX_CODE_BYTES);
  }

  /** Line probes plus LocalVariableTable-gated local reads. */
  public static LineProbeConfig focused(String probeOwner) {
    return new LineProbeConfig(probeOwner, true, 1024, 16, 4096, DEFAULT_MAX_CODE_BYTES);
  }
}
