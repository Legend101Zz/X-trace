package dev.xtrace.agent.runtime.line;

/**
 * Honest per-method outcome. {@code status} is INSTRUMENTED or SKIPPED; {@code reason} is a stable
 * machine token (see {@link Reasons}); {@code valuesReason} explains why focused locals were not
 * read although line probes were (empty when values were read or not requested).
 */
public record MethodReport(
    String name,
    String descriptor,
    Status status,
    String reason,
    int sites,
    int valueCalls,
    String valuesReason) {

  public enum Status {
    INSTRUMENTED,
    SKIPPED
  }

  /** Stable reason tokens. */
  public static final class Reasons {
    public static final String BRIDGE = "bridge";
    public static final String SYNTHETIC = "synthetic";
    public static final String NO_LINE_TABLE = "no_line_table";
    public static final String TOO_LARGE = "method_too_large";
    public static final String SITE_BUDGET = "line_site_budget_exceeded";
    public static final String REGISTRY_FULL = "site_registry_full";
    public static final String JSR_RET = "jsr_ret_unsupported";
    public static final String NO_LVT = "no_local_variable_table";
    public static final String VALUES_NON_JAVAC = "values_skipped_non_javac";
    public static final String VALUE_BUDGET = "value_budget_exceeded";
    public static final String VALUES_CAPPED = "values_capped_per_site";
    public static final String CLASS_VERSION = "unsupported_class_version";
    public static final String TRANSFORM_ERROR = "transform_error";
    public static final String NONE = "";

    private Reasons() {}
  }
}
