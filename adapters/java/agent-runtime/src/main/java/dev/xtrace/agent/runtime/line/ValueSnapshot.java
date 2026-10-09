package dev.xtrace.agent.runtime.line;

/**
 * Bounded, sanitized, redacted view of one local value (mirrors the wire CapturedValue states).
 * {@code preview} is non-null only for CAPTURED and TRUNCATED; {@code contentHash} (BLAKE3-256 of
 * the emitted preview UTF-8 bytes) only for the same two states, never for REDACTED.
 */
public record ValueSnapshot(
    State state,
    String name,
    Role role,
    NameOrigin nameOrigin,
    String typeName,
    String preview,
    byte[] contentHash,
    String ruleId,
    Reason reason) {

  public enum State {
    CAPTURED,
    TRUNCATED,
    REDACTED,
    UNAVAILABLE
  }

  public enum Role {
    ARGUMENT,
    RETURN,
    LOCAL
  }

  public enum NameOrigin {
    DECLARED,
    SYNTHESIZED
  }

  /** Subset of the wire UnavailableReason this sanitizer can produce. */
  public enum Reason {
    NONE,
    UNSAFE_TO_RENDER,
    DEBUG_METADATA_ABSENT
  }
}
