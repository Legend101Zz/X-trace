package dev.xtrace.agent.runtime.line;

/**
 * Bounded, sanitized, redacted view of one local value (mirrors the wire CapturedValue states).
 * {@code preview} is non-null only for CAPTURED and TRUNCATED; {@code contentHash} (BLAKE3-256 of
 * the emitted preview UTF-8 bytes) only for the same two states, never for REDACTED. Wire mapping
 * (recording.proto): CAPTURED -> {shape, preview, content_hash}; TRUNCATED -> {preview,
 * original_size_lower_bound, limit} (the wire Truncated message has no content_hash, so this hash
 * is NOT wire-carried until the schema or CONTRACTS section 3 rule 1 changes); REDACTED ->
 * {rule_id, shape_hint = shape}. {@code originalSizeLowerBound} and {@code limit} are bytes and are
 * 0 unless the state is TRUNCATED.
 */
public record ValueSnapshot(
    State state,
    String name,
    Role role,
    NameOrigin nameOrigin,
    String typeName,
    String preview,
    ValueShape shape,
    long originalSizeLowerBound,
    long limit,
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
    LOCAL,
    EXCEPTION,
    RECEIVER
  }

  /** Mirrors the wire ValueShape enum (char has no wire shape and maps to STRING). */
  public enum ValueShape {
    STRING,
    BOOLEAN,
    INTEGER_8,
    INTEGER_16,
    INTEGER_32,
    INTEGER_64,
    FLOAT_32,
    FLOAT_64,
    NULL,
    BYTES,
    LIST,
    OBJECT,
    UNKNOWN
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
