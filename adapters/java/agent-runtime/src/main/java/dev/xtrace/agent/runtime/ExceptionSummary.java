package dev.xtrace.agent.runtime;

import java.nio.charset.StandardCharsets;

/**
 * Bounded, redacted exception text for the recording. The adapter never sends a stack trace or
 * the raw message: the message is cut to {@link #MAX_MESSAGE_BYTES} UTF-8 bytes on a character
 * boundary, secret-shaped content is replaced, and control characters are removed. The daemon
 * runs its own audit pass over the result; this is the first of two gates, not the only one.
 */
final class ExceptionSummary {
  /** Largest message the adapter will send, in UTF-8 bytes. */
  static final int MAX_MESSAGE_BYTES = 512;

  /** Largest exception type name the adapter will send, in UTF-8 bytes. */
  static final int MAX_TYPE_BYTES = 256;

  /** Replacement for redacted content. */
  static final String REDACTED = "[redacted]";

  private ExceptionSummary() {}

  /** Sanitized message, or null when the exception had none. */
  static String message(String raw) {
    if (raw == null) return null;
    String text = raw.length() > 4096 ? raw.substring(0, 4096) : raw;
    // One redaction policy for values and exception messages (JB-2).
    text = dev.xtrace.agent.runtime.line.Redaction.replaceSecrets(text);
    StringBuilder clean = new StringBuilder(text.length());
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      clean.append(c < ' ' || c == 0x7f ? ' ' : c);
    }
    return truncate(clean.toString(), MAX_MESSAGE_BYTES);
  }

  /** True when {@link #message} replaced any content. */
  static boolean wasRedacted(String raw, String sanitized) {
    return raw != null && sanitized != null && sanitized.contains(REDACTED);
  }

  /** Exception class name bounded to {@link #MAX_TYPE_BYTES} bytes. */
  static String type(String raw) {
    return raw == null ? null : truncate(raw, MAX_TYPE_BYTES);
  }

  /** Cuts to a byte bound without splitting a UTF-8 sequence or a surrogate pair. */
  static String truncate(String value, int maxBytes) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    if (bytes.length <= maxBytes) return value;
    int end = maxBytes;
    while (end > 0 && (bytes[end] & 0xC0) == 0x80) end--;
    return new String(bytes, 0, end, StandardCharsets.UTF_8);
  }
}
