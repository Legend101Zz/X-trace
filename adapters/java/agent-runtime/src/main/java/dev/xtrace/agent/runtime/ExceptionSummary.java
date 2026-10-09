package dev.xtrace.agent.runtime;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

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

  private static final Pattern[] SECRET_SHAPES = {
    // PEM blocks, including truncated ones.
    Pattern.compile("-----BEGIN [A-Z ]+-----[\\s\\S]*"),
    // JSON web tokens.
    Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*"),
    // Authorization-style credentials.
    Pattern.compile("(?i)\\b(bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}"),
    // Cloud access keys.
    Pattern.compile("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"),
    // Credentials embedded in URLs.
    Pattern.compile("(?i)\\b[a-z][a-z0-9+.-]*://[^\\s/@:]+:[^\\s/@]+@"),
    // key=value or key: value where the key names a secret.
    Pattern.compile(
        "(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
            + "authorization|cookie|session[_-]?id)\\b\\s*[=:]\\s*[^\\s,;&]+"),
    // Long opaque tokens: 32 or more hex or base64url characters.
    Pattern.compile("\\b[A-Fa-f0-9]{32,}\\b"),
    Pattern.compile("\\b[A-Za-z0-9_-]{40,}\\b"),
  };

  private ExceptionSummary() {}

  /** Sanitized message, or null when the exception had none. */
  static String message(String raw) {
    if (raw == null) return null;
    String text = raw.length() > 4096 ? raw.substring(0, 4096) : raw;
    for (Pattern pattern : SECRET_SHAPES) {
      text = pattern.matcher(text).replaceAll(REDACTED);
    }
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
