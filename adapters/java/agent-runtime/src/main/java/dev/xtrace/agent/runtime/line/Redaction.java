package dev.xtrace.agent.runtime.line;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.security.Key;
import java.util.regex.Pattern;

/** ADR 0003 section 6 rules: name rule, type rule, content rule. Pattern list version is stamped. */
public final class Redaction {
  /** Recorded against the redaction policy digest; bump when any pattern changes. */
  public static final String POLICY_VERSION = "adr0003-s6-v2";

  public static final String RULE_NAME = "name.secret";
  public static final String RULE_TYPE = "type.sensitive";
  public static final String RULE_CONTENT = "content.secret_pattern";

  /** Only this prefix of a string is scanned for content patterns (bounds regex cost). */
  public static final int CONTENT_SCAN_CHARS = 8192;

  private static final Pattern NAME =
      Pattern.compile(
          "password|passwd|pwd|secret|token|authorization|cookie|api[_-]?key|credential"
              + "|private[_-]?key|session|bearer",
          Pattern.CASE_INSENSITIVE);

  /** Replacement text used when {@link #replaceSecrets} rewrites a message. */
  public static final String REDACTED_TEXT = "[redacted]";

  /**
   * Single source of truth for secret-shaped content (values and exception messages). Keep in step
   * with the Rust audit redactor through the shared vectors in
   * {@code src/test/resources/line/redaction-vectors.tsv}.
   */
  private static final Pattern[] CONTENT = {
    // PEM blocks, including truncated ones
    Pattern.compile("-----BEGIN [A-Z0-9 ]+-----[\\s\\S]*"),
    // JWT-shaped; also a lone header segment so truncation cannot hide the token
    Pattern.compile("eyJ[A-Za-z0-9_-]{8,}"),
    Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*"),
    // Authorization-style credentials
    Pattern.compile("(?i)\\b(bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}"),
    Pattern.compile("(?i)bearer\\s+[^\\s]{4,}"),
    // Cloud access keys
    Pattern.compile("(AKIA|ASIA)[0-9A-Z]{16}"),
    // Credentials embedded in URLs
    Pattern.compile("(?i)\\b[a-z][a-z0-9+.-]*://[^\\s/@:]+:[^\\s/@]+@"),
    // key=value or key: value where the key names a secret
    Pattern.compile(
        "(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
            + "authorization|cookie|session[_-]?id)\\b\\s*[=:]\\s*[^\\s,;&]+"),
    // Long opaque tokens: 32 or more hex or 40 or more base64url characters
    Pattern.compile("\\b[A-Fa-f0-9]{32,}\\b"),
    Pattern.compile("\\b[A-Za-z0-9_-]{40,}\\b"),
  };

  private Redaction() {}

  public static boolean nameIsSecret(String name) {
    return name != null && NAME.matcher(name).find();
  }

  public static boolean contentIsSecret(String text) {
    if (text == null) return false;
    CharSequence scan = text.length() > CONTENT_SCAN_CHARS ? text.subSequence(0, CONTENT_SCAN_CHARS) : text;
    for (Pattern p : CONTENT) {
      if (p.matcher(scan).find()) return true;
    }
    return false;
  }

  /** Replaces every secret-shaped span with {@link #REDACTED_TEXT} (for free-text messages). */
  public static String replaceSecrets(String text) {
    if (text == null) return null;
    String out = text;
    for (Pattern p : CONTENT) out = p.matcher(out).replaceAll(REDACTED_TEXT);
    return out;
  }

  /** Type rule by instanceof only: never calls into the value. */
  public static boolean typeIsSensitive(Object value) {
    return value instanceof Key
        || value instanceof javax.crypto.Cipher
        || value instanceof java.security.KeyStore
        || value instanceof InputStream
        || value instanceof OutputStream
        || value instanceof Reader
        || value instanceof Writer
        || value instanceof Class<?>
        || value instanceof ClassLoader
        || value instanceof Thread;
  }
}
