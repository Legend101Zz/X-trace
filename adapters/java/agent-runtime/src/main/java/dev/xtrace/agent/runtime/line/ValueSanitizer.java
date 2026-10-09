package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Reason;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import dev.xtrace.agent.runtime.line.ValueSnapshot.State;
import java.nio.charset.StandardCharsets;

/**
 * Turns raw probe values into {@link ValueSnapshot}s. Supported: primitives, {@code String}, boxed
 * primitives, enum constants (by {@code name()}). Everything else is the type name plus
 * UNAVAILABLE. It never invokes {@code toString}, {@code hashCode}, getters or any other code of a
 * value it does not own (String, boxed types and {@code Enum.name()} are final JDK code).
 */
public final class ValueSanitizer {
  /** Per-mode bounds from ADR 0003 section 5. */
  public record Limits(int maxPreviewBytes, int maxNameBytes, int maxTypeBytes) {
    public static final Limits STANDARD = new Limits(256, 128, 256);
    public static final Limits FOCUSED = new Limits(512, 128, 256);
  }

  private ValueSanitizer() {}

  public static ValueSnapshot ofInt(
      SiteRegistry.Name n, int value, Role role, Limits limits) {
    char kind = n.descriptor().charAt(0);
    String text;
    String type;
    switch (kind) {
      case 'Z' -> {
        text = value != 0 ? "true" : "false";
        type = "boolean";
      }
      case 'C' -> {
        text = printableChar((char) value);
        type = "char";
      }
      case 'B' -> {
        text = Integer.toString((byte) value);
        type = "byte";
      }
      case 'S' -> {
        text = Integer.toString((short) value);
        type = "short";
      }
      default -> {
        text = Integer.toString(value);
        type = "int";
      }
    }
    return primitive(n.name(), role, type, text, limits);
  }

  public static ValueSnapshot ofLong(SiteRegistry.Name n, long value, Role role, Limits limits) {
    return primitive(n.name(), role, "long", Long.toString(value), limits);
  }

  public static ValueSnapshot ofFloat(SiteRegistry.Name n, float value, Role role, Limits limits) {
    return primitive(n.name(), role, "float", Float.toString(value), limits);
  }

  public static ValueSnapshot ofDouble(SiteRegistry.Name n, double value, Role role, Limits limits) {
    return primitive(n.name(), role, "double", Double.toString(value), limits);
  }

  private static ValueSnapshot primitive(
      String rawName, Role role, String type, String text, Limits limits) {
    String name = boundName(rawName, limits);
    if (Redaction.nameIsSecret(name)) return redacted(name, role, type, Redaction.RULE_NAME);
    return captured(name, role, type, text, limits);
  }

  /** Reference value; {@code declaredName} is the LocalVariableTable (or parameter) name. */
  public static ValueSnapshot ofRef(
      String declaredName, NameOrigin origin, Object value, Role role, Limits limits) {
    String name = boundName(declaredName, limits);
    String type = value == null ? "null" : typeName(value, limits);
    if (Redaction.nameIsSecret(name)) return redacted(name, role, type, origin, Redaction.RULE_NAME);
    if (value == null) return captured(name, role, "null", "null", origin, limits);
    if (Redaction.typeIsSensitive(value)) {
      return redacted(name, role, type, origin, Redaction.RULE_TYPE);
    }
    Class<?> c = value.getClass();
    if (c == String.class) {
      String s = (String) value;
      if (Redaction.contentIsSecret(s)) {
        return redacted(name, role, type, origin, Redaction.RULE_CONTENT);
      }
      return captured(name, role, type, s, origin, limits);
    }
    String boxed = boxedText(value);
    if (boxed != null) return captured(name, role, type, boxed, origin, limits);
    if (value instanceof Enum<?> e) {
      // Enum.name() is final: no user code runs.
      return captured(name, role, type, e.name(), origin, limits);
    }
    return unavailable(name, role, type, origin, Reason.UNSAFE_TO_RENDER);
  }

  /** Unavailable binding for a method that has no LocalVariableTable (synthesized argN name). */
  public static ValueSnapshot noDebugMetadata(int argIndex, Role role) {
    return new ValueSnapshot(
        State.UNAVAILABLE, "arg" + argIndex, role, NameOrigin.SYNTHESIZED, "", null, null, null,
        Reason.DEBUG_METADATA_ABSENT);
  }

  // ---------------------------------------------------------------------------------------------

  private static String boxedText(Object value) {
    if (value instanceof Integer || value instanceof Long || value instanceof Short
        || value instanceof Byte || value instanceof Boolean || value instanceof Float
        || value instanceof Double) {
      return value.toString(); // final JDK classes
    }
    if (value instanceof Character ch) return printableChar(ch);
    return null;
  }

  private static String printableChar(char c) {
    if (Character.isISOControl(c) || Character.isSurrogate(c)) {
      return String.format("\\u%04x", (int) c);
    }
    return String.valueOf(c);
  }

  private static ValueSnapshot captured(
      String name, Role role, String type, String text, Limits limits) {
    return captured(name, role, type, text, NameOrigin.DECLARED, limits);
  }

  private static ValueSnapshot captured(
      String name, Role role, String type, String text, NameOrigin origin, Limits limits) {
    boolean tooLong = text.length() > limits.maxPreviewBytes();
    // every char is at least one UTF-8 byte, so this prefix always covers the byte limit
    String clean = stripControl(tooLong ? text.substring(0, limits.maxPreviewBytes()) : text);
    byte[] bytes = clean.getBytes(StandardCharsets.UTF_8);
    boolean truncated = tooLong || bytes.length > limits.maxPreviewBytes();
    String preview = clean;
    if (bytes.length > limits.maxPreviewBytes()) {
      preview = cutUtf8(clean, limits.maxPreviewBytes());
      bytes = preview.getBytes(StandardCharsets.UTF_8);
    }
    // The content rule runs again on the exact emitted text.
    if (Redaction.contentIsSecret(preview)) {
      return redacted(name, role, type, origin, Redaction.RULE_CONTENT);
    }
    return new ValueSnapshot(
        truncated ? State.TRUNCATED : State.CAPTURED,
        name, role, origin, type, preview, LineProbeInstrumenter.blake3(bytes), null, Reason.NONE);
  }

  private static ValueSnapshot redacted(String name, Role role, String type, String rule) {
    return redacted(name, role, type, NameOrigin.DECLARED, rule);
  }

  private static ValueSnapshot redacted(
      String name, Role role, String type, NameOrigin origin, String rule) {
    return new ValueSnapshot(State.REDACTED, name, role, origin, type, null, null, rule, Reason.NONE);
  }

  private static ValueSnapshot unavailable(
      String name, Role role, String type, NameOrigin origin, Reason reason) {
    return new ValueSnapshot(State.UNAVAILABLE, name, role, origin, type, null, null, null, reason);
  }

  private static String typeName(Object value, Limits limits) {
    String t = value.getClass().getName();
    return t.length() > limits.maxTypeBytes() ? cutUtf8(t, limits.maxTypeBytes()) : t;
  }

  private static String boundName(String name, Limits limits) {
    String n = stripControl(name == null ? "" : name);
    if (n.isEmpty()) n = "_";
    return n.getBytes(StandardCharsets.UTF_8).length > limits.maxNameBytes()
        ? cutUtf8(n, limits.maxNameBytes())
        : n;
  }

  private static String stripControl(String s) {
    StringBuilder b = null;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean bad = c == 0 || (Character.isISOControl(c) && c != '\n' && c != '\t');
      if (bad && b == null) {
        b = new StringBuilder(s.length());
        b.append(s, 0, i);
      }
      if (b != null) b.append(bad ? '�' : c);
    }
    return b == null ? s : b.toString();
  }

  /** Longest prefix whose UTF-8 encoding is at most {@code maxBytes}, never splitting a code point. */
  static String cutUtf8(String s, int maxBytes) {
    int bytes = 0;
    int i = 0;
    while (i < s.length()) {
      int cp = s.codePointAt(i);
      int len = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
      if (bytes + len > maxBytes) break;
      bytes += len;
      i += Character.charCount(cp);
    }
    return s.substring(0, i);
  }
}
