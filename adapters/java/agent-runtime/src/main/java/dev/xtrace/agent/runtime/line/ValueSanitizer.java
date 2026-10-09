package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Reason;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import dev.xtrace.agent.runtime.line.ValueSnapshot.State;
import dev.xtrace.agent.runtime.line.ValueSnapshot.ValueShape;
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
    ValueShape shape;
    switch (kind) {
      case 'Z' -> {
        text = value != 0 ? "true" : "false";
        type = "boolean";
        shape = ValueShape.BOOLEAN;
      }
      case 'C' -> {
        text = printableChar((char) value);
        type = "char";
        shape = ValueShape.STRING;
      }
      case 'B' -> {
        text = Integer.toString((byte) value);
        type = "byte";
        shape = ValueShape.INTEGER_8;
      }
      case 'S' -> {
        text = Integer.toString((short) value);
        type = "short";
        shape = ValueShape.INTEGER_16;
      }
      default -> {
        text = Integer.toString(value);
        type = "int";
        shape = ValueShape.INTEGER_32;
      }
    }
    return primitive(n.name(), role, type, shape, text, limits);
  }

  public static ValueSnapshot ofLong(SiteRegistry.Name n, long value, Role role, Limits limits) {
    return primitive(n.name(), role, "long", ValueShape.INTEGER_64, Long.toString(value), limits);
  }

  public static ValueSnapshot ofFloat(SiteRegistry.Name n, float value, Role role, Limits limits) {
    return primitive(n.name(), role, "float", ValueShape.FLOAT_32, Float.toString(value), limits);
  }

  public static ValueSnapshot ofDouble(SiteRegistry.Name n, double value, Role role, Limits limits) {
    return primitive(n.name(), role, "double", ValueShape.FLOAT_64, Double.toString(value), limits);
  }

  private static ValueSnapshot primitive(
      String rawName, Role role, String type, ValueShape shape, String text, Limits limits) {
    String name = boundName(rawName, limits);
    if (Redaction.nameIsSecret(name)) {
      return redacted(name, role, type, NameOrigin.DECLARED, shape, Redaction.RULE_NAME);
    }
    return captured(name, role, type, shape, text, NameOrigin.DECLARED, limits);
  }

  /** Reference value; {@code declaredName} is the LocalVariableTable (or parameter) name. */
  public static ValueSnapshot ofRef(
      String declaredName, NameOrigin origin, Object value, Role role, Limits limits) {
    String name = boundName(declaredName, limits);
    String type = value == null ? "null" : typeName(value, limits);
    ValueShape shape = shapeOf(value);
    if (Redaction.nameIsSecret(name)) {
      return redacted(name, role, type, origin, shape, Redaction.RULE_NAME);
    }
    if (value == null) return captured(name, role, "null", ValueShape.NULL, "null", origin, limits);
    if (Redaction.typeIsSensitive(value)) {
      return redacted(name, role, type, origin, shape, Redaction.RULE_TYPE);
    }
    Class<?> c = value.getClass();
    if (c == String.class) {
      String s = (String) value;
      if (Redaction.contentIsSecret(s)) {
        return redacted(name, role, type, origin, shape, Redaction.RULE_CONTENT);
      }
      return captured(name, role, type, shape, s, origin, limits);
    }
    String boxed = boxedText(value);
    if (boxed != null) return captured(name, role, type, shape, boxed, origin, limits);
    if (value instanceof Enum<?> e) {
      // Enum.name() is final: no user code runs.
      return captured(name, role, type, shape, e.name(), origin, limits);
    }
    return unavailable(name, role, type, origin, Reason.UNSAFE_TO_RENDER);
  }

  /** Wire shape by class identity only (never calls into the value). */
  private static ValueShape shapeOf(Object v) {
    if (v == null) return ValueShape.NULL;
    Class<?> c = v.getClass();
    if (c == String.class || c == Character.class || v instanceof Enum<?>) return ValueShape.STRING;
    if (c == Boolean.class) return ValueShape.BOOLEAN;
    if (c == Byte.class) return ValueShape.INTEGER_8;
    if (c == Short.class) return ValueShape.INTEGER_16;
    if (c == Integer.class) return ValueShape.INTEGER_32;
    if (c == Long.class) return ValueShape.INTEGER_64;
    if (c == Float.class) return ValueShape.FLOAT_32;
    if (c == Double.class) return ValueShape.FLOAT_64;
    if (c == byte[].class) return ValueShape.BYTES;
    if (c.isArray() || v instanceof java.util.Collection<?>) return ValueShape.LIST;
    return ValueShape.OBJECT;
  }

  /** Unavailable binding for a method that has no LocalVariableTable (synthesized argN name). */
  public static ValueSnapshot noDebugMetadata(int argIndex, Role role) {
    return new ValueSnapshot(
        State.UNAVAILABLE, "arg" + argIndex, role, NameOrigin.SYNTHESIZED, "", null, ValueShape.UNKNOWN, 0, 0, null, null,
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
      String name,
      Role role,
      String type,
      ValueShape shape,
      String text,
      NameOrigin origin,
      Limits limits) {
    int max = limits.maxPreviewBytes();
    boolean tooLong = text.length() > max;
    // Every char is at least one UTF-8 byte, so a char prefix of `max` covers the byte limit.
    // Never end the prefix on a high surrogate whose low half was cut off.
    int cut = max;
    if (tooLong && Character.isHighSurrogate(text.charAt(cut - 1))) cut--;
    String clean = stripControl(tooLong ? text.substring(0, cut) : text);
    byte[] bytes = clean.getBytes(StandardCharsets.UTF_8);
    long lowerBound = bytes.length;
    if (tooLong) lowerBound += text.length() - cut; // each unseen char is at least one byte
    boolean truncated = tooLong || bytes.length > max;
    String preview = clean;
    if (bytes.length > max) {
      preview = cutUtf8(clean, max);
      bytes = preview.getBytes(StandardCharsets.UTF_8);
    }
    // The content rule runs again on the exact emitted text.
    if (Redaction.contentIsSecret(preview)) {
      return redacted(name, role, type, origin, shape, Redaction.RULE_CONTENT);
    }
    return new ValueSnapshot(
        truncated ? State.TRUNCATED : State.CAPTURED,
        name, role, origin, type, preview, shape,
        truncated ? lowerBound : 0, truncated ? max : 0,
        LineProbeInstrumenter.blake3(bytes), null, Reason.NONE);
  }

  private static ValueSnapshot redacted(
      String name, Role role, String type, NameOrigin origin, ValueShape shape, String rule) {
    return new ValueSnapshot(
        State.REDACTED, name, role, origin, type, null, shape, 0, 0, null, rule, Reason.NONE);
  }

  private static ValueSnapshot unavailable(
      String name, Role role, String type, NameOrigin origin, Reason reason) {
    return new ValueSnapshot(
        State.UNAVAILABLE, name, role, origin, type, null, ValueShape.UNKNOWN, 0, 0, null, null,
        reason);
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

  /** Replaces control characters and unpaired surrogates (not valid UTF-8) with U+FFFD. */
  private static String stripControl(String s) {
    StringBuilder b = null;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean bad = c == 0 || (Character.isISOControl(c) && c != '\n' && c != '\t');
      boolean pair = false;
      if (Character.isHighSurrogate(c)) {
        pair = i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        bad |= !pair;
      } else if (Character.isLowSurrogate(c)) {
        bad = true; // a paired low half is consumed with its high half below
      }
      if (bad && b == null) {
        b = new StringBuilder(s.length());
        b.append(s, 0, i);
      }
      if (b != null) b.append(bad ? '\uFFFD' : c);
      if (pair) {
        i++;
        if (b != null) b.append(s.charAt(i));
      }
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
