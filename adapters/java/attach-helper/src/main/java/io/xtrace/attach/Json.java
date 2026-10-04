package io.xtrace.attach;

import java.util.List;
import java.util.Map;

/** Minimal deterministic JSON encoder for the standalone JDK-only helper. */
final class Json {
  private Json() {}

  static String encode(Object value) {
    StringBuilder output = new StringBuilder(512);
    append(output, value);
    return output.toString();
  }

  private static void append(StringBuilder output, Object value) {
    if (value == null) {
      output.append("null");
    } else if (value instanceof String text) {
      quote(output, text);
    } else if (value instanceof Number || value instanceof Boolean) {
      output.append(value);
    } else if (value instanceof Map<?, ?> values) {
      output.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : values.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw new IllegalArgumentException("JSON object keys must be strings");
        }
        if (!first) output.append(',');
        first = false;
        quote(output, key);
        output.append(':');
        append(output, entry.getValue());
      }
      output.append('}');
    } else if (value instanceof List<?> values) {
      output.append('[');
      for (int index = 0; index < values.size(); index++) {
        if (index > 0) output.append(',');
        append(output, values.get(index));
      }
      output.append(']');
    } else {
      throw new IllegalArgumentException("unsupported JSON value type");
    }
  }

  private static void quote(StringBuilder output, String value) {
    output.append('"');
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"' -> output.append("\\\"");
        case '\\' -> output.append("\\\\");
        case '\b' -> output.append("\\b");
        case '\f' -> output.append("\\f");
        case '\n' -> output.append("\\n");
        case '\r' -> output.append("\\r");
        case '\t' -> output.append("\\t");
        default -> {
          if (character < 0x20 || Character.isSurrogate(character)) {
            output.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) character));
          } else {
            output.append(character);
          }
        }
      }
    }
    output.append('"');
  }
}
