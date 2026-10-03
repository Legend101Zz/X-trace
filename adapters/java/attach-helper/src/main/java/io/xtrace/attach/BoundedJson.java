package io.xtrace.attach;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small strict JSON reader for the bounded worker response; it has no external dependencies. */
final class BoundedJson {
  private static final int MAX_INPUT_CHARS = 256 * 1024;
  private static final int MAX_DEPTH = 32;
  private static final int MAX_VALUES = 32 * 1024;

  private BoundedJson() {}

  static Map<String, Object> parseObject(String input) {
    if (input == null || input.length() > MAX_INPUT_CHARS) {
      throw new IllegalArgumentException("JSON input is missing or exceeds its limit");
    }
    Parser parser = new Parser(input);
    Object value = parser.parse();
    if (!(value instanceof Map<?, ?> object)) {
      throw new IllegalArgumentException("JSON object required");
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> typed = (Map<String, Object>) object;
    return typed;
  }

  static boolean isWorkerResponse(String input, String expectedCommand, int exitCode) {
    try {
      Map<String, Object> object = parseObject(input);
      Object version = object.get("schemaVersion");
      Object ok = object.get("ok");
      Object command = object.get("command");
      Object code = object.get("code");
      Object message = object.get("message");
      if (!(version instanceof BigDecimal number)
          || number.compareTo(BigDecimal.ONE) != 0
          || number.stripTrailingZeros().scale() > 0
          || !(ok instanceof Boolean success)
          || !(command instanceof String commandText)
          || !commandText.equals(expectedCommand)
          || !(code instanceof String codeText)
          || !codeText.matches("XTR-[A-Z0-9-]{1,96}")
          || !(message instanceof String)
          || (object.containsKey("remediation") && !(object.get("remediation") instanceof String))
          || (object.containsKey("targetAgentState")
              && !(object.get("targetAgentState") instanceof String))
          || (object.containsKey("targetIdentityStatus")
              && !(object.get("targetIdentityStatus") instanceof String))) {
        return false;
      }
      if (success) return exitCode == 0 && "XTR-ATTACH-OK".equals(codeText);
      return exitCode != 0 && !"XTR-ATTACH-OK".equals(codeText);
    } catch (IllegalArgumentException error) {
      return false;
    }
  }

  private static final class Parser {
    private final String input;
    private int offset;
    private int values;

    Parser(String input) {
      this.input = input;
    }

    Object parse() {
      whitespace();
      Object value = value(0);
      whitespace();
      if (offset != input.length()) fail();
      return value;
    }

    private Object value(int depth) {
      if (depth > MAX_DEPTH || ++values > MAX_VALUES || offset >= input.length()) fail();
      return switch (input.charAt(offset)) {
        case '{' -> object(depth + 1);
        case '[' -> array(depth + 1);
        case '"' -> string();
        case 't' -> literal("true", Boolean.TRUE);
        case 'f' -> literal("false", Boolean.FALSE);
        case 'n' -> literal("null", null);
        default -> number();
      };
    }

    private Map<String, Object> object(int depth) {
      offset++;
      whitespace();
      Map<String, Object> result = new LinkedHashMap<>();
      if (take('}')) return result;
      while (true) {
        if (offset >= input.length() || input.charAt(offset) != '"') fail();
        String key = string();
        whitespace();
        require(':');
        whitespace();
        Object value = value(depth);
        if (result.containsKey(key)) fail();
        result.put(key, value);
        whitespace();
        if (take('}')) return result;
        require(',');
        whitespace();
      }
    }

    private List<Object> array(int depth) {
      offset++;
      whitespace();
      List<Object> result = new ArrayList<>();
      if (take(']')) return result;
      while (true) {
        result.add(value(depth));
        whitespace();
        if (take(']')) return result;
        require(',');
        whitespace();
      }
    }

    private String string() {
      require('"');
      StringBuilder result = new StringBuilder();
      while (offset < input.length()) {
        char current = input.charAt(offset++);
        if (current == '"') {
          validateSurrogates(result);
          return result.toString();
        }
        if (current < 0x20) fail();
        if (current != '\\') {
          result.append(current);
          continue;
        }
        if (offset >= input.length()) fail();
        switch (input.charAt(offset++)) {
          case '"' -> result.append('"');
          case '\\' -> result.append('\\');
          case '/' -> result.append('/');
          case 'b' -> result.append('\b');
          case 'f' -> result.append('\f');
          case 'n' -> result.append('\n');
          case 'r' -> result.append('\r');
          case 't' -> result.append('\t');
          case 'u' -> result.append(unicodeEscape());
          default -> fail();
        }
      }
      fail();
      return "";
    }

    private char unicodeEscape() {
      if (input.length() - offset < 4) fail();
      int value = 0;
      for (int index = 0; index < 4; index++) {
        int digit = Character.digit(input.charAt(offset++), 16);
        if (digit < 0) fail();
        value = (value << 4) | digit;
      }
      return (char) value;
    }

    private void validateSurrogates(CharSequence text) {
      for (int index = 0; index < text.length(); index++) {
        char value = text.charAt(index);
        if (Character.isHighSurrogate(value)) {
          if (++index >= text.length() || !Character.isLowSurrogate(text.charAt(index))) fail();
        } else if (Character.isLowSurrogate(value)) {
          fail();
        }
      }
    }

    private Object number() {
      int start = offset;
      take('-');
      if (take('0')) {
        if (digitAhead()) fail();
      } else {
        digits(true);
      }
      if (take('.')) digits(true);
      if (take('e') || take('E')) {
        if (!take('+')) take('-');
        digits(true);
      }
      if (start == offset) fail();
      try {
        return new BigDecimal(input.substring(start, offset));
      } catch (NumberFormatException error) {
        throw new IllegalArgumentException("invalid JSON number");
      }
    }

    private void digits(boolean required) {
      int start = offset;
      while (digitAhead()) offset++;
      if (required && start == offset) fail();
    }

    private boolean digitAhead() {
      return offset < input.length() && input.charAt(offset) >= '0' && input.charAt(offset) <= '9';
    }

    private Object literal(String spelling, Object result) {
      if (!input.startsWith(spelling, offset)) fail();
      offset += spelling.length();
      return result;
    }

    private void whitespace() {
      while (offset < input.length()) {
        char value = input.charAt(offset);
        if (value != ' ' && value != '\t' && value != '\r' && value != '\n') return;
        offset++;
      }
    }

    private boolean take(char expected) {
      if (offset < input.length() && input.charAt(offset) == expected) {
        offset++;
        return true;
      }
      return false;
    }

    private void require(char expected) {
      if (!take(expected)) fail();
    }

    private void fail() {
      throw new IllegalArgumentException("invalid bounded JSON");
    }
  }
}
