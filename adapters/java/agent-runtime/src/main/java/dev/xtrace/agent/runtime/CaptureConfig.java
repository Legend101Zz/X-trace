package dev.xtrace.agent.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads the optional private {@code capture.json} beside the bootstrap. A missing, oversized,
 * non-private or malformed file yields the defaults: the file only narrows or names scope and can
 * never widen what the agent is allowed to do.
 */
final class CaptureConfig {
  private static final int MAX_BYTES = 64 * 1024;

  private final ApplicationScope scope;

  private CaptureConfig(ApplicationScope scope) {
    this.scope = scope;
  }

  static CaptureConfig defaults() {
    return new CaptureConfig(ApplicationScope.defaultScope());
  }

  ApplicationScope scope() {
    return scope;
  }

  /** Reads {@code capture.json} next to {@code bootstrapPath}; never throws. */
  static CaptureConfig readBeside(Path bootstrapPath) {
    try {
      Path file = bootstrapPath.toAbsolutePath().resolveSibling("capture.json");
      if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return defaults();
      if (Files.size(file) > MAX_BYTES || !ownerOnly(file)) return defaults();
      return parse(Files.readAllBytes(file));
    } catch (IOException | RuntimeException failure) {
      return defaults();
    }
  }

  static CaptureConfig parse(byte[] bytes) {
    try {
      if (bytes.length > MAX_BYTES) return defaults();
      Object root = new MiniJson(new String(bytes, StandardCharsets.UTF_8)).parse();
      if (!(root instanceof Map<?, ?> top)) return defaults();
      if (!Long.valueOf(1).equals(top.get("capture_schema_version"))) return defaults();
      Object scopeValue = top.get("application_scope");
      if (!(scopeValue instanceof Map<?, ?> scopeMap)) return defaults();
      List<String> packages = strings(scopeMap.get("application_packages"));
      List<String> roots = strings(scopeMap.get("source_roots"));
      List<String> safeRoots = new ArrayList<>();
      for (String root1 : roots) {
        if (safeRelative(root1) && safeRoots.size() < 32) safeRoots.add(root1);
      }
      if (safeRoots.isEmpty()) safeRoots.add("src/main/java");
      return new CaptureConfig(new ApplicationScope(packages, safeRoots));
    } catch (RuntimeException invalid) {
      return defaults();
    }
  }

  /** A repo-relative directory: no absolute path, no parent segments, no control characters. */
  static boolean safeRelative(String value) {
    if (value == null || value.isEmpty() || value.length() > 256 || value.startsWith("/")) {
      return false;
    }
    for (String segment : value.split("/", -1)) {
      if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c < ' ' || c == 0x7f || c == '\\') return false;
    }
    return true;
  }

  private static List<String> strings(Object value) {
    List<String> result = new ArrayList<>();
    if (value instanceof List<?> list) {
      for (Object item : list) {
        if (item instanceof String text) result.add(text);
      }
    }
    return result;
  }

  private static boolean ownerOnly(Path file) throws IOException {
    try {
      Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file);
      return permissions.stream()
          .noneMatch(
              p ->
                  p == PosixFilePermission.GROUP_READ
                      || p == PosixFilePermission.GROUP_WRITE
                      || p == PosixFilePermission.GROUP_EXECUTE
                      || p == PosixFilePermission.OTHERS_READ
                      || p == PosixFilePermission.OTHERS_WRITE
                      || p == PosixFilePermission.OTHERS_EXECUTE);
    } catch (UnsupportedOperationException notPosix) {
      return true;
    }
  }

  /** Minimal bounded JSON reader: objects, arrays, strings, integers, booleans, null. */
  private static final class MiniJson {
    private final String text;
    private int index;
    private int depth;

    MiniJson(String text) {
      this.text = text;
    }

    Object parse() {
      Object value = value();
      skip();
      if (index != text.length()) throw new IllegalArgumentException();
      return value;
    }

    private Object value() {
      skip();
      if (index >= text.length()) throw new IllegalArgumentException();
      char c = text.charAt(index);
      if (c == '{') return object();
      if (c == '[') return array();
      if (c == '"') return string();
      if (text.startsWith("true", index)) {
        index += 4;
        return Boolean.TRUE;
      }
      if (text.startsWith("false", index)) {
        index += 5;
        return Boolean.FALSE;
      }
      if (text.startsWith("null", index)) {
        index += 4;
        return null;
      }
      return number();
    }

    private Object object() {
      if (++depth > 8) throw new IllegalArgumentException();
      index++;
      java.util.LinkedHashMap<String, Object> map = new java.util.LinkedHashMap<>();
      skip();
      if (peek() == '}') {
        index++;
        depth--;
        return map;
      }
      while (true) {
        skip();
        String key = string();
        skip();
        expect(':');
        map.put(key, value());
        skip();
        char c = next();
        if (c == '}') break;
        if (c != ',') throw new IllegalArgumentException();
        if (map.size() > 64) throw new IllegalArgumentException();
      }
      depth--;
      return map;
    }

    private Object array() {
      if (++depth > 8) throw new IllegalArgumentException();
      index++;
      List<Object> list = new ArrayList<>();
      skip();
      if (peek() == ']') {
        index++;
        depth--;
        return list;
      }
      while (true) {
        list.add(value());
        if (list.size() > 256) throw new IllegalArgumentException();
        skip();
        char c = next();
        if (c == ']') break;
        if (c != ',') throw new IllegalArgumentException();
      }
      depth--;
      return list;
    }

    private String string() {
      expect('"');
      StringBuilder out = new StringBuilder();
      while (true) {
        char c = next();
        if (c == '"') return out.toString();
        if (c < ' ') throw new IllegalArgumentException();
        if (c == '\\') {
          char e = next();
          switch (e) {
            case '"', '\\', '/' -> out.append(e);
            case 'n' -> out.append('\n');
            case 't' -> out.append('\t');
            case 'r' -> out.append('\r');
            case 'b' -> out.append('\b');
            case 'f' -> out.append('\f');
            case 'u' -> {
              if (index + 4 > text.length()) throw new IllegalArgumentException();
              out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
              index += 4;
            }
            default -> throw new IllegalArgumentException();
          }
        } else {
          out.append(c);
        }
        if (out.length() > 1024) throw new IllegalArgumentException();
      }
    }

    private Object number() {
      int start = index;
      if (peek() == '-') index++;
      while (index < text.length() && Character.isDigit(text.charAt(index))) index++;
      if (index == start || index - start > 18) throw new IllegalArgumentException();
      return Long.parseLong(text.substring(start, index));
    }

    private void skip() {
      while (index < text.length() && " \t\r\n".indexOf(text.charAt(index)) >= 0) index++;
    }

    private char peek() {
      if (index >= text.length()) throw new IllegalArgumentException();
      return text.charAt(index);
    }

    private char next() {
      char c = peek();
      index++;
      return c;
    }

    private void expect(char expected) {
      if (next() != expected) throw new IllegalArgumentException();
    }
  }
}
