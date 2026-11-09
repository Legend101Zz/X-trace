package dev.xtrace.agent.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;

/** Opt-in, bounded metadata for diagnosing missing proxy boundaries; never reads call values. */
final class ProxyDiagnostics {
  private static final boolean ENABLED = Boolean.getBoolean("xtrace.agent.recordingDiagnostics");
  private static final AtomicInteger ROWS = new AtomicInteger();
  private static final int MAX_ROWS = 128;

  private ProxyDiagnostics() {}

  static void report(String proxy, String invocation, String declaration, String result) {
    if (!ENABLED || ROWS.getAndUpdate(count -> Math.min(MAX_ROWS, count + 1)) >= MAX_ROWS) return;
    try {
      System.err.println(row(proxy, invocation, declaration, result));
    } catch (RuntimeException | LinkageError ignored) {
      // Diagnostics must not affect transformation or capture.
    }
  }

  static void resolution(Class<?> proxy, java.lang.reflect.Method method, String declaration, String result) {
    if (!ENABLED) return;
    try {
      report(proxy.getName(), method.getName() + net.bytebuddy.jar.asm.Type.getMethodDescriptor(method), declaration, result);
    } catch (RuntimeException | LinkageError ignored) {
      // Resolving diagnostic metadata must not change a proxy call either.
    }
  }

  static String row(String proxy, String invocation, String declaration, String result) {
    if (!java.util.Set.of("transformed", "transform_failed", "resolved", "no_declaration", "resolution_failed")
        .contains(result)) throw new IllegalArgumentException("unknown diagnostic result");
    return "{\"code\":\"XTR-JAVA-PROXY-DIAGNOSTIC\",\"proxyHash\":\"" + hash(proxy)
        + "\",\"invocationHash\":" + nullableHash(invocation) + ",\"declarationHash\":" + nullableHash(declaration)
        + ",\"result\":\"" + result + "\"}";
  }

  private static String nullableHash(String value) {
    return value == null ? "null" : "\"" + hash(value) + "\"";
  }

  private static String hash(String value) {
    try {
      return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 is required by the JDK", impossible);
    }
  }
}
