package dev.xtrace.agent.bootstrap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Privacy-safe observed method identity shared by boundary and cursor emission. */
public final class MethodIdentity {
  private MethodIdentity() {}

  /**
   * Keeps the readable simple name and hashes the declaring binary name, method and JVM descriptor.
   * No descriptor text, application object or captured value enters the symbol. A missing descriptor
   * cannot establish an identity. The suffix is versioned so consumers can reject unknown formats.
   */
  public static String symbol(String binaryName, String method, String descriptor) {
    if (binaryName == null || method == null || descriptor == null || descriptor.isEmpty()) return null;
    String readable = binaryName.substring(binaryName.lastIndexOf('.') + 1) + "." + method;
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(binaryName.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      digest.update(method.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      String hash = HexFormat.of().formatHex(digest.digest(descriptor.getBytes(StandardCharsets.UTF_8)));
      // BootstrapBridge's symbol bound is 200 characters, including the complete identity suffix.
      return readable.substring(0, Math.min(readable.length(), 131)) + "#m1:" + hash;
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 unavailable", impossible);
    }
  }
}
