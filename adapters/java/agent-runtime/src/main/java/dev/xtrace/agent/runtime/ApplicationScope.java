package dev.xtrace.agent.runtime;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.List;

/**
 * Decides which loaded classes are application code. Scope comes from the launcher's
 * {@code capture.json} application packages; without packages, classes loaded from a Spring Boot
 * fat jar's {@code BOOT-INF/classes} are application code. The deny set is fixed: it cannot be
 * overridden by configuration, and dependency jars are never application roots.
 */
final class ApplicationScope {
  /** Verdict for a type that is application code. */
  static final int APPLICATION = 1;

  /** Verdict for a type that is framework, dependency or agent code. */
  static final int NOT_APPLICATION = 0;

  /** Verdict when no scope is configured and the type's origin does not identify it. */
  static final int UNKNOWN = -1;

  /** Package prefixes that are never application code, whatever the configuration says. */
  static final List<String> DENY_PREFIXES =
      List.of(
          "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.", "dev.xtrace.agent.",
          "dev.xtrace.adapter.", "net.bytebuddy.", "org.bouncycastle.", "com.google.protobuf.",
          "org.slf4j.", "ch.qos.logback.", "org.apache.logging.");

  private static final int MAX_PACKAGES = 64;
  private static final int MAX_PACKAGE_BYTES = 256;
  private static final String BOOT_CLASSES = "BOOT-INF/classes";
  private static final String BOOT_LIB = "BOOT-INF/lib/";

  private final List<String> packages;
  private final List<String> sourceRoots;

  ApplicationScope(List<String> packages, List<String> sourceRoots) {
    this.packages = sanitizePackages(packages);
    this.sourceRoots = List.copyOf(sourceRoots);
  }

  /** Scope used when the launcher supplied none: fat-jar application classes only. */
  static ApplicationScope defaultScope() {
    return new ApplicationScope(List.of(), List.of("src/main/java"));
  }

  List<String> packages() {
    return packages;
  }

  List<String> sourceRoots() {
    return sourceRoots;
  }

  boolean configured() {
    return !packages.isEmpty();
  }

  /** True when the class should receive method boundary probes. */
  boolean isApplication(String className, ProtectionDomain domain) {
    return verdict(className, domain) == APPLICATION;
  }

  /** Verdict for a loaded type, used to decide whether a handler is application code. */
  int verdict(Class<?> type) {
    if (type == null) return UNKNOWN;
    return verdict(type.getName(), type.getProtectionDomain());
  }

  int verdict(String className, ProtectionDomain domain) {
    if (className == null || className.isEmpty() || denied(className) || generated(className)) {
      return NOT_APPLICATION;
    }
    String location = location(domain);
    if (location != null && location.contains(BOOT_LIB)) return NOT_APPLICATION;
    if (configured()) {
      return matchesPackage(className) ? APPLICATION : NOT_APPLICATION;
    }
    if (location != null && location.contains(BOOT_CLASSES)) return APPLICATION;
    return UNKNOWN;
  }

  static boolean denied(String className) {
    for (String prefix : DENY_PREFIXES) {
      if (className.startsWith(prefix)) return true;
    }
    return false;
  }

  /** Proxies and generated classes carry no source and would duplicate their target's frames. */
  static boolean generated(String className) {
    return className.contains("$$")
        || className.contains("$Proxy")
        || className.contains("CGLIB")
        || className.contains("ByteBuddy")
        || className.contains("$HibernateProxy")
        || className.contains("$Lambda");
  }

  private boolean matchesPackage(String className) {
    for (String prefix : packages) {
      if (className.startsWith(prefix + ".")) return true;
    }
    return false;
  }

  private static List<String> sanitizePackages(List<String> requested) {
    java.util.ArrayList<String> accepted = new java.util.ArrayList<>();
    for (String value : requested) {
      if (accepted.size() >= MAX_PACKAGES) break;
      if (!validPackage(value)) continue;
      // A configured prefix inside the deny set is dropped, never honored.
      if (denied(value + ".")) continue;
      if (!accepted.contains(value)) accepted.add(value);
    }
    return List.copyOf(accepted);
  }

  static boolean validPackage(String value) {
    if (value == null || value.isEmpty() || value.length() > MAX_PACKAGE_BYTES) return false;
    boolean segmentStart = true;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '.') {
        if (segmentStart) return false;
        segmentStart = true;
      } else if (segmentStart ? Character.isJavaIdentifierStart(c) : Character.isJavaIdentifierPart(c)) {
        segmentStart = false;
      } else {
        return false;
      }
    }
    return !segmentStart;
  }

  private static String location(ProtectionDomain domain) {
    if (domain == null) return null;
    CodeSource source = domain.getCodeSource();
    URL url = source == null ? null : source.getLocation();
    return url == null ? null : url.toString();
  }
}
