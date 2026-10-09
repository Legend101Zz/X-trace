package dev.xtrace.agent.runtime;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.jar.asm.Type;
import org.bouncycastle.crypto.digests.Blake3Digest;

/**
 * Verifies the exact class bytes presented to instrumentation against the
 * fixture build map.
 */
final class SourceAttestation {
  private static final String RESOURCE =
      "META-INF/xtrace/source-attestation.tsv";
  private static final Map<ClassLoader, State> STATES = new WeakHashMap<>();

  private SourceAttestation() {}

  static void observe(ClassLoader loader, String internalName,
                      byte[] classBytes) {
    if (loader == null || internalName == null || classBytes == null)
      return;
    synchronized (STATES) {
      State state = state(loader);
      String name = internalName.replace('/', '.');
      boolean found = false;
      for (Entry entry : state.entries.values()) {
        if (!entry.className.equals(name))
          continue;
        found = true;
        entry.classObserved = true;
        entry.classMatches = classBytes.length <= 8 * 1024 * 1024 &&
                             hex(blake3(classBytes)).equals(entry.classHash);
      }
      if (!found && state.failure == 0)
        state.failure = 2;
    }
  }

  static SourceInfo lookup(ClassLoader loader, Method method) {
    if (loader == null || method == null)
      return SourceInfo.unavailable(2);
    synchronized (STATES) {
      State state = state(loader);
      Entry entry = state.entries.get(key(method.getDeclaringClass().getName(),
                                          method.getName(),
                                          Type.getMethodDescriptor(method)));
      if (entry == null)
        return SourceInfo.unavailable(state.failure == 0 ? 2 : state.failure);
      if (!entry.classObserved)
        return SourceInfo.unavailable(2);
      if (!entry.classMatches)
        return SourceInfo.unavailable(3);
      if (entry.startLine < 1 || entry.endLine < entry.startLine)
        return SourceInfo.unavailable(4);
      return new SourceInfo(entry.path, entry.startLine, entry.endLine,
                            unhex(entry.sourceHash), 1);
    }
  }

  /** True when the fixture build map names this class, so a build attestation can apply. */
  static boolean hasEntry(String className) {
    return className.equals("dev.xtrace.fixture.OrderController")
        || className.equals("dev.xtrace.fixture.OrderService")
        || className.equals("dev.xtrace.fixture.OrderRepository");
  }

  static SourceInfo lookup(ClassLoader loader, String className, String method,
                           String descriptor) {
    if (loader == null || className == null)
      return SourceInfo.unavailable(2);
    synchronized (STATES) {
      State state = state(loader);
      Entry entry = state.entries.get(key(className, method, descriptor));
      if (entry == null)
        return SourceInfo.unavailable(state.failure == 0 ? 2 : state.failure);
      if (!entry.classObserved)
        return SourceInfo.unavailable(2);
      if (!entry.classMatches)
        return SourceInfo.unavailable(3);
      if (entry.startLine < 1 || entry.endLine < entry.startLine)
        return SourceInfo.unavailable(4);
      return new SourceInfo(entry.path, entry.startLine, entry.endLine,
                            unhex(entry.sourceHash), 1);
    }
  }

  private static State state(ClassLoader loader) {
    State existing = STATES.get(loader);
    if (existing != null)
      return existing;
    State state = new State();
    STATES.put(loader, state);
    try (var stream = loader.getResourceAsStream(RESOURCE)) {
      if (stream == null) {
        state.failure = 2;
        return state;
      }
      byte[] manifest = stream.readNBytes(64 * 1024 + 1);
      if (manifest.length > 64 * 1024)
        throw new IllegalArgumentException();
      String contents = new String(manifest, StandardCharsets.UTF_8);
      try (var reader =
               new java.io.BufferedReader(new java.io.StringReader(contents))) {
        String line;
        int count = 0;
        while ((line = reader.readLine()) != null) {
          if (++count > 16 || line.length() > 1024)
            throw new IllegalArgumentException();
          String[] fields = line.split("\\t", -1);
          if (fields.length != 7)
            throw new IllegalArgumentException();
          String path = fields[3];
          if (!allowed(fields[0], fields[1], path) || !validHash(fields[4]) ||
              !validHash(fields[5]))
            throw new IllegalArgumentException();
          String[] range = fields[6].split(":", -1);
          if (range.length != 2)
            throw new IllegalArgumentException();
          int start = Integer.parseInt(range[0]);
          int end = range.length == 2 ? Integer.parseInt(range[1]) : start;
          if ((start == 0 && end != 0) || (start > 0 && end < start))
            throw new IllegalArgumentException();
          Entry entry = new Entry(fields[0], fields[1], fields[2], path,
                                  fields[4], fields[5], start, end);
          if (state.entries.put(
                  key(entry.className, entry.methodName, entry.descriptor),
                  entry) != null)
            throw new IllegalArgumentException();
        }
        if (count == 0)
          throw new IllegalArgumentException();
      }
    } catch (Exception invalid) {
      state.entries.clear();
      state.failure = 5;
    }
    return state;
  }

  private static boolean allowed(String className, String method, String path) {
    return className.equals("dev.xtrace.fixture.OrderController") &&
        method.equals("create") &&
        path.equals("adapters/java/spring-fixture/src/main/java/dev/xtrace/" +
                    "fixture/OrderController.java") ||
        className.equals("dev.xtrace.fixture.OrderService") &&
            method.equals("place") &&
            path.equals("adapters/java/spring-fixture/src/main/java/dev/" +
                        "xtrace/fixture/OrderService.java") ||
        className.equals("dev.xtrace.fixture.OrderRepository") &&
            method.equals("save") &&
            path.equals("adapters/java/spring-fixture/src/main/java/dev/" +
                        "xtrace/fixture/OrderRepository.java");
  }

  private static String key(String type, String method, String descriptor) {
    return type + "#" + method + descriptor;
  }
  private static boolean validHash(String value) {
    return value.length() == 64 && value.matches("[0-9a-f]{64}");
  }
  static byte[] blake3Of(byte[] value) { return blake3(value); }
  private static byte[] blake3(byte[] value) {
    Blake3Digest d = new Blake3Digest(256);
    d.update(value, 0, value.length);
    byte[] out = new byte[32];
    d.doFinal(out, 0);
    return out;
  }
  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(64);
    for (byte b : bytes)
      out.append(String.format("%02x", b & 255));
    return out.toString();
  }
  private static byte[] unhex(String value) {
    byte[] out = new byte[32];
    for (int i = 0; i < 32; i++)
      out[i] = (byte)Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    return out;
  }

  record SourceInfo(String path, int startLine, int endLine, byte[] hash,
                    int binding) {
    static SourceInfo unavailable(int binding) {
      return new SourceInfo(null, 0, 0, null, binding);
    }
  }
  private static final class State {
    final Map<String, Entry> entries = new HashMap<>();
    int failure;
  }
  private static final class Entry {
    final String className, methodName, descriptor, path, classHash, sourceHash;
    final int startLine, endLine;
    boolean classObserved, classMatches;
    Entry(String c, String m, String d, String p, String ch, String sh, int s,
          int e) {
      className = c;
      methodName = m;
      descriptor = d;
      path = p;
      classHash = ch;
      sourceHash = sh;
      startLine = s;
      endLine = e;
    }
  }
}
