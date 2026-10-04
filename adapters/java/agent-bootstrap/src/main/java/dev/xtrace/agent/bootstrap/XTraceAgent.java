package dev.xtrace.agent.bootstrap;

import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;

/** Fixture-bounded Java premain and explicit attach agent entrypoint. */
public final class XTraceAgent {
  private static final String RUNTIME_ENTRY = "dev.xtrace.agent.runtime.AgentRuntime";
  private static final AtomicInteger START_STATE = new AtomicInteger();
  private static volatile byte[] activeIdentity;
  private static volatile ClassLoader activeLoader;

  private XTraceAgent() {}

  /** Starts the private agent runtime. Setup failure leaves the application running. */
  public static void premain(String agentArgument, Instrumentation instrumentation) {
    try {
      start(agentArgument, instrumentation, false);
    } catch (InvocationTargetException error) {
      rethrowFatal(error.getCause());
      reportUnavailable();
    } catch (Exception | LinkageError error) {
      rethrowFatal(error);
      reportUnavailable();
    }
  }

  /** Starts the bounded fixture attach path after the target JVM has already started. */
  public static void agentmain(String agentArgument, Instrumentation instrumentation)
      throws Exception {
    if (START_STATE.get() == 2) {
      throw new Exception("XTR-JAVA-AGENT-RELAUNCH-REQUIRED");
    }
    AgentOptions options = parseAttachOptions(agentArgument);
    validateSnapshot(options.snapshotRoot());
    String bootstrapPath = options.bootstrapPath();
    if (START_STATE.get() == 1) {
      boolean same = sameActiveIdentity(bootstrapPath);
      if (same) return;
      throw new Exception("XTR-JAVA-AGENT-ALREADY-ACTIVE-ELSEWHERE");
    }
    if (START_STATE.get() == 2) {
      throw new Exception("XTR-JAVA-AGENT-RELAUNCH-REQUIRED");
    }
    try {
      start(bootstrapPath, instrumentation, true);
    } catch (InvocationTargetException error) {
      Throwable cause = error.getCause();
      rethrowFatal(cause);
      boolean permanent = START_STATE.get() == 2 || failurePermanent(cause);
      if (permanent) START_STATE.set(2);
      else if (START_STATE.get() != 1) START_STATE.set(0);
      throw new Exception(
          permanent
              ? "XTR-JAVA-AGENT-INITIALIZATION-PARTIAL-RELAUNCH-REQUIRED"
              : "XTR-JAVA-AGENT-INITIALIZATION-RETRYABLE");
    } catch (Exception | LinkageError error) {
      rethrowFatal(error);
      boolean permanent = START_STATE.get() == 2;
      if (!permanent && START_STATE.get() != 1) START_STATE.set(0);
      throw new Exception(
          permanent
              ? "XTR-JAVA-AGENT-INITIALIZATION-PARTIAL-RELAUNCH-REQUIRED"
              : "XTR-JAVA-AGENT-INITIALIZATION-RETRYABLE");
    }
  }

  private static synchronized void start(
      String agentArgument, Instrumentation instrumentation, boolean attach) throws Exception {
    if (attach && START_STATE.get() == 1) {
      boolean same = sameActiveIdentity(parseBootstrapPath(agentArgument));
      if (same) return;
      throw new IllegalStateException("XTR-JAVA-AGENT-ALREADY-ACTIVE-ELSEWHERE");
    }
    if (attach && START_STATE.get() == 2) {
      throw new IllegalStateException("XTR-JAVA-AGENT-RELAUNCH-REQUIRED");
    }
    if (START_STATE.get() != 0) {
      throw new IllegalStateException("XTR-JAVA-AGENT-START-IN-PROGRESS");
    }

    String bootstrapPath = parseBootstrapPath(agentArgument);
    Path agentJar = ownJar();
    URL[] runtime = runtimeUrls(agentJar.getParent().resolve("runtime"));
    PrivateAgentClassLoader loader = new PrivateAgentClassLoader(runtime);
    Class<?> entry = null;
    byte[] identity = null;
    boolean keepLoader = false;
    boolean permanentFailure = false;
    boolean irreversibleMutationStarted = false;
    try {
      entry = Class.forName(RUNTIME_ENTRY, true, loader);
      identity = (byte[]) entry
          .getMethod("prepareBootstrap", String.class, Instrumentation.class, boolean.class)
          .invoke(null, bootstrapPath, instrumentation, attach);
      if (!START_STATE.compareAndSet(0, -1)) {
        throw new IllegalStateException("XTR-JAVA-AGENT-START-IN-PROGRESS");
      }
      irreversibleMutationStarted = true;
      keepLoader = true;
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(agentJar.toFile(), false));
      Class.forName("dev.xtrace.agent.bootstrap.BootstrapBridge", true, null);
      byte[] startedIdentity;
      try {
        startedIdentity = (byte[]) entry
            .getMethod(
                "start", String.class, Instrumentation.class, boolean.class, byte[].class)
            .invoke(null, bootstrapPath, instrumentation, attach, identity);
      } catch (InvocationTargetException error) {
        permanentFailure = irreversibleMutationStarted || failurePermanent(error.getCause());
        keepLoader = permanentFailure;
        throw error;
      }
      keepLoader = true;
      if (!MessageDigest.isEqual(identity, startedIdentity)) {
        Arrays.fill(startedIdentity, (byte) 0);
        START_STATE.set(2);
        throw new IllegalStateException("XTR-JAVA-AGENT-BOOTSTRAP-CHANGED");
      }
      activeIdentity = identity.clone();
      activeLoader = loader;
      START_STATE.set(1);
    } finally {
      if (identity != null) Arrays.fill(identity, (byte) 0);
      finishFailedStart(permanentFailure || irreversibleMutationStarted);
      if (!keepLoader) {
        try {
          loader.close();
        } catch (IOException ignored) {
          // Preflight or pre-install failure has no active transformer to retain.
        }
      }
    }
  }

  static void finishFailedStart(boolean permanentFailure) {
    if (START_STATE.get() == -1) START_STATE.set(permanentFailure ? 2 : 0);
  }

  private static AgentOptions parseAttachOptions(String argument) {
    final String prefix = "xtrace-attach-v1:";
    if (argument == null || argument.length() > 16 * 1024 || !argument.startsWith(prefix)) {
      throw new IllegalArgumentException("bounded attach options are required");
    }
    String[] parts = argument.substring(prefix.length()).split("\\.", -1);
    if (parts.length != 2) throw new IllegalArgumentException("bounded attach options are malformed");
    byte[] bootstrapBytes = null;
    byte[] snapshotBytes = null;
    try {
      bootstrapBytes = Base64.getUrlDecoder().decode(parts[0]);
      snapshotBytes = Base64.getUrlDecoder().decode(parts[1]);
      String bootstrap = decodeUtf8(bootstrapBytes);
      String snapshot = decodeUtf8(snapshotBytes);
      Path bootstrapPath = Path.of(parseBootstrapPath(bootstrap)).toAbsolutePath().normalize();
      Path snapshotPath = Path.of(snapshot).toAbsolutePath().normalize();
      if (!Path.of(snapshot).isAbsolute()) throw new IllegalArgumentException("snapshot path must be absolute");
      return new AgentOptions(bootstrapPath.toString(), snapshotPath);
    } catch (java.nio.charset.CharacterCodingException error) {
      throw new IllegalArgumentException("bounded attach options are not valid UTF-8");
    } finally {
      if (bootstrapBytes != null) Arrays.fill(bootstrapBytes, (byte) 0);
      if (snapshotBytes != null) Arrays.fill(snapshotBytes, (byte) 0);
    }
  }

  private static String decodeUtf8(byte[] bytes) throws java.nio.charset.CharacterCodingException {
    return java.nio.charset.StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(bytes))
        .toString();
  }

  private record AgentOptions(String bootstrapPath, Path snapshotRoot) {}

  private static boolean sameActiveIdentity(String bootstrapPath) throws Exception {
    ClassLoader loader = activeLoader;
    byte[] expected = activeIdentity;
    if (loader == null || expected == null) return false;
    Class<?> entry = Class.forName(RUNTIME_ENTRY, true, loader);
    byte[] actual = (byte[]) entry.getMethod("bootstrapIdentity", String.class).invoke(null, bootstrapPath);
    try {
      return MessageDigest.isEqual(expected, actual);
    } finally {
      Arrays.fill(actual, (byte) 0);
    }
  }

  private static boolean failurePermanent(Throwable error) {
    if (error == null) return false;
    try {
      return Boolean.TRUE.equals(error.getClass().getMethod("permanent").invoke(error));
    } catch (ReflectiveOperationException ignored) {
      return false;
    }
  }

  private static void rethrowFatal(Throwable error) {
    if (error instanceof VirtualMachineError fatal) throw fatal;
    if (error instanceof ThreadDeath death) throw death;
  }

  static String parseBootstrapPath(String argument) {
    if (argument == null || argument.isBlank() || argument.indexOf('\0') >= 0) {
      throw new IllegalArgumentException("bootstrap path is required");
    }
    return Path.of(argument).toString();
  }

  private static Path ownJar() throws URISyntaxException {
    CodeSource source = XTraceAgent.class.getProtectionDomain().getCodeSource();
    if (source == null) throw new IllegalStateException("agent code source is unavailable");
    Path path = Path.of(source.getLocation().toURI()).toAbsolutePath().normalize();
    if (!Files.isRegularFile(path)) throw new IllegalStateException("agent must run from a jar");
    return path;
  }

  private static URL[] runtimeUrls(Path directory) throws IOException {
    if (!Files.isDirectory(directory)) {
      throw new IOException("private runtime directory is unavailable");
    }
    try (var entries = Files.list(directory)) {
      return entries
          .filter(path -> Files.isRegularFile(path) && path.getFileName().toString().endsWith(".jar"))
          .sorted(Comparator.comparing(path -> path.getFileName().toString()))
          .map(XTraceAgent::toUrl)
          .toArray(URL[]::new);
    }
  }

  private static URL toUrl(Path path) {
    try {
      return path.toUri().toURL();
    } catch (IOException error) {
      throw new IllegalStateException("private runtime path is invalid", error);
    }
  }

  private static void validateSnapshot(Path snapshot) throws IOException {
    Path cache = snapshot.getParent();
    if (!snapshot.isAbsolute()
        || cache == null
        || !"xtrace-attach-snapshots".equals(cache.getFileName().toString())
        || !snapshot.getFileName().toString().matches("target-[1-9][0-9]{0,9}-[0-9a-f-]{36}")
        || Files.isSymbolicLink(cache)
        || Files.isSymbolicLink(snapshot)
        || !Files.isDirectory(snapshot, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("private attach snapshot is unavailable");
    }
    cache = cache.toRealPath(LinkOption.NOFOLLOW_LINKS);
    Path canonical = snapshot.toRealPath(LinkOption.NOFOLLOW_LINKS);
    String owner = ProcessHandle.current().info().user().orElse("");
    if (!canonical.getParent().equals(cache)
        || !Files.getOwner(cache, LinkOption.NOFOLLOW_LINKS).getName().equals(owner)
        || !Files.getOwner(snapshot, LinkOption.NOFOLLOW_LINKS).getName().equals(owner)) {
      throw new IOException("private attach snapshot ownership is unavailable");
    }
    int cacheMode = ((Number) Files.getAttribute(cache, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
    int snapshotMode = ((Number) Files.getAttribute(snapshot, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
    if ((cacheMode & 0077) != 0 || (snapshotMode & 0077) != 0
        || !snapshotLeaseMatches(snapshot, ProcessHandle.current().pid(),
            ProcessHandle.current().info().startInstant().orElseThrow().toEpochMilli())) {
      throw new IOException("private attach snapshot lease is invalid");
    }
  }

  private static boolean snapshotLeaseMatches(Path snapshot, long pid, long started) {
    byte[] leaseBytes = null;
    try {
      if (Files.isSymbolicLink(snapshot)
          || !Files.isDirectory(snapshot, LinkOption.NOFOLLOW_LINKS)
          || !Files.getOwner(snapshot, LinkOption.NOFOLLOW_LINKS).getName()
              .equals(ProcessHandle.current().info().user().orElse(""))) return false;
      int directoryMode = ((Number) Files.getAttribute(snapshot, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
      if ((directoryMode & 0077) != 0) return false;
      Path lease = snapshot.resolve("snapshot.lease");
      var attributes = Files.readAttributes(lease, "unix:nlink,mode", LinkOption.NOFOLLOW_LINKS);
      if (!Files.isRegularFile(lease, LinkOption.NOFOLLOW_LINKS)
          || Files.isSymbolicLink(lease)
          || ((Number) attributes.get("nlink")).longValue() != 1
          || ((((Number) attributes.get("mode")).intValue()) & 0077) != 0
          || Files.size(lease) > 128) return false;
      try (InputStream input = Files.newInputStream(lease, LinkOption.NOFOLLOW_LINKS)) {
        leaseBytes = input.readNBytes(129);
        if (leaseBytes.length > 128 || input.read() != -1) return false;
      }
      String[] values = new String(leaseBytes, java.nio.charset.StandardCharsets.US_ASCII).split("\\n");
      return values.length == 2
          && values[0].equals(Long.toString(pid))
          && values[1].equals(Long.toString(started));
    } catch (IOException | RuntimeException ignored) {
      return false;
    } finally {
      if (leaseBytes != null) Arrays.fill(leaseBytes, (byte) 0);
    }
  }

  private static void reportUnavailable() {
    System.err.println(
        "{\"code\":\"XTR-JAVA-AGENT-UNAVAILABLE\",\"message\":\"X-trace capture is unavailable; application startup continues\"}");
  }
}
