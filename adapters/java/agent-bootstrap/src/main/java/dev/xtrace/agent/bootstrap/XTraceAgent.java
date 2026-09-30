package dev.xtrace.agent.bootstrap;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.Comparator;
import java.util.jar.JarFile;

/** Launch-only experimental Java agent entrypoint. */
public final class XTraceAgent {
  private static final String RUNTIME_ENTRY = "dev.xtrace.agent.runtime.AgentRuntime";

  private XTraceAgent() {}

  /**
   * Starts the private agent runtime. Any supported setup or instrumentation failure leaves the
   * application running and emits only a bounded non-sensitive diagnostic.
   */
  public static void premain(String agentArgument, Instrumentation instrumentation) {
    try {
      String bootstrapPath = parseBootstrapPath(agentArgument);
      Path agentJar = ownJar();
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(agentJar.toFile(), false));
      Class.forName("dev.xtrace.agent.bootstrap.BootstrapBridge", true, null);
      URL[] runtime = runtimeUrls(agentJar.getParent().resolve("runtime"));
      PrivateAgentClassLoader loader = new PrivateAgentClassLoader(runtime);
      Class<?> entry = Class.forName(RUNTIME_ENTRY, true, loader);
      entry.getMethod("start", String.class, Instrumentation.class)
          .invoke(null, bootstrapPath, instrumentation);
    } catch (InvocationTargetException error) {
      Throwable cause = error.getCause();
      if (cause instanceof VirtualMachineError fatal) throw fatal;
      if (cause instanceof ThreadDeath death) throw death;
      reportUnavailable();
    } catch (Exception | LinkageError error) {
      reportUnavailable();
    }
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

  private static void reportUnavailable() {
    System.err.println(
        "{\"code\":\"XTR-JAVA-AGENT-UNAVAILABLE\",\"message\":\"X-trace capture is unavailable; application startup continues\"}");
  }
}
