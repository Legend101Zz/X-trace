package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyCaptureTest {
  @TempDir Path scratch;

  @Test
  void productionTransformerCapturesActualJdkProxiesAcrossTheCorpus() throws Exception {
    ProbeResult result = runProbe();
    assertEquals(0, result.exitCode(), result.text());
    assertTrue(result.text().contains("proxy-capture-cases=18"), result.text());
    assertTrue(result.text().contains("\"result\":\"transformed\""), result.text());
    assertTrue(result.text().contains("\"result\":\"resolved\""), result.text());
  }

  @Test
  void attachRetransformsSpringStyleProxyCreatedBeforeTheTransformerWasInstalled() throws Exception {
    ProbeResult result = runProbe(true);
    assertEquals(0, result.exitCode(), result.text());
    assertTrue(result.text().contains("preloaded-proxy-capture-cases=1"), result.text());
    assertTrue(result.text().contains("proxy-capture-cases=18"), result.text());
  }

  @Test
  void probePrintsItsFailureReasonBeforeExitingNonZero() throws Exception {
    ProbeResult result = runProbe("unexpected-argument");
    assertEquals(1, result.exitCode(), result.text());
    assertTrue(result.text().contains("proxy-capture-probe failed"), result.text());
    assertTrue(result.text().contains("java.lang.IllegalArgumentException: proxy capture probe accepts no arguments"),
        result.text());
    assertTrue(result.text().contains("ProxyCaptureProbe.main"), result.text());
  }

  @Test
  void failureListenerOnlyStopsCaptureForGeneratedProxyNamesAndContainsCallbackFailures() {
    AtomicInteger failures = new AtomicInteger();
    ClassLoader loader = getClass().getClassLoader();
    var error = new IllegalStateException("unresolvable in-memory superclass");
    var listener = new ProxyInstrumentation.FailureListener(cause -> {
      assertSame(error, cause);
      failures.incrementAndGet();
    });
    listener.onError("demo.proxy.MemoryChild", loader, null, false, error);
    listener.onError("demo.proxy.User$ProxyHelper", loader, null, false, error);
    assertEquals(0, failures.get());
    listener.onError("jdk.proxy2.$Proxy7", loader, null, false, error);
    listener.onError("demo.proxy.$Proxy8", loader, null, false, error);
    assertEquals(2, failures.get());
    var throwing = new ProxyInstrumentation.FailureListener(cause -> { throw new IllegalStateException(); });
    assertDoesNotThrow(() -> throwing.onError("jdk.proxy2.$Proxy7", loader, null, false, error));
  }

  private record ProbeResult(int exitCode, String text) {}

  private ProbeResult runProbe(String... arguments) throws Exception {
    return runProbe(false, arguments);
  }

  private ProbeResult runProbe(boolean attach, String... arguments) throws Exception {
    Path agent = scratch.resolve("proxy-probe-agent.jar");
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Premain-Class", ProxyProbeAgent.class.getName());
    manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(agent), manifest)) {
      String resource = ProxyProbeAgent.class.getName().replace('.', '/') + ".class";
      jar.putNextEntry(new JarEntry(resource));
      try (var stream = getClass().getClassLoader().getResourceAsStream(resource)) {
        java.util.Objects.requireNonNull(stream).transferTo(jar);
      }
      jar.closeEntry();
    }
    Path bridge = Path.of(dev.xtrace.agent.bootstrap.BootstrapBridge.class
        .getProtectionDomain().getCodeSource().getLocation().toURI());
    Path output = scratch.resolve("proxy-probe-output.txt");
    List<String> command = new ArrayList<>(List.of(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-Xverify:all", "-Xbootclasspath/a:" + bridge, "-javaagent:" + agent,
        "-Dxtrace.proxy.probe.attach=" + attach,
        "-Dxtrace.agent.recordingDiagnostics=true",
        "-cp", System.getProperty("java.class.path"), ProxyCaptureProbe.class.getName()));
    command.addAll(List.of(arguments));
    Process process = new ProcessBuilder(command)
        .redirectErrorStream(true).redirectOutput(output.toFile()).start();
    try {
      boolean finished = process.waitFor(60, TimeUnit.SECONDS);
      String text = Files.readString(output, StandardCharsets.UTF_8);
      assertTrue(finished, "proxy capture probe timed out\n" + text);
      return new ProbeResult(process.exitValue(), text);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }
}
