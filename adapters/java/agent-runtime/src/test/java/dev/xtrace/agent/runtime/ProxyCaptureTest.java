package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
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
    Path agent = scratch.resolve("proxy-probe-agent.jar");
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Premain-Class", ProxyProbeAgent.class.getName());
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
    Process process = new ProcessBuilder(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-Xverify:all", "-Xbootclasspath/a:" + bridge, "-javaagent:" + agent,
        "-cp", System.getProperty("java.class.path"), ProxyCaptureProbe.class.getName())
        .redirectErrorStream(true).redirectOutput(output.toFile()).start();
    try {
      assertTrue(process.waitFor(60, TimeUnit.SECONDS), "proxy capture probe timed out");
      String text = Files.readString(output, StandardCharsets.UTF_8);
      assertEquals(0, process.exitValue(), text);
      assertTrue(text.contains("proxy-capture-cases=13"), text);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }
}
