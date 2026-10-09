package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** The production probe-owner path: BootstrapBridge visible only through the bootstrap loader. */
class BootstrapOwnerPathTest {
  @Test
  void wrapperInstrumentsWhenTheOwnerResolvesThroughTheBootstrapLoader() throws Exception {
    Path bridgeLocation =
        Path.of(
            dev.xtrace.agent.bootstrap.BootstrapBridge.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI());
    // Remove the bridge from the application class path so only the bootstrap search sees it.
    StringBuilder classpath = new StringBuilder();
    for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
      if (Path.of(entry).toAbsolutePath().equals(bridgeLocation.toAbsolutePath())) continue;
      if (classpath.length() > 0) classpath.append(File.pathSeparator);
      classpath.append(entry);
    }
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    Process process =
        new ProcessBuilder(
                java,
                "-Xbootclasspath/a:" + bridgeLocation,
                "-cp",
                classpath.toString(),
                "demo.probe.OwnerProbeMain")
            .redirectErrorStream(true)
            .start();
    byte[] output = process.getInputStream().readAllBytes();
    assertTrue(process.waitFor(60, TimeUnit.SECONDS), "child JVM timed out");
    String text = new String(output, StandardCharsets.UTF_8);
    assertTrue(text.contains("bridgeLoader=null"), text);
    assertTrue(text.contains("problem=null"), text);
    assertTrue(!text.contains("sites=0"), text);
    assertTrue(!text.contains("probe_owner_unavailable"), text);
  }
}
