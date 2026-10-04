package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.xtrace.fixture.OrderService;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import net.bytebuddy.jar.asm.Type;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.junit.jupiter.api.Test;

class SourceAttestationTest {
  private static final String SOURCE =
      "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/" +
      "OrderService.java";

  @Test
  void staleClassOutputCannotBeAttestedAfterCompileInputChanges() {
    byte[] compiledSource = "before compile".getBytes(StandardCharsets.UTF_8);
    byte[] currentSource = "edited after compile".getBytes(StandardCharsets.UTF_8);

    assertThrows(
        IllegalStateException.class,
        () -> SourceAttestationGenerator.requireCompileInputMatches(
            currentSource, compiledSource));
  }

  @Test
  void exactClassBytesAndMethodDescriptorProduceVerifiedSourceFacts()
      throws Exception {
    byte[] classBytes = "original class bytes".getBytes(StandardCharsets.UTF_8);
    try (URLClassLoader loader = loader(manifest(hash(classBytes), "12:14"))) {
      SourceAttestation.observe(loader, "dev/xtrace/fixture/OrderService",
                                classBytes);
      SourceAttestation.SourceInfo source =
          SourceAttestation.lookup(loader, method());
      assertEquals(1, source.binding());
      assertEquals(SOURCE, source.path());
      assertEquals(12, source.startLine());
      assertEquals(14, source.endLine());
      assertNotNull(source.hash());
    }
  }

  @Test
  void changedClassBytesAreAnExplicitMismatch() throws Exception {
    byte[] classBytes = "recorded class bytes".getBytes(StandardCharsets.UTF_8);
    try (URLClassLoader loader = loader(manifest(hash(classBytes), "12:14"))) {
      SourceAttestation.observe(loader, "dev/xtrace/fixture/OrderService",
                                "changed".getBytes(StandardCharsets.UTF_8));
      assertEquals(3, SourceAttestation.lookup(loader, method()).binding());
      assertNull(SourceAttestation.lookup(loader, method()).path());
    }
  }

  @Test
  void absentAttestationAndAbsentDebugLinesStayUnavailable() throws Exception {
    try (URLClassLoader missing =
             new URLClassLoader(new java.net.URL[0], null)) {
      assertEquals(2, SourceAttestation.lookup(missing, method()).binding());
    }
    byte[] classBytes = "class".getBytes(StandardCharsets.UTF_8);
    try (URLClassLoader noLines = loader(manifest(hash(classBytes), "0:0"))) {
      SourceAttestation.observe(noLines, "dev/xtrace/fixture/OrderService",
                                classBytes);
      assertEquals(4, SourceAttestation.lookup(noLines, method()).binding());
    }
  }

  private static URLClassLoader loader(String manifest) throws Exception {
    Path root = Files.createTempDirectory("xtrace-source-attestation-");
    Path file = root.resolve("META-INF/xtrace/source-attestation.tsv");
    Files.createDirectories(file.getParent());
    Files.writeString(file, manifest, StandardCharsets.UTF_8);
    return new URLClassLoader(new java.net.URL[] {root.toUri().toURL()}, null);
  }

  private static String manifest(String classHash, String lineRange)
      throws Exception {
    Method method = method();
    return "dev.xtrace.fixture.OrderService\tplace\t" +
        Type.getMethodDescriptor(method) + "\t" + SOURCE + "\t" + classHash +
        "\t"
        + "00".repeat(32) + "\t" + lineRange + "\n";
  }

  private static Method method() throws Exception {
    return OrderService.class.getMethod("place", String.class, String.class);
  }
  private static String hash(byte[] bytes) {
    Blake3Digest digest = new Blake3Digest(256);
    digest.update(bytes, 0, bytes.length);
    byte[] out = new byte[32];
    digest.doFinal(out, 0);
    StringBuilder value = new StringBuilder(64);
    for (byte item : out)
      value.append(String.format("%02x", item & 255));
    return value.toString();
  }
}
