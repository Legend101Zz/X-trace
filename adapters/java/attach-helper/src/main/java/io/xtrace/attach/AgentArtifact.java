package io.xtrace.attach;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/** Validates the explicitly selected regular agent JAR without echoing its path. */
final class AgentArtifact {
  private static final long MAX_AGENT_BYTES = 128L * 1024 * 1024;
  private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
  private static final int MAX_RUNTIME_JARS = 128;
  private static final String XTRACE_AGENT = "dev.xtrace.agent.bootstrap.XTraceAgent";

  private AgentArtifact() {}

  static Path validate(Path input) throws AttachCommands.Failure {
    if (input == null || !input.isAbsolute()) {
      throw invalid("the selected agent must use an absolute path");
    }
    try {
      String currentOwner = ProcessHandle.current().info().user().orElse(null);
      if (currentOwner == null) throw invalid("the helper could not verify its operating-system user");
      FileIdentity selectedIdentity = FileIdentity.file(input, MAX_AGENT_BYTES, currentOwner);
      Path canonical = input.toRealPath();
      selectedIdentity.requireSame(FileIdentity.file(canonical, MAX_AGENT_BYTES, currentOwner));
      try (JarFile jar = new JarFile(canonical.toFile(), false)) {
        Manifest manifest = jar.getManifest();
        if (manifest == null) throw invalid("the selected JAR has no agent manifest");
        String agentClass = manifest.getMainAttributes().getValue(Attributes.Name.AGENT_CLASS);
        if (agentClass == null || agentClass.isBlank()) {
          throw invalid("the selected JAR does not declare an Agent-Class");
        }
        if (!XTRACE_AGENT.equals(agentClass)) {
          throw invalid("the selected JAR is not the supported X-trace agent");
        }
        validateXtraceDistribution(canonical, selectedIdentity);
      }
      return canonical;
    } catch (AttachCommands.Failure failure) {
      throw failure;
    } catch (IOException | RuntimeException error) {
      throw invalid("the selected agent JAR could not be validated");
    }
  }

  private static void validateXtraceDistribution(Path agent, FileIdentity agentBefore)
      throws IOException, AttachCommands.Failure {
    Path root = agent.getParent();
    if (root == null || !"xtrace-java-agent.jar".equals(agent.getFileName().toString())) {
      throw invalid("the selected X-trace agent has an unexpected filename");
    }
    String currentOwner = ProcessHandle.current().info().user().orElse(null);
    if (currentOwner == null) throw invalid("the helper could not verify its operating-system user");

    FileIdentity rootBefore = FileIdentity.directory(root, currentOwner);
    Path runtime = root.resolve("runtime");
    FileIdentity runtimeBefore = FileIdentity.directory(runtime, currentOwner);
    Path manifest = root.resolve("manifest.sha256");
    FileIdentity manifestBefore = FileIdentity.file(manifest, MAX_MANIFEST_BYTES, currentOwner);

    Map<String, Path> artifacts = new TreeMap<>();
    artifacts.put("xtrace-java-agent.jar", agent);
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(root)) {
      Set<String> expected = Set.of("xtrace-java-agent.jar", "manifest.sha256", "runtime");
      for (Path entry : entries) {
        String name = entry.getFileName().toString();
        if (!expected.contains(name)) throw invalid("the X-trace distribution has unexpected files");
      }
    }
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(runtime)) {
      int count = 0;
      for (Path entry : entries) {
        if (++count > MAX_RUNTIME_JARS) throw invalid("the X-trace runtime exceeds its file bound");
        String name = entry.getFileName().toString();
        if (!name.matches("[A-Za-z0-9_.+-]{1,128}\\.jar")) {
          throw invalid("the X-trace runtime contains an unexpected file");
        }
        FileIdentity.file(entry, MAX_AGENT_BYTES, currentOwner);
        artifacts.put("runtime/" + name, entry);
      }
    }
    if (artifacts.size() < 2) throw invalid("the X-trace runtime distribution is incomplete");

    byte[] manifestBytes = readBounded(manifest, manifestBefore, MAX_MANIFEST_BYTES);
    String manifestText;
    try {
      manifestText = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
          .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(manifestBytes))
          .toString();
    } catch (java.nio.charset.CharacterCodingException error) {
      throw invalid("the X-trace distribution manifest is malformed");
    } finally {
      Arrays.fill(manifestBytes, (byte) 0);
    }

    Map<String, String> declared = new LinkedHashMap<>();
    for (String line : manifestText.lines().toList()) {
      String[] parts = line.split("  ", 2);
      if (parts.length != 2
          || !parts[0].matches("[0-9a-f]{64}")
          || declared.putIfAbsent(parts[1], parts[0]) != null) {
        throw invalid("the X-trace distribution manifest is malformed");
      }
    }
    if (!declared.keySet().equals(artifacts.keySet())) {
      throw invalid("the X-trace distribution manifest membership does not match");
    }
    Map<Path, FileIdentity> before = new LinkedHashMap<>();
    for (Map.Entry<String, Path> artifact : artifacts.entrySet()) {
      FileIdentity identity = FileIdentity.file(artifact.getValue(), MAX_AGENT_BYTES, currentOwner);
      before.put(artifact.getValue(), identity);
      String digest = sha256(artifact.getValue(), identity);
      if (!digest.equals(declared.get(artifact.getKey()))) {
        throw invalid("the X-trace distribution digest does not match");
      }
    }
    for (Map.Entry<Path, FileIdentity> entry : before.entrySet()) {
      entry.getValue().requireSame(FileIdentity.file(entry.getKey(), MAX_AGENT_BYTES, currentOwner));
    }
    agentBefore.requireSame(FileIdentity.file(agent, MAX_AGENT_BYTES, currentOwner));
    manifestBefore.requireSame(FileIdentity.file(manifest, MAX_MANIFEST_BYTES, currentOwner));
    rootBefore.requireSame(FileIdentity.directory(root, currentOwner));
    runtimeBefore.requireSame(FileIdentity.directory(runtime, currentOwner));
    byte[] manifestAfter = readBounded(manifest, manifestBefore, MAX_MANIFEST_BYTES);
    try {
      if (!manifestText.equals(new String(manifestAfter, java.nio.charset.StandardCharsets.UTF_8))) {
        throw invalid("the X-trace distribution changed during validation");
      }
    } finally {
      Arrays.fill(manifestAfter, (byte) 0);
    }
  }

  private static byte[] readBounded(Path path, FileIdentity identity, int maximum)
      throws IOException, AttachCommands.Failure {
    ByteBuffer buffer = ByteBuffer.allocate(maximum + 1);
    try (SeekableByteChannel channel = Files.newByteChannel(
        path, Set.<OpenOption>of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      identity.requireSame(FileIdentity.file(path, maximum));
      while (buffer.hasRemaining() && channel.read(buffer) != -1) {
        // Read into a fixed-capacity buffer; never trust an on-disk size as an allocation size.
      }
      if (buffer.position() > maximum) throw invalid("an X-trace distribution file exceeds its bound");
      return Arrays.copyOf(buffer.array(), buffer.position());
    } finally {
      Arrays.fill(buffer.array(), (byte) 0);
    }
  }

  private static String sha256(Path path, FileIdentity identity)
      throws IOException, AttachCommands.Failure {
    final MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 is required by the Java runtime", error);
    }
    ByteBuffer buffer = ByteBuffer.allocate(8192);
    long total = 0;
    try (SeekableByteChannel channel = Files.newByteChannel(
        path, Set.<OpenOption>of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      identity.requireSame(FileIdentity.file(path, MAX_AGENT_BYTES));
      int read;
      while ((read = channel.read(buffer)) != -1) {
        if (read == 0) continue;
        total += read;
        if (total > MAX_AGENT_BYTES) throw invalid("an X-trace agent file exceeds its bound");
        buffer.flip();
        digest.update(buffer);
        buffer.clear();
      }
    } finally {
      Arrays.fill(buffer.array(), (byte) 0);
    }
    if (total != identity.size()) throw invalid("an X-trace agent file changed during validation");
    return HexFormat.of().formatHex(digest.digest());
  }

  private static AttachCommands.Failure invalid(String message) {
    return new AttachCommands.Failure(
        "attach",
        "XTR-ATTACH-AGENT-INVALID",
        2,
        message,
        "Select the installed X-trace agent JAR from its packaged distribution.");
  }

  private record FileIdentity(Object fileKey, long device, long inode, long owner, long links,
      int mode, long size) {
    static FileIdentity directory(Path path, String currentOwner)
        throws IOException, AttachCommands.Failure {
      BasicFileAttributes basic = Files.readAttributes(
          path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!basic.isDirectory() || basic.isSymbolicLink()) {
        throw invalid("the X-trace distribution directories must be real directories");
      }
      FileIdentity identity = read(path, basic, currentOwner, false);
      if ((identity.mode & 0022) != 0) throw invalid("the X-trace distribution directory is writable by others");
      return identity;
    }

    static FileIdentity file(Path path, long maximum) throws IOException, AttachCommands.Failure {
      return file(path, maximum, null);
    }

    static FileIdentity file(Path path, long maximum, String currentOwner)
        throws IOException, AttachCommands.Failure {
      BasicFileAttributes basic = Files.readAttributes(
          path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!basic.isRegularFile() || basic.isSymbolicLink() || basic.size() == 0 || basic.size() > maximum) {
        throw invalid("the selected X-trace distribution file is not a bounded regular file");
      }
      return read(path, basic, currentOwner, true);
    }

    private static FileIdentity read(
        Path path, BasicFileAttributes basic, String currentOwner, boolean singleLink)
        throws IOException, AttachCommands.Failure {
      var attributes = Files.readAttributes(path, "unix:dev,ino,uid,nlink,mode", LinkOption.NOFOLLOW_LINKS);
      long links = ((Number) attributes.get("nlink")).longValue();
      if (singleLink && links != 1) throw invalid("X-trace distribution files must not be hard-linked");
      String owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
      if (currentOwner != null && !owner.equals(currentOwner)) {
        throw invalid("the X-trace distribution must be owned by the helper user");
      }
      int mode = ((Number) attributes.get("mode")).intValue();
      if (singleLink && (mode & 0022) != 0) {
        throw invalid("the X-trace distribution files must not be writable by others");
      }
      return new FileIdentity(
          basic.fileKey(),
          ((Number) attributes.get("dev")).longValue(),
          ((Number) attributes.get("ino")).longValue(),
          ((Number) attributes.get("uid")).longValue(),
          links,
          mode,
          singleLink ? basic.size() : -1);
    }

    void requireSame(FileIdentity actual) throws AttachCommands.Failure {
      if ((fileKey != null && !fileKey.equals(actual.fileKey))
          || device != actual.device
          || inode != actual.inode
          || owner != actual.owner
          || links != actual.links
          || mode != actual.mode
          || (size >= 0 && size != actual.size)) {
        throw invalid("the X-trace distribution changed during validation");
      }
    }
  }
}
