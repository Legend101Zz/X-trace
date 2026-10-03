package io.xtrace.attach;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/** Owner-private immutable copy handed to the target VM by Attach API. */
record AgentSnapshot(Path root, Path agentJar) {
  private static final long MAX_DISTRIBUTION_BYTES = 256L * 1024 * 1024;
  private static final long MAX_CACHED_BYTES = 512L * 1024 * 1024;
  private static final int MAX_SNAPSHOTS = 8;
  private static final int CHUNK_BYTES = 8192;

  String agentOptions(Path bootstrap) throws AttachCommands.Failure {
    String encodedBootstrap = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(bootstrap.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String encodedSnapshot = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(root.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String options = "xtrace-attach-v1:" + encodedBootstrap + "." + encodedSnapshot;
    if (options.length() > 16 * 1024) {
      throw invalid("the private attach options exceed their size limit");
    }
    return options;
  }

  static AgentSnapshot create(
      AgentArtifact.VerifiedDistribution verified, long pid, Instant startTime)
      throws AttachCommands.Failure {
    try {
      Path cache = cacheDirectory();
      Path lockPath = cache.resolve(".lock");
      try (FileChannel lockChannel = FileChannel.open(
              lockPath,
              StandardOpenOption.CREATE,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS);
          FileLock lock = lockChannel.tryLock()) {
        if (lock == null) throw invalid("another attach operation is preparing a private snapshot");
        Files.setPosixFilePermissions(lockPath, PosixFilePermissions.fromString("rw-------"));
        return createUnderLock(verified, pid, startTime, cache);
      }
    } catch (AttachCommands.Failure failure) {
      throw failure;
    } catch (IOException | RuntimeException error) {
      throw invalid("the verified X-trace distribution could not be snapshotted safely");
    }
  }

  private static AgentSnapshot createUnderLock(
      AgentArtifact.VerifiedDistribution verified, long pid, Instant startTime, Path cache)
      throws IOException, AttachCommands.Failure {
    Path snapshot = null;
    try {
      reapExited(cache);
      ensureCapacity(cache);
      snapshot = Files.createTempDirectory(cache, "target-" + pid + "-" + UUID.randomUUID());
      Files.setPosixFilePermissions(snapshot, PosixFilePermissions.fromString("rwx------"));
      Path distribution = Files.createDirectory(snapshot.resolve("distribution"));
      Files.setPosixFilePermissions(distribution, PosixFilePermissions.fromString("rwx------"));
      Path runtime = Files.createDirectory(distribution.resolve("runtime"));
      Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwx------"));

      long total = 0;
      for (Map.Entry<String, Path> item : verified.artifacts().entrySet()) {
        String name = item.getKey();
        Path destination = name.startsWith("runtime/")
            ? runtime.resolve(name.substring("runtime/".length()))
            : distribution.resolve("xtrace-java-agent.jar");
        total += copyVerified(
            item.getValue(),
            destination,
            verified.digests().get(name),
            MAX_DISTRIBUTION_BYTES - total);
      }
      Path manifest = distribution.resolve("manifest.sha256");
      byte[] manifestBytes = readBounded(verified.manifest(), 1024 * 1024);
      try {
        if (manifestBytes.length > MAX_DISTRIBUTION_BYTES - total) {
          throw invalid("the X-trace distribution exceeds its snapshot size limit");
        }
        String contents = new String(manifestBytes, java.nio.charset.StandardCharsets.UTF_8);
        if (!contents.equals(verified.manifestContents())) {
          throw invalid("the X-trace distribution changed while it was snapshotted");
        }
        Files.write(manifest, manifestBytes);
      } finally {
        java.util.Arrays.fill(manifestBytes, (byte) 0);
      }
      Files.setPosixFilePermissions(manifest, PosixFilePermissions.fromString("r--------"));
      Files.setPosixFilePermissions(distribution, PosixFilePermissions.fromString("r-x------"));

      Path lease = snapshot.resolve("snapshot.lease");
      Files.writeString(lease, pid + "\n" + startTime.toEpochMilli() + "\n");
      Files.setPosixFilePermissions(lease, PosixFilePermissions.fromString("r--------"));
      Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("r-x------"));
      Files.setPosixFilePermissions(snapshot, PosixFilePermissions.fromString("r-x------"));

      AgentArtifact.validate(distribution.resolve("xtrace-java-agent.jar"));
      requireOwner(snapshot, verified.owner());
      return new AgentSnapshot(snapshot, distribution.resolve("xtrace-java-agent.jar"));
    } catch (AttachCommands.Failure failure) {
      deleteQuietly(snapshot);
      throw failure;
    } catch (IOException | RuntimeException error) {
      deleteQuietly(snapshot);
      throw error;
    }
  }

  static void deleteOwnedSnapshot(Path snapshot, long pid, Instant startTime) {
    try {
      Path cache = cacheDirectory();
      Path canonical = snapshot.toRealPath(LinkOption.NOFOLLOW_LINKS);
      if (!canonical.getParent().equals(cache)) return;
      Path lockPath = cache.resolve(".lock");
      try (FileChannel channel = FileChannel.open(
              lockPath,
              StandardOpenOption.CREATE,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS);
          FileLock lock = channel.tryLock()) {
        if (lock == null) return;
        Files.setPosixFilePermissions(lockPath, PosixFilePermissions.fromString("rw-------"));
        if (!leaseMatches(canonical, pid, startTime.toEpochMilli())) return;
        delete(canonical);
      }
    } catch (AttachCommands.Failure | IOException | RuntimeException ignored) {
      // A bounded private snapshot is retained if its ownership cannot be proven.
    }
  }

  private static Path cacheDirectory() throws IOException, AttachCommands.Failure {
    Path tmp = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();
    Path cache = tmp.resolve("xtrace-attach-snapshots");
    if (!Files.exists(cache, LinkOption.NOFOLLOW_LINKS)) {
      Files.createDirectory(cache, PosixFilePermissions.asFileAttribute(
          PosixFilePermissions.fromString("rwx------")));
    }
    if (!Files.isDirectory(cache, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(cache)
        || (Files.getAttribute(cache, "unix:mode", LinkOption.NOFOLLOW_LINKS) instanceof Number mode
            && (mode.intValue() & 0077) != 0)) {
      throw invalid("the private attach snapshot directory is not secure");
    }
    requireOwner(cache, ProcessHandle.current().info().user().orElse(""));
    return cache.toRealPath(LinkOption.NOFOLLOW_LINKS);
  }

  private static void ensureCapacity(Path cache) throws IOException, AttachCommands.Failure {
    long total = 0;
    int snapshots = 0;
    try (var paths = Files.list(cache)) {
      for (Path path : paths.toList()) {
        if (path.getFileName().toString().equals(".lock")) continue;
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
          throw invalid("the private attach snapshot directory contains an unexpected entry");
        }
        snapshots++;
        if (snapshots >= MAX_SNAPSHOTS) {
          throw invalid("too many active attach snapshots are retained");
        }
        total += treeSize(path, MAX_CACHED_BYTES - total);
      }
    }
    if (total > MAX_CACHED_BYTES - MAX_DISTRIBUTION_BYTES - 8192) {
      throw invalid("the private attach snapshot cache is full");
    }
  }

  static boolean reapExited(Path cache) throws IOException {
    boolean active = false;
    try (var paths = Files.list(cache)) {
      for (Path path : paths.toList()) {
        if (path.getFileName().toString().equals(".lock")) continue;
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) continue;
        if (!path.getFileName().toString().matches("target-[1-9][0-9]{0,9}-[0-9a-f-]{36}")) continue;
        long[] lease = readLease(path);
        if (lease == null) continue;
        ProcessHandle target = ProcessHandle.of(lease[0]).orElse(null);
        if (target == null || !target.isAlive()) {
          delete(path);
          continue;
        }
        try {
          ProcessIdentity identity = ProcessIdentity.read(lease[0], "attach");
          if (identity.startTime() == null || identity.owner() == null) {
            active = true;
          } else if (identity.startTime().toEpochMilli() != lease[1]
              || !identity.owner().equals(ProcessHandle.current().info().user().orElse(""))) {
            delete(path);
          } else {
            active = true;
          }
        } catch (AttachCommands.Failure ignored) {
          // An alive PID with unavailable identity may still be using lazy runtime classes.
          active = true;
        }
      }
    }
    return active;
  }


  private static long treeSize(Path root, long maximum) throws IOException, AttachCommands.Failure {
    long total = 0;
    try (var paths = Files.walk(root)) {
      for (Path path : paths.toList()) {
        if (Files.isSymbolicLink(path)) throw invalid("an attach snapshot contains a symbolic link");
        if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
          total += Files.size(path);
          if (total > maximum) return total;
        }
      }
    }
    return total;
  }

  private static long copyVerified(
      Path source, Path destination, String expectedDigest, long maximumBytes)
      throws IOException, AttachCommands.Failure {
    if (expectedDigest == null) throw invalid("the verified X-trace digest is unavailable");
    MessageDigest digest = sha256();
    long total = 0;
    try (InputStream input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS);
        OutputStream output = Files.newOutputStream(destination)) {
      byte[] buffer = new byte[CHUNK_BYTES];
      int count;
      while ((count = input.read(buffer)) != -1) {
        total += count;
        if (total > maximumBytes || total > AgentArtifact.MAX_AGENT_BYTES) {
          throw invalid("an X-trace distribution file exceeds its snapshot size limit");
        }
        digest.update(buffer, 0, count);
        output.write(buffer, 0, count);
      }
      java.util.Arrays.fill(buffer, (byte) 0);
    }
    String copied = HexFormat.of().formatHex(digest.digest());
    if (!copied.equals(expectedDigest)) {
      Files.deleteIfExists(destination);
      throw invalid("the X-trace distribution changed while it was snapshotted");
    }
    Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--------"));
    return total;
  }

  private static byte[] readBounded(Path path, int maximum) throws IOException, AttachCommands.Failure {
    try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
      byte[] bytes = input.readNBytes(maximum + 1);
      if (bytes.length == 0 || bytes.length > maximum || input.read() != -1) {
        java.util.Arrays.fill(bytes, (byte) 0);
        throw invalid("the X-trace distribution manifest exceeds its size limit");
      }
      return bytes;
    }
  }

  private static long[] readLease(Path snapshot) {
    byte[] content = null;
    try {
      if (!Files.isDirectory(snapshot, LinkOption.NOFOLLOW_LINKS)
          || Files.isSymbolicLink(snapshot)
          || !Files.getOwner(snapshot, LinkOption.NOFOLLOW_LINKS).getName()
              .equals(ProcessHandle.current().info().user().orElse(""))) return null;
      Path lease = snapshot.resolve("snapshot.lease");
      var attrs = Files.readAttributes(lease, "unix:nlink,mode", LinkOption.NOFOLLOW_LINKS);
      if (!Files.isRegularFile(lease, LinkOption.NOFOLLOW_LINKS)
          || Files.isSymbolicLink(lease)
          || ((Number) attrs.get("nlink")).longValue() != 1
          || ((((Number) attrs.get("mode")).intValue()) & 0077) != 0
          || Files.size(lease) > 128) return null;
      try (InputStream input = Files.newInputStream(lease, LinkOption.NOFOLLOW_LINKS)) {
        content = input.readNBytes(129);
        if (content.length > 128 || input.read() != -1) return null;
      }
      String[] lines = new String(content, java.nio.charset.StandardCharsets.US_ASCII).split("\\n");
      if (lines.length != 2 || !lines[0].matches("[1-9][0-9]{0,9}")
          || !lines[1].matches("[0-9]{1,16}")) return null;
      return new long[] {Long.parseLong(lines[0]), Long.parseLong(lines[1])};
    } catch (IOException | RuntimeException ignored) {
      return null;
    } finally {
      if (content != null) java.util.Arrays.fill(content, (byte) 0);
    }
  }

  private static boolean leaseMatches(Path snapshot, long pid, long startMillis) {
    long[] lease = readLease(snapshot);
    return lease != null && lease[0] == pid && lease[1] == startMillis;
  }

  private static void requireOwner(Path path, String expected) throws IOException, AttachCommands.Failure {
    if (!Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName().equals(expected)) {
      throw invalid("the attach snapshot is not owned by the helper user");
    }
  }

  private static void delete(Path root) throws IOException {
    try (var paths = Files.walk(root)) {
      for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
          Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        }
        Files.deleteIfExists(path);
      }
    }
  }

  private static void deleteQuietly(Path root) {
    if (root == null) return;
    try {
      delete(root);
    } catch (IOException | RuntimeException ignored) {
      // Failed cleanup remains private and will be considered by the next helper invocation.
    }
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 is required by the Java runtime", error);
    }
  }

  private static AttachCommands.Failure invalid(String message) {
    return new AttachCommands.Failure(
        "attach",
        "XTR-ATTACH-AGENT-INVALID",
        2,
        message,
        "Select the installed X-trace agent JAR from its packaged distribution.");
  }
}
