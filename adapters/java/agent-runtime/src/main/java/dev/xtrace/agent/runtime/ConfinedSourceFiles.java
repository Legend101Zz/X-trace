package dev.xtrace.agent.runtime;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;

/**
 * One bounded source read, confined to a canonical project directory, with no ancestor search.
 *
 * <p>On Linux and macOS, use the provider's SecureDirectoryStream (openat/O_NOFOLLOW in
 * OpenJDK) to pin every directory, starting at the filesystem root. A swapped intermediate or
 * final symlink is never followed by the read. Providers without that facility or stable file
 * keys fail closed; there is no path-based read fallback.
 *
 * <p>Java 17 exposes size on the opened channel, but no portable fstat/fileKey for that channel.
 * Compare entry keys, sizes and timestamps before/after, channel size, and the canonical path
 * after reading instead. This detects observed replacement/edit races, not every possible ABA
 * replacement or an in-place write that restores metadata. Neither OS offers an atomic content
 * snapshot through these JDK APIs. The bytes are still only observed, never build-attested.
 */
final class ConfinedSourceFiles {
  static final int MAX_SOURCE_BYTES = 1024 * 1024;

  @FunctionalInterface
  interface BeforeOpen {
    void run(Path file) throws IOException;
  }

  record Source(Path path, byte[] bytes) {}

  static final class TooLarge extends IOException {
    TooLarge() {
      super("source exceeds the byte limit");
    }
  }

  private ConfinedSourceFiles() {}

  static Source read(Path base, String relative) throws IOException {
    return read(base, relative, file -> {});
  }

  /** Per-read seam: runs after validation and immediately before opening the source handle. */
  static Source read(Path base, String relative, BeforeOpen beforeOpen) throws IOException {
    Path canonicalBase = base.toRealPath();
    Path found = locate(canonicalBase, relative);
    if (found == null) return null;
    BasicFileAttributes before = attributes(found);
    if (!before.isRegularFile()) return null;
    if (before.size() > MAX_SOURCE_BYTES) throw new TooLarge();
    try (DirectoryStream<Path> root = Files.newDirectoryStream(found.getRoot())) {
      if (!(root instanceof SecureDirectoryStream<Path> secure)) {
        throw new IOException("secure source traversal unavailable");
      }
      byte[] bytes = readFrom(secure, found, 0, before, beforeOpen);
      // Re-resolve the original spelling too: an in-project alias may have changed.
      if (!canonicalBase.equals(base.toRealPath())
          || !found.equals(locate(canonicalBase, relative))
          || !sameFile(before, attributes(found))) {
        throw new IOException("source changed during read");
      }
      return new Source(canonicalBase.relativize(found), bytes);
    } catch (UnsupportedOperationException unsupported) {
      throw new IOException("secure source traversal unavailable", unsupported);
    }
  }

  private static byte[] readFrom(SecureDirectoryStream<Path> directory, Path file, int index,
      BasicFileAttributes expected, BeforeOpen beforeOpen) throws IOException {
    Path name = file.getName(index);
    BasicFileAttributes before = directory.getFileAttributeView(
        name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
    if (index + 1 < file.getNameCount()) {
      if (!before.isDirectory()) throw new IOException("unsafe source directory");
      try (SecureDirectoryStream<Path> child =
          directory.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS)) {
        BasicFileAttributes opened = child.getFileAttributeView(
            BasicFileAttributeView.class).readAttributes();
        if (!sameKey(before, opened)) throw new IOException("source directory changed");
        byte[] bytes = readFrom(child, file, index + 1, expected, beforeOpen);
        BasicFileAttributes after = directory.getFileAttributeView(
            name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
        if (!after.isDirectory() || !sameKey(before, after)) {
          throw new IOException("source directory changed");
        }
        return bytes;
      }
    }
    if (!sameFile(expected, before)) throw new IOException("source changed before open");
    beforeOpen.run(file);
    try (SeekableByteChannel channel = directory.newByteChannel(
        name, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      if (channel.size() != before.size()) throw new IOException("source size changed");
      // One extra byte detects growth without an unbounded allocation or readAllBytes reopen.
      ByteBuffer buffer = ByteBuffer.allocate((int) before.size() + 1);
      while (buffer.hasRemaining() && channel.read(buffer) != -1) {
        // Read only from this handle, even when the pathname is replaced.
      }
      BasicFileAttributes after = directory.getFileAttributeView(
          name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
      if (buffer.position() != before.size() || channel.size() != before.size()
          || !sameFile(before, after)) throw new IOException("source changed during read");
      byte[] bytes = new byte[buffer.position()];
      buffer.flip();
      buffer.get(bytes);
      return bytes;
    }
  }

  private static BasicFileAttributes attributes(Path file) throws IOException {
    return Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
  }

  private static boolean sameKey(BasicFileAttributes before, BasicFileAttributes after) {
    return before.fileKey() != null && before.fileKey().equals(after.fileKey());
  }

  private static boolean sameFile(BasicFileAttributes before, BasicFileAttributes after) {
    return before.isRegularFile() && after.isRegularFile() && sameKey(before, after)
        && before.size() == after.size()
        && before.lastModifiedTime().equals(after.lastModifiedTime())
        && before.creationTime().equals(after.creationTime());
  }

  /** Missing files allow another declared root; an unsafe path stops resolution entirely. */
  private static Path locate(Path base, String relative) throws IOException {
    Path suffix = Path.of(relative);
    if (suffix.isAbsolute()) throw new IOException("source path is outside the project");
    // Validate the entire spelling even if an earlier component is missing.
    for (Path part : suffix) {
      if (part.toString().equals("..")) throw new IOException("source path contains a parent segment");
    }
    Path current = base;
    for (Path part : suffix) {
      current = current.resolve(part);
      try {
        attributes(current);
      } catch (NoSuchFileException missing) {
        return null;
      }
      current = current.toRealPath();
      if (!current.startsWith(base)) throw new IOException("source path is outside the project");
    }
    return current;
  }
}
