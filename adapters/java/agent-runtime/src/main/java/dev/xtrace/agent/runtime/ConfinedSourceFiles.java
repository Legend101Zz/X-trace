package dev.xtrace.agent.runtime;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One bounded source read checked against a canonical project directory, with no ancestor search.
 *
 * <p>Use SecureDirectoryStream where available (normally Linux OpenJDK), pinning directories
 * from the canonical project base. Opening ancestors above the base would need read permission
 * where ordinary path lookup needs only search permission. Java on macOS has no directory-relative,
 * no-follow file open. There, or when a directory is searchable but not listable, keep a verified
 * POSIX path fallback: check every canonical component with NOFOLLOW_LINKS, require stable file
 * keys, open the final file with NOFOLLOW_LINKS, and compare the directory keys and file
 * key/size/timestamps after reading.
 * Unsupported providers fail closed with a distinct, once-per-process diagnostic.
 *
 * <p>The path fallback cannot fully exclude a directory swapped and restored between checks.
 * An attacker with write access inside the project can replace an intermediate directory with
 * a symlink to an external directory, let the open read an equal-sized external file, then restore
 * the directory before the next check. NOFOLLOW_LINKS protects only the final component, and
 * Java 17 exposes channel size but no portable fstat/fileKey for the opened channel. A swap
 * left in place fails closed, but a restored swap can bind external bytes to a project path.
 * The agent records only the source hash, line count and path, not the source content. This
 * fallback is not a confinement guarantee against such a writer.
 *
 * <p>Both paths detect observed replacement/edit races, not every in-place write that restores
 * metadata. Neither is an atomic content snapshot. Bytes remain observed, never build-attested.
 */
final class ConfinedSourceFiles {
  static final int MAX_SOURCE_BYTES = 1024 * 1024;
  private static final AtomicBoolean VERIFICATION_REPORTED = new AtomicBoolean();

  @FunctionalInterface
  interface BeforeOpen {
    void run(Path file) throws IOException;

    default void afterRead(Path file) throws IOException {}
  }

  @FunctionalInterface
  interface Reader {
    Source read(Path base, String relative) throws IOException;
  }

  record Source(Path path, byte[] bytes) {}

  private record DirectoryIdentity(Path path, BasicFileAttributes attributes) {}

  private record Located(Path path, List<DirectoryIdentity> directories,
      BasicFileAttributes file) {}

  static final class TooLarge extends IOException {
    TooLarge() {
      super("source exceeds the byte limit");
    }
  }

  /** A provider capability failure, distinct from a missing source or attestation. */
  static final class CannotVerify extends IOException {
    CannotVerify() {
      super("the platform cannot verify this source read");
    }
  }

  /** Only a directory-open permission failure may select the path walk. */
  private static final class SearchOnlyDirectory extends IOException {}

  private ConfinedSourceFiles() {}

  static Source read(Path base, String relative) throws IOException {
    return read(base, relative, file -> {});
  }

  /** Per-read seam: runs after initial validation, before opening the source handle. */
  static Source read(Path base, String relative, BeforeOpen beforeOpen) throws IOException {
    return read(base, relative, beforeOpen, false);
  }

  /** Force the same fallback used on macOS, without changing process-wide provider state. */
  static Source read(Path base, String relative, BeforeOpen beforeOpen, boolean forceFallback)
      throws IOException {
    try {
      Path canonicalBase = base.toRealPath();
      Path found = locate(canonicalBase, relative);
      if (found == null) return null;
      Located before = inspect(canonicalBase, found);
      if (!before.file().isRegularFile()) return null;
      if (before.file().size() > MAX_SOURCE_BYTES) throw new TooLarge();
      byte[] bytes;
      if (forceFallback) {
        bytes = readByPath(canonicalBase, before, beforeOpen);
      } else {
        bytes = readPreferred(canonicalBase, before, beforeOpen);
      }
      beforeOpen.afterRead(found);
      // Re-resolve the original spelling too: an in-project alias may have changed.
      if (!canonicalBase.equals(base.toRealPath())
          || !found.equals(locate(canonicalBase, relative))
          || !sameLocation(before, inspect(canonicalBase, found))) {
        throw new IOException("source changed during read");
      }
      return new Source(canonicalBase.relativize(found), bytes);
    } catch (UnsupportedOperationException unsupported) {
      CannotVerify unavailable = new CannotVerify();
      unavailable.initCause(unsupported);
      reportCannotVerify();
      throw unavailable;
    } catch (CannotVerify unavailable) {
      reportCannotVerify();
      throw unavailable;
    }
  }

  private static void reportCannotVerify() {
    if (VERIFICATION_REPORTED.compareAndSet(false, true)) {
      // Fixed text only: no paths, provider messages or captured content reach stderr.
      System.err.println("{\"code\":\"XTR-JAVA-SOURCE-UNVERIFIABLE\","
          + "\"message\":\"Source unavailable: the platform cannot verify this read.\"}");
    }
  }

  static void resetDiagnosticForTest() {
    VERIFICATION_REPORTED.set(false);
  }

  private static DirectoryStream<Path> openBase(Path base) throws IOException {
    try {
      return Files.newDirectoryStream(base);
    } catch (AccessDeniedException searchOnly) {
      throw new SearchOnlyDirectory();
    }
  }

  private static byte[] readPreferred(Path base, Located before, BeforeOpen beforeOpen)
      throws IOException {
    try (DirectoryStream<Path> stream = openBase(base)) {
      if (stream instanceof SecureDirectoryStream<Path> secure) {
        BasicFileAttributes opened = secure.getFileAttributeView(
            BasicFileAttributeView.class).readAttributes();
        if (!opened.isDirectory() || !sameKey(before.directories().get(0).attributes(), opened)) {
          throw new IOException("source base changed");
        }
        return readFrom(secure, before.path(), base.relativize(before.path()), 0,
            before, beforeOpen);
      }
    } catch (SearchOnlyDirectory searchOnly) {
      // Metadata lookup and a file open need search permission, not a directory listing.
    }
    return readByPath(base, before, beforeOpen);
  }

  private static byte[] readByPath(Path base, Located before, BeforeOpen beforeOpen)
      throws IOException {
    if (!base.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      throw new CannotVerify();
    }
    beforeOpen.run(before.path());
    if (!sameLocation(before, inspect(base, before.path()))) {
      throw new IOException("source changed before open");
    }
    try (SeekableByteChannel channel = Files.newByteChannel(
        before.path(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      byte[] bytes = readBounded(channel, before.file());
      if (!sameLocation(before, inspect(base, before.path()))) {
        throw new IOException("source changed during read");
      }
      return bytes;
    }
  }

  private static SecureDirectoryStream<Path> openChild(SecureDirectoryStream<Path> directory,
      Path name) throws IOException {
    try {
      return directory.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS);
    } catch (AccessDeniedException searchOnly) {
      throw new SearchOnlyDirectory();
    }
  }

  private static byte[] readFrom(SecureDirectoryStream<Path> directory, Path absolute,
      Path file, int index, Located expected, BeforeOpen beforeOpen) throws IOException {
    Path name = file.getName(index);
    BasicFileAttributes before = directory.getFileAttributeView(
        name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
    if (index + 1 < file.getNameCount()) {
      if (!before.isDirectory()
          || !sameKey(expected.directories().get(index + 1).attributes(), before)) {
        throw new IOException("unsafe source directory");
      }
      try (SecureDirectoryStream<Path> child = openChild(directory, name)) {
        BasicFileAttributes opened = child.getFileAttributeView(
            BasicFileAttributeView.class).readAttributes();
        if (!opened.isDirectory() || !sameKey(before, opened)) {
          throw new IOException("source directory changed");
        }
        byte[] bytes = readFrom(child, absolute, file, index + 1, expected, beforeOpen);
        BasicFileAttributes after = directory.getFileAttributeView(
            name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
        if (!after.isDirectory() || !sameKey(before, after)) {
          throw new IOException("source directory changed");
        }
        return bytes;
      }
    }
    if (!sameFile(expected.file(), before)) throw new IOException("source changed before open");
    beforeOpen.run(absolute);
    try (SeekableByteChannel channel = directory.newByteChannel(
        name, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      byte[] bytes = readBounded(channel, before);
      BasicFileAttributes after = directory.getFileAttributeView(
          name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
      if (!sameFile(before, after)) throw new IOException("source changed during read");
      return bytes;
    }
  }

  private static byte[] readBounded(SeekableByteChannel channel, BasicFileAttributes before)
      throws IOException {
    if (channel.size() != before.size()) throw new IOException("source size changed");
    // One extra byte detects growth without an unbounded allocation or readAllBytes reopen.
    ByteBuffer buffer = ByteBuffer.allocate((int) before.size() + 1);
    while (buffer.hasRemaining() && channel.read(buffer) != -1) {
      // Read only from this handle, even when the pathname is replaced.
    }
    if (buffer.position() != before.size() || channel.size() != before.size()) {
      throw new IOException("source changed during read");
    }
    byte[] bytes = new byte[buffer.position()];
    buffer.flip();
    buffer.get(bytes);
    return bytes;
  }

  /** Walk the resolved spelling without following links; record every directory identity. */
  private static Located inspect(Path base, Path found) throws IOException {
    if (!found.startsWith(base) || !base.equals(base.toRealPath())) {
      throw new IOException("source path is outside the project");
    }
    List<DirectoryIdentity> directories = new ArrayList<>();
    Path current = base;
    BasicFileAttributes entry = attributes(current);
    Path suffix = base.relativize(found);
    for (Path part : suffix) {
      if (!entry.isDirectory()) throw new IOException("unsafe source directory");
      requireKey(entry);
      directories.add(new DirectoryIdentity(current, entry));
      current = current.resolve(part);
      entry = attributes(current);
      if (entry.isSymbolicLink()) throw new IOException("unsafe source component");
    }
    requireKey(entry);
    return new Located(found, List.copyOf(directories), entry);
  }

  private static boolean sameLocation(Located before, Located after) {
    if (!before.path().equals(after.path())
        || before.directories().size() != after.directories().size()
        || !sameFile(before.file(), after.file())) return false;
    for (int i = 0; i < before.directories().size(); i++) {
      DirectoryIdentity first = before.directories().get(i);
      DirectoryIdentity second = after.directories().get(i);
      if (!first.path().equals(second.path())
          || !sameKey(first.attributes(), second.attributes())) return false;
    }
    return true;
  }

  private static void requireKey(BasicFileAttributes entry) throws CannotVerify {
    if (entry.fileKey() == null) throw new CannotVerify();
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
    Path suffix = base.getFileSystem().getPath(relative);
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
