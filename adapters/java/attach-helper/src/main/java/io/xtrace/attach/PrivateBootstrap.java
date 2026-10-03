package io.xtrace.attach;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Set;

/** Validates the owner-only one-shot bootstrap document passed to agentmain by path only. */
final class PrivateBootstrap {
  private static final int MAX_BOOTSTRAP_BYTES = 64 * 1024;

  private PrivateBootstrap() {}

  static Path validate(Path input) throws AttachCommands.Failure {
    if (input == null || !input.isAbsolute()) {
      throw invalid("the bootstrap options file must use an absolute path");
    }
    byte[] content = null;
    try {
      Path absolute = input.normalize();
      Path parent = absolute.getParent();
      if (parent == null) throw invalid("the bootstrap parent is unavailable");
      FileIdentity parentBefore = FileIdentity.directory(parent);
      FileIdentity before = FileIdentity.file(absolute);
      before.requirePrivateFile();
      Set<OpenOption> flags = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
      try (SeekableByteChannel channel = Files.newByteChannel(absolute, flags)) {
        before.requireSame(FileIdentity.file(absolute));
        content = readBounded(channel);
      }
      before.requireSame(FileIdentity.file(absolute));
      parentBefore.requireSame(FileIdentity.directory(parent));
      validateBootstrapDocument(content);
      Path canonical = absolute.toRealPath();
      if (!canonical.getParent().equals(parent.toRealPath())) {
        throw invalid("the bootstrap path changed while it was validated");
      }
      before.requireSame(FileIdentity.file(absolute));
      parentBefore.requireSame(FileIdentity.directory(parent));
      return canonical;
    } catch (AttachCommands.Failure failure) {
      throw failure;
    } catch (UnsupportedOperationException error) {
      throw new AttachCommands.Failure(
          "attach",
          "XTR-ATTACH-UNSUPPORTED-PLATFORM",
          4,
          "This platform cannot verify owner-only bootstrap file permissions.",
          "Use a supported Unix host or launch the JVM through X-trace.");
    } catch (IOException | RuntimeException error) {
      throw invalid("the bootstrap options file could not be read safely");
    } finally {
      if (content != null) Arrays.fill(content, (byte) 0);
    }
  }

  private static byte[] readBounded(SeekableByteChannel channel)
      throws IOException, AttachCommands.Failure {
    ByteBuffer bytes = ByteBuffer.allocate(MAX_BOOTSTRAP_BYTES + 1);
    try {
      while (bytes.hasRemaining() && channel.read(bytes) != -1) {
        // The buffer is fixed-size; never allocate from a file-reported length.
      }
      if (bytes.position() == 0 || bytes.position() > MAX_BOOTSTRAP_BYTES) {
        throw invalid("the bootstrap document is empty or exceeds its size limit");
      }
      return Arrays.copyOf(bytes.array(), bytes.position());
    } finally {
      Arrays.fill(bytes.array(), (byte) 0);
    }
  }

  private static void validateBootstrapDocument(byte[] content) throws AttachCommands.Failure {
    try {
      CharBuffer text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(content));
      try {
        int first = 0;
        while (first < text.length() && Character.isWhitespace(text.charAt(first))) first++;
        if (first == text.length() || text.charAt(first) != '{') {
          throw invalid("the options file is not a valid X-trace bootstrap document");
        }
        for (int index = 0; index < text.length(); index++) {
          if (text.charAt(index) == '\0') {
            throw invalid("the options file is not a valid X-trace bootstrap document");
          }
        }
      } finally {
        text.clear();
        while (text.hasRemaining()) text.put('\0');
      }
    } catch (CharacterCodingException error) {
      throw invalid("the bootstrap document is not valid UTF-8");
    }
  }

  private static AttachCommands.Failure invalid(String message) {
    return new AttachCommands.Failure(
        "attach",
        "XTR-ATTACH-OPTIONS-INVALID",
        2,
        message,
        "Use the live private bootstrap file created for the selected X-trace daemon session.");
  }

  private record FileIdentity(Object fileKey, long device, long inode, long owner, int mode) {
    static FileIdentity directory(Path path) throws IOException, AttachCommands.Failure {
      BasicFileAttributes basic =
          Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!basic.isDirectory() || basic.isSymbolicLink()) {
        throw invalid("the bootstrap parent must be a private real directory");
      }
      FileIdentity identity = unixIdentity(path, basic, false);
      identity.requirePrivateDirectory();
      return identity;
    }

    static FileIdentity file(Path path) throws IOException, AttachCommands.Failure {
      BasicFileAttributes basic =
          Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!basic.isRegularFile() || basic.isSymbolicLink() || basic.size() > MAX_BOOTSTRAP_BYTES) {
        throw invalid("the bootstrap must be a bounded regular file without symlinks");
      }
      return unixIdentity(path, basic, true);
    }

    private static FileIdentity unixIdentity(
        Path path, BasicFileAttributes basic, boolean requireSingleLink)
        throws IOException, AttachCommands.Failure {
      var attributes = Files.readAttributes(path, "unix:dev,ino,uid,nlink,mode", LinkOption.NOFOLLOW_LINKS);
      int mode = ((Number) attributes.get("mode")).intValue();
      long links = ((Number) attributes.get("nlink")).longValue();
      if (requireSingleLink && links != 1) {
        throw invalid("the bootstrap path must not be hard-linked");
      }
      String owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
      String current = ProcessHandle.current().info().user().orElse("");
      if (!owner.equals(current)) throw invalid("the bootstrap must be owned by the helper user");
      return new FileIdentity(
          basic.fileKey(),
          ((Number) attributes.get("dev")).longValue(),
          ((Number) attributes.get("ino")).longValue(),
          ((Number) attributes.get("uid")).longValue(),
          mode);
    }

    void requirePrivateFile() throws AttachCommands.Failure {
      if ((mode & 0077) != 0 || (mode & 0400) == 0) {
        throw invalid("the bootstrap file must be owner-readable and inaccessible to other users");
      }
    }

    private void requirePrivateDirectory() throws AttachCommands.Failure {
      if ((mode & 0077) != 0 || (mode & 0100) == 0) {
        throw invalid("the bootstrap parent must be inaccessible to other users");
      }
    }

    void requireSame(FileIdentity actual) throws AttachCommands.Failure {
      if ((fileKey != null && !fileKey.equals(actual.fileKey))
          || device != actual.device
          || inode != actual.inode
          || owner != actual.owner
          || mode != actual.mode) {
        throw invalid("the bootstrap file or parent changed while being validated");
      }
    }
  }
}
