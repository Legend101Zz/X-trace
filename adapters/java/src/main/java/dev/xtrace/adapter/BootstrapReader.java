package dev.xtrace.adapter;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Reads and validates the daemon's private one-shot bootstrap document. */
public final class BootstrapReader {
  private static final int MAX_BYTES = 64 * 1024;
  private static final Pattern PIN = Pattern.compile("[0-9a-f]{64}");
  private static final Pattern FINGERPRINT = Pattern.compile("b3:[0-9a-f]{64}");
  private static final Pattern UUID_TEXT =
      Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
  private static final Set<String> FIELDS =
      Set.of(
          "schema_version",
          "host",
          "port",
          "certificate_sha256_pin",
          "runtime_session_id",
          "session_secret_base64",
          "project_id",
          "expected_repository_fingerprint",
          "max_protocol_major",
          "max_protocol_minor");
  private static final JsonFactory JSON =
      JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

  private BootstrapReader() {}

  /**
   * Opens an owner-only regular file without following its final symlink and validates every
   * bootstrap field. The immediate owner-only, non-symlink parent is the namespace trust boundary
   * and its identity is checked before and after the read. The returned bootstrap owns its decoded
   * secret and must be closed.
   */
  public static Bootstrap read(Path path) throws ClientException {
    if (!isUnix()) {
      throw new ClientException(
          "XTR-JAVA-PLATFORM", "synthetic XTP client requires a Unix daemon bootstrap");
    }
    Path absolute = path.toAbsolutePath().normalize();
    Path parent = absolute.getParent();
    if (parent == null) {
      throw new ClientException("XTR-JAVA-BOOTSTRAP", "bootstrap parent is unavailable");
    }
    byte[] raw = null;
    try {
      ParentIdentity parentBefore = inspectParent(parent);
      BasicFileAttributes before = attributes(absolute);
      Map<String, Object> unixBefore = unixAttributes(absolute);
      validateFile(before, unixBefore);
      Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
      try (SeekableByteChannel channel = Files.newByteChannel(absolute, options)) {
        BasicFileAttributes after = attributes(absolute);
        Map<String, Object> unixAfter = unixAttributes(absolute);
        if (!before.fileKey().equals(after.fileKey())
            || !unixBefore.get("dev").equals(unixAfter.get("dev"))
            || !unixBefore.get("ino").equals(unixAfter.get("ino"))) {
          throw invalid("bootstrap changed while being opened");
        }
        validateFile(after, unixAfter);
        raw = readBounded(channel);
      }
      // Recheck the path after reading so replacement never silently changes the trust target.
      BasicFileAttributes finalAttrs = attributes(absolute);
      Map<String, Object> unixFinal = unixAttributes(absolute);
      validateFile(finalAttrs, unixFinal);
      if (!before.fileKey().equals(finalAttrs.fileKey())
          || !unixBefore.get("dev").equals(unixFinal.get("dev"))
          || !unixBefore.get("ino").equals(unixFinal.get("ino"))) {
        throw invalid("bootstrap changed while being read");
      }
      verifyParent(parent, parentBefore);
      return parse(raw);
    } catch (ClientException error) {
      throw error;
    } catch (IOException | RuntimeException error) {
      throw new ClientException("XTR-JAVA-BOOTSTRAP", "bootstrap could not be read safely", error);
    } finally {
      if (raw != null) Arrays.fill(raw, (byte) 0);
    }
  }

  static ParentIdentity inspectParent(Path parent) throws IOException, ClientException {
    BasicFileAttributes basic = attributes(parent);
    Map<String, Object> unix = unixAttributes(parent);
    int mode = ((Number) unix.get("mode")).intValue();
    long uid = ((Number) unix.get("uid")).longValue();
    if (!basic.isDirectory()
        || basic.isSymbolicLink()
        || (mode & 0077) != 0
        || uid != currentUid()) {
      throw invalid("bootstrap parent must be an owner-only directory");
    }
    return new ParentIdentity(basic.fileKey(), unix.get("dev"), unix.get("ino"));
  }

  static void verifyParent(Path parent, ParentIdentity expected)
      throws IOException, ClientException {
    ParentIdentity actual = inspectParent(parent);
    if (!expected.equals(actual)) {
      throw invalid("bootstrap parent changed while being read");
    }
  }

  record ParentIdentity(Object fileKey, Object device, Object inode) {
    ParentIdentity {
      Objects.requireNonNull(device, "device");
      Objects.requireNonNull(inode, "inode");
    }
  }

  static Bootstrap parse(byte[] raw) throws ClientException {
    Map<String, Object> fields = new HashMap<>();
    try (JsonParser parser = JSON.createParser(new ByteArrayInputStream(raw))) {
      if (parser.nextToken() != JsonToken.START_OBJECT)
        throw invalid("bootstrap must be a JSON object");
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        if (parser.currentToken() != JsonToken.FIELD_NAME)
          throw invalid("bootstrap JSON is invalid");
        String name = parser.currentName();
        if (!FIELDS.contains(name) || fields.containsKey(name)) {
          throw invalid("bootstrap contains an unknown or duplicate field");
        }
        JsonToken token = parser.nextToken();
        if (token == JsonToken.VALUE_STRING) fields.put(name, parser.getText());
        else if (token == JsonToken.VALUE_NUMBER_INT) fields.put(name, parser.getLongValue());
        else throw invalid("bootstrap fields must be strings or integers");
      }
      if (parser.nextToken() != null) throw invalid("bootstrap has trailing JSON data");
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-BOOTSTRAP", "bootstrap JSON is invalid", error);
    }
    byte[] secret = null;
    try {
      if (!Long.valueOf(1).equals(fields.get("schema_version")))
        throw invalid("bootstrap schema version is invalid");
      String host = string(fields, "host");
      if (!host.equals("127.0.0.1") && !host.equals("::1"))
        throw invalid("bootstrap host is not a loopback literal");
      int port = exactInt(fields, "port", 1, 65535);
      String pin = string(fields, "certificate_sha256_pin");
      if (!PIN.matcher(pin).matches()) throw invalid("certificate pin is invalid");
      UUID runtime = canonicalUuid(string(fields, "runtime_session_id"));
      UUID project = canonicalUuid(string(fields, "project_id"));
      String fingerprint = string(fields, "expected_repository_fingerprint");
      if (!FINGERPRINT.matcher(fingerprint).matches())
        throw invalid("repository fingerprint is invalid");
      String encoded = string(fields, "session_secret_base64");
      try {
        secret = Base64.getDecoder().decode(encoded);
      } catch (IllegalArgumentException error) {
        throw invalid("session secret encoding is invalid");
      }
      if (secret.length != 32 || !Base64.getEncoder().encodeToString(secret).equals(encoded)) {
        throw invalid("session secret encoding is invalid");
      }
      int major = exactInt(fields, "max_protocol_major", 1, Integer.MAX_VALUE);
      int minor = exactInt(fields, "max_protocol_minor", 0, Integer.MAX_VALUE);
      byte[] owned = secret;
      secret = null;
      return new Bootstrap(host, port, pin, runtime, owned, project, fingerprint, major, minor);
    } finally {
      if (secret != null) Arrays.fill(secret, (byte) 0);
      Object encoded = fields.put("session_secret_base64", "");
      if (encoded instanceof String value) {
        // Strings cannot be erased, but dropping the last local reference minimizes retention.
        fields.remove("session_secret_base64");
      }
    }
  }

  private static BasicFileAttributes attributes(Path path) throws IOException {
    return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
  }

  private static Map<String, Object> unixAttributes(Path path) throws IOException {
    return Files.readAttributes(path, "unix:dev,ino,uid,nlink,mode", LinkOption.NOFOLLOW_LINKS);
  }

  private static void validateFile(BasicFileAttributes basic, Map<String, Object> unix)
      throws ClientException {
    long size = basic.size();
    int mode = ((Number) unix.get("mode")).intValue();
    long links = ((Number) unix.get("nlink")).longValue();
    long uid = ((Number) unix.get("uid")).longValue();
    long currentUid = currentUid();
    if (!basic.isRegularFile()
        || links != 1
        || size > MAX_BYTES
        || (mode & 0077) != 0
        || uid != currentUid) {
      throw invalid("bootstrap must be an owner-only regular file");
    }
  }

  private static long currentUid() throws ClientException {
    try {
      Class<?> unixSystem = Class.forName("com.sun.security.auth.module.UnixSystem");
      Object instance = unixSystem.getConstructor().newInstance();
      Object value = unixSystem.getMethod("getUid").invoke(instance);
      return ((Number) value).longValue();
    } catch (ReflectiveOperationException error) {
      throw new ClientException(
          "XTR-JAVA-PLATFORM", "platform cannot verify bootstrap ownership", error);
    }
  }

  private static byte[] readBounded(SeekableByteChannel channel)
      throws IOException, ClientException {
    ByteBuffer buffer = ByteBuffer.allocate(MAX_BYTES + 1);
    while (buffer.hasRemaining() && channel.read(buffer) != -1) {
      /* bounded read */
    }
    if (buffer.position() > MAX_BYTES) throw invalid("bootstrap exceeds the allowed file size");
    return Arrays.copyOf(buffer.array(), buffer.position());
  }

  private static String string(Map<String, Object> fields, String name) throws ClientException {
    Object value = fields.get(name);
    if (!(value instanceof String text)) throw invalid("bootstrap field " + name + " is invalid");
    return text;
  }

  private static int exactInt(Map<String, Object> fields, String name, int min, int max)
      throws ClientException {
    Object value = fields.get(name);
    if (!(value instanceof Long number) || number < min || number > max)
      throw invalid("bootstrap field " + name + " is invalid");
    return number.intValue();
  }

  private static UUID canonicalUuid(String value) throws ClientException {
    if (!UUID_TEXT.matcher(value).matches()) throw invalid("bootstrap UUID is not canonical");
    try {
      UUID uuid = UUID.fromString(value);
      if (!uuid.toString().equals(value)) throw invalid("bootstrap UUID is not canonical");
      return uuid;
    } catch (IllegalArgumentException error) {
      throw invalid("bootstrap UUID is invalid");
    }
  }

  private static boolean isUnix() {
    return FileSystemsSupport.UNIX;
  }

  private static ClientException invalid(String message) {
    return new ClientException("XTR-JAVA-BOOTSTRAP", message);
  }

  private static final class FileSystemsSupport {
    private static final boolean UNIX =
        java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("unix");
  }
}
