package dev.xtrace.agent.bootstrap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bootstrap-visible, JDK-only bridge for JVM child-process boundaries ({@code ProcessBuilder.start}).
 *
 * <p>Never reads or retains command names, raw arguments, working directories, environment maps,
 * or raw correlation tokens. Emits bounded explicit gap signals when child instrumentation is
 * absent or correlation fails, and links supported opt-in child sessions only upon verified
 * token agreement.
 */
public final class ProcessLinkageBridge {
  private static final int MAX_LINK_RECORDS = 256;
  private static final int MAX_ID_BYTES = 128;
  private static final int MAX_TOKEN_BYTES = 256;
  private static final byte[] TOKEN_HASH_DOMAIN =
      "xtrace.process-linkage.correlation-token.v1\0".getBytes(StandardCharsets.UTF_8);

  private static final Object LOCK = new Object();
  private static final Deque<LinkRecord> RECORDS = new ArrayDeque<>(MAX_LINK_RECORDS);
  private static final ThreadLocal<Boolean> IN_HOOK = new ThreadLocal<>();
  private static final ThreadLocal<OptInClaim> PENDING_CLAIM = new ThreadLocal<>();
  private static final AtomicLong LINKED_COUNT = new AtomicLong();
  private static final AtomicLong GAP_COUNT = new AtomicLong();
  private static final AtomicLong UNINSTRUMENTED_GAP_COUNT = new AtomicLong();
  private static final AtomicLong CORRELATION_LOST_COUNT = new AtomicLong();
  private static final AtomicBoolean INSTRUMENTATION_UNAVAILABLE = new AtomicBoolean();

  private ProcessLinkageBridge() {}

  /** Spawn boundary kind observed by the Java agent. */
  public enum SpawnKind {
    JVM_FORK("jvm_fork");

    private final String wireName;

    SpawnKind(String wireName) {
      this.wireName = wireName;
    }

    public String wireName() {
      return wireName;
    }
  }

  /** Correlation outcome for an observed process spawn boundary. */
  public enum LinkStatus {
    LINKED("linked"),
    UNINSTRUMENTED_GAP("uninstrumented_gap"),
    CORRELATION_LOST("correlation_lost");

    private final String wireName;

    LinkStatus(String wireName) {
      this.wireName = wireName;
    }

    public String wireName() {
      return wireName;
    }
  }

  /** Bounded linkage or gap record containing zero raw argv, env, or raw secrets. */
  public record LinkRecord(
      String linkId,
      String parentRecordingId,
      String childSessionId,
      String childRecordingId,
      SpawnKind spawnKind,
      LinkStatus status,
      String gapReason,
      String correlationTokenHash,
      long createdAtMs) {}

  /** Scoped single-use opt-in claim for correlating a child runtime session on spawn. */
  public static final class Scope implements AutoCloseable {
    private final OptInClaim previous;
    private final AtomicBoolean closed = new AtomicBoolean();

    private Scope(OptInClaim previous) {
      this.previous = previous;
    }

    @Override
    public void close() {
      if (!closed.compareAndSet(false, true)) return;
      if (previous == null) PENDING_CLAIM.remove();
      else PENDING_CLAIM.set(previous);
    }
  }

  private static final class OptInClaim {
    final String childSessionId;
    final String childRecordingId;
    final String correlationToken;
    final String expectedCorrelationToken;
    final AtomicBoolean consumed = new AtomicBoolean();

    OptInClaim(
        String childSessionId,
        String childRecordingId,
        String correlationToken,
        String expectedCorrelationToken) {
      this.childSessionId = childSessionId;
      this.childRecordingId = childRecordingId;
      this.correlationToken = correlationToken;
      this.expectedCorrelationToken = expectedCorrelationToken;
    }
  }

  /**
   * Advice entrypoint invoked at {@code ProcessBuilder.start()} entry. Never inspects
   * {@code ProcessBuilder.command()} or {@code ProcessBuilder.environment()} and fails open.
   */
  public static void onProcessBuilderStart() {
    if (!BootstrapBridge.hasBridgeSink() || Boolean.TRUE.equals(IN_HOOK.get())) return;
    IN_HOOK.set(Boolean.TRUE);
    try {
      OptInClaim claim = PENDING_CLAIM.get();
      if (claim == null) {
        recordGap("child_process_not_instrumented", BootstrapBridge.CHILD_PROCESS_NOT_INSTRUMENTED_SYMBOL,
            LinkStatus.UNINSTRUMENTED_GAP, null, null);
        return;
      }
      if (!claim.consumed.compareAndSet(false, true)) {
        recordGap("bootstrap_consumed", BootstrapBridge.BOOTSTRAP_CONSUMED_SYMBOL,
            LinkStatus.UNINSTRUMENTED_GAP, null, null);
        return;
      }
      registerChildSessionLink(
          claim.childSessionId,
          claim.childRecordingId,
          claim.correlationToken,
          claim.expectedCorrelationToken);
    } catch (Throwable ignored) {
      // Fail open: process instrumentation can never alter application behavior.
    } finally {
      IN_HOOK.remove();
    }
  }

  /**
   * Scopes a single-use opt-in child session claim around a {@code ProcessBuilder.start()} call.
   * Subsequent spawns inside the same scope fail closed with {@code bootstrap_consumed}.
   */
  public static Scope withOptInChildLink(
      String childSessionId,
      String childRecordingId,
      String correlationToken,
      String expectedCorrelationToken) {
    OptInClaim previous = PENDING_CLAIM.get();
    PENDING_CLAIM.set(
        new OptInClaim(childSessionId, childRecordingId, correlationToken, expectedCorrelationToken));
    return new Scope(previous);
  }

  /**
   * Explicitly registers a child runtime session link when valid bounded child identifiers and
   * matching correlation token are supplied; fails closed to {@code correlation_lost} otherwise.
   */
  public static boolean registerChildSessionLink(
      String childSessionId,
      String childRecordingId,
      String correlationToken,
      String expectedCorrelationToken) {
    String parentRecordingId = BootstrapBridge.activeRecordingId();
    String boundedChildSession = boundedId(childSessionId);
    String boundedChildRecording = boundedId(childRecordingId);
    byte[] tokenDigest = hashTokenBytes(correlationToken);
    byte[] expectedDigest = expectedCorrelationToken != null
        ? hashTokenBytes(expectedCorrelationToken)
        : tokenDigest;

    boolean valid =
        boundedChildSession != null
            && tokenDigest != null
            && expectedDigest != null
            && MessageDigest.isEqual(tokenDigest, expectedDigest)
            && (parentRecordingId.isEmpty()
                || boundedChildRecording == null
                || !parentRecordingId.equals(boundedChildRecording));

    if (valid) {
      String tokenHashHex = "sha256:" + toHex(tokenDigest);
      BootstrapBridge.emitProcessLink(BootstrapBridge.PROCESS_LINK_SYMBOL);
      appendRecord(
          new LinkRecord(
              UuidV7.random().toString(),
              parentRecordingId.isEmpty() ? null : parentRecordingId,
              boundedChildSession,
              boundedChildRecording,
              SpawnKind.JVM_FORK,
              LinkStatus.LINKED,
              null,
              tokenHashHex,
              System.currentTimeMillis()));
      LINKED_COUNT.incrementAndGet();
      return true;
    }

    String partialHash = tokenDigest == null ? null : "sha256:" + toHex(tokenDigest);
    recordGap(
        "correlation_lost",
        BootstrapBridge.CORRELATION_LOST_SYMBOL,
        LinkStatus.CORRELATION_LOST,
        boundedChildSession,
        partialHash);
    return false;
  }

  /** Marks ProcessBuilder instrumentation as degraded/unavailable in this JVM. */
  public static void reportInstrumentationUnavailable() {
    INSTRUMENTATION_UNAVAILABLE.set(true);
  }

  public static boolean isInstrumentationUnavailable() {
    return INSTRUMENTATION_UNAVAILABLE.get();
  }

  public static boolean takeInstrumentationUnavailable() {
    return INSTRUMENTATION_UNAVAILABLE.getAndSet(false);
  }

  /** Returns a bounded snapshot of recorded child process links and explicit gaps. */
  public static List<LinkRecord> recordedLinks() {
    synchronized (LOCK) {
      return List.copyOf(RECORDS);
    }
  }

  public static long linkedCount() {
    return LINKED_COUNT.get();
  }

  public static long gapCount() {
    return GAP_COUNT.get();
  }

  public static long uninstrumentedGapCount() {
    return UNINSTRUMENTED_GAP_COUNT.get();
  }

  public static long correlationLostCount() {
    return CORRELATION_LOST_COUNT.get();
  }

  static void resetForTest() {
    PENDING_CLAIM.remove();
    IN_HOOK.remove();
    synchronized (LOCK) {
      RECORDS.clear();
    }
    LINKED_COUNT.set(0);
    GAP_COUNT.set(0);
    UNINSTRUMENTED_GAP_COUNT.set(0);
    CORRELATION_LOST_COUNT.set(0);
    INSTRUMENTATION_UNAVAILABLE.set(false);
  }

  private static void recordGap(
      String gapReason,
      String gapSymbol,
      LinkStatus status,
      String childSessionId,
      String tokenHashHex) {
    String parentRecordingId = BootstrapBridge.activeRecordingId();
    BootstrapBridge.emitProcessGap(gapSymbol, 1);
    appendRecord(
        new LinkRecord(
            UuidV7.random().toString(),
            parentRecordingId.isEmpty() ? null : parentRecordingId,
            childSessionId,
            null,
            SpawnKind.JVM_FORK,
            status,
            gapReason,
            tokenHashHex,
            System.currentTimeMillis()));
    GAP_COUNT.incrementAndGet();
    if (status == LinkStatus.UNINSTRUMENTED_GAP) UNINSTRUMENTED_GAP_COUNT.incrementAndGet();
    else if (status == LinkStatus.CORRELATION_LOST) CORRELATION_LOST_COUNT.incrementAndGet();
  }

  private static void appendRecord(LinkRecord record) {
    synchronized (LOCK) {
      while (RECORDS.size() >= MAX_LINK_RECORDS) {
        RECORDS.pollFirst();
      }
      RECORDS.addLast(record);
    }
  }

  private static String boundedId(String value) {
    if (value == null || value.isEmpty()) return null;
    if (value.getBytes(StandardCharsets.UTF_8).length > MAX_ID_BYTES) return null;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c <= ' ' || c == 0x7f) return null;
    }
    return value;
  }

  private static byte[] hashTokenBytes(String token) {
    if (token == null || token.isEmpty()) return null;
    byte[] raw = token.getBytes(StandardCharsets.UTF_8);
    if (raw.length > MAX_TOKEN_BYTES) return null;
    for (int i = 0; i < token.length(); i++) {
      char c = token.charAt(i);
      if (c < ' ' || c == 0x7f) return null;
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(TOKEN_HASH_DOMAIN);
      digest.update(raw);
      return digest.digest();
    } catch (NoSuchAlgorithmException impossible) {
      return null;
    }
  }

  private static String toHex(byte[] bytes) {
    char[] hex = new char[bytes.length * 2];
    final char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xff;
      hex[i * 2] = digits[v >>> 4];
      hex[i * 2 + 1] = digits[v & 0x0f];
    }
    return new String(hex);
  }
}
