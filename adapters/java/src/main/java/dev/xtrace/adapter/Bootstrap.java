package dev.xtrace.adapter;

import java.util.Arrays;
import java.util.UUID;

/** Validated daemon bootstrap data. Closing erases the caller-owned session secret. */
public final class Bootstrap implements AutoCloseable {
  private final String host;
  private final int port;
  private final String certificatePin;
  private final UUID runtimeSessionId;
  private final byte[] sessionSecret;
  private final UUID projectId;
  private final String repositoryFingerprint;
  private final int protocolMajor;
  private final int protocolMinor;
  private boolean closed;

  Bootstrap(
      String host,
      int port,
      String certificatePin,
      UUID runtimeSessionId,
      byte[] sessionSecret,
      UUID projectId,
      String repositoryFingerprint,
      int protocolMajor,
      int protocolMinor) {
    this.host = host;
    this.port = port;
    this.certificatePin = certificatePin;
    this.runtimeSessionId = runtimeSessionId;
    this.sessionSecret = sessionSecret;
    this.projectId = projectId;
    this.repositoryFingerprint = repositoryFingerprint;
    this.protocolMajor = protocolMajor;
    this.protocolMinor = protocolMinor;
  }

  /** Returns the literal loopback host selected by the daemon. */
  public String host() {
    return host;
  }

  /** Returns the daemon's loopback port. */
  public int port() {
    return port;
  }

  /** Returns the lowercase SHA-256 leaf-certificate pin. */
  public String certificatePin() {
    return certificatePin;
  }

  /** Returns the authenticated runtime-session identifier. */
  public UUID runtimeSessionId() {
    return runtimeSessionId;
  }

  /** Returns a defensive copy of the transcript secret. */
  public synchronized byte[] copySessionSecret() {
    if (closed) throw new IllegalStateException("bootstrap is closed");
    return sessionSecret.clone();
  }

  /** Returns the bootstrap-bound project identifier. */
  public UUID projectId() {
    return projectId;
  }

  /** Returns the canonical repository fingerprint. */
  public String repositoryFingerprint() {
    return repositoryFingerprint;
  }

  /** Returns the maximum protocol major offered by the daemon. */
  public int protocolMajor() {
    return protocolMajor;
  }

  /** Returns the maximum protocol minor offered by the daemon. */
  public int protocolMinor() {
    return protocolMinor;
  }

  /** Erases the in-memory transcript secret. This method is idempotent. */
  @Override
  public synchronized void close() {
    Arrays.fill(sessionSecret, (byte) 0);
    closed = true;
  }
}
