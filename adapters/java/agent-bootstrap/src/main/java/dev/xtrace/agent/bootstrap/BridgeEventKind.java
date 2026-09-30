package dev.xtrace.agent.bootstrap;

/** Stable JDK-only event discriminators shared with the isolated runtime. */
public final class BridgeEventKind {
  /** Sanitized HTTP method and normalized-route observation. */
  public static final int REQUEST_UPDATE = 1;
  /** Exact fixture method entry. */
  public static final int FRAME_ENTER = 2;
  /** Exact fixture method normal exit. */
  public static final int FRAME_EXIT = 3;
  /** Exact fixture method exceptional exit. */
  public static final int FRAME_THROW = 4;
  /** Coarse H2 execute start. */
  public static final int DATABASE_START = 7;
  /** Coarse H2 execute end. */
  public static final int DATABASE_END = 8;
  /** Sanitized response-status observation. */
  public static final int RESPONSE = 13;

  private BridgeEventKind() {}
}
