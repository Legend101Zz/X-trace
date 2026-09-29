package dev.xtrace.adapter;

/** Safe, stable client error suitable for reporting without credential leakage. */
public final class ClientException extends Exception {
  private final String code;

  /** Creates a safe client error with a stable code and non-sensitive message. */
  public ClientException(String code, String message) {
    super(message);
    this.code = code;
  }

  /** Creates a safe client error while retaining the internal cause for diagnostics. */
  public ClientException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  /** Returns the stable machine-readable error code. */
  public String code() {
    return code;
  }
}
