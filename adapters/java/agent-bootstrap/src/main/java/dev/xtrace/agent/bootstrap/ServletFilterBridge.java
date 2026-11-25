package dev.xtrace.agent.bootstrap;

/** Late request admission based on a positively observed standard servlet filter chain. */
public final class ServletFilterBridge {
  private static final ThreadLocal<Chain> CHAIN = new ThreadLocal<>();
  private static volatile boolean enabled;

  private static final class Chain {
    final String method;
    final long started;
    boolean filterObserved;
    boolean excluded;
    boolean errorPending;

    Chain(String method, long started) {
      this.method = method;
      this.started = started;
    }
  }

  private ServletFilterBridge() {}

  /** Enabled once during launch setup. Attach has no preexisting boundary guarantees. */
  public static void enable() {
    enabled = true;
  }

  /** A failed dispatcher, filter, service, async, or status probe invalidates the fallback. */
  public static void boundaryUnavailable() {
    enabled = false;
  }

  /** Returns only the invocation that owns cleanup and possible recording. */
  public static Object chainEnter(Object request, Object response) {
    if (!enabled) return null;
    Chain active = CHAIN.get();
    if (active != null) {
      if (!active.excluded && !initialSynchronous(request)) active.excluded = true;
      return null;
    }
    String method = null;
    if (!BootstrapBridge.hasContext() && SpringMvcBridge.captureBoundary() == null
        && initialSynchronous(request)) {
      int status = SpringMvcBridge.status(response);
      if (status >= 100 && status < 400) method = SpringMvcBridge.httpMethod(request);
    }
    Chain chain = new Chain(method, System.nanoTime());
    // Hold ownership even when the outer chain cannot qualify. A nested chain must not take over.
    chain.excluded = !BootstrapBridge.validMethod(method);
    CHAIN.set(chain);
    return chain;
  }

  /** Closes at the owning chain return, after all filters have finished working. */
  public static void chainEnd(Object owner, Object request, Object response, Throwable thrown) {
    if (owner == null || owner != CHAIN.get()) return;
    Chain chain = (Chain) owner;
    try {
      if (!enabled || !chain.filterObserved || chain.excluded || thrown != null
          || !initialSynchronous(request)) return;
      int status = SpringMvcBridge.status(response);
      if (status >= 400 && status <= 599) {
        BootstrapBridge.filterRefusal(chain.method, chain.started, status, chain.errorPending);
      }
    } finally {
      CHAIN.remove();
    }
  }

  /** Distinguishes the real standard filter seam from downstream servlet service. */
  public static void servletEnter(boolean filter, Object request) {
    Chain chain = CHAIN.get();
    if (chain == null || chain.excluded) return;
    if (filter && initialSynchronous(request)) chain.filterObserved = true;
    else chain.excluded = true;
  }

  /** Downstream service, MVC dispatch, and async attempts preclude late admission. */
  public static void downstreamEnter() {
    Chain chain = CHAIN.get();
    if (chain != null) chain.excluded = true;
  }

  /** Invoking sendError leaves container processing pending. */
  static void sendError() {
    Chain chain = CHAIN.get();
    if (chain != null) chain.errorPending = true;
  }

  private static boolean initialSynchronous(Object request) {
    return request != null && "REQUEST".equals(SpringMvcBridge.dispatchType(request))
        && Boolean.FALSE.equals(SpringMvcBridge.asyncState(request));
  }
}
