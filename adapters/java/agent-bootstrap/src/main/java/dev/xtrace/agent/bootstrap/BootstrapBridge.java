package dev.xtrace.agent.bootstrap;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Bootstrap-visible, JDK-only advice bridge. It retains only bounded identifiers and never performs
 * transport or file operations on an application thread.
 */
public final class BootstrapBridge {
  /**
   * Exception message text is withheld (type only) until root rules on J-003 and the daemon audit
   * redactor is on integration: pattern redaction cannot catch a plain user value echoed into a
   * message. Flip here, in one place, if root keeps messages.
   */
  static final boolean FORWARD_EXCEPTION_MESSAGES = false;

  private static final AtomicReference<BridgeSink> SINK = new AtomicReference<>();
  private static final ThreadLocal<RequestContext> CONTEXT = new ThreadLocal<>();
  private static final AtomicReference<LineSink> LINE_SINK = new AtomicReference<>();

  /** Most line events one request may record (focused budget); the rest are counted as a gap. */
  static final int MAX_LINE_EVENTS_PER_REQUEST = 8192;

  /** Symbol of the GAP event that records line events withheld by the per-request budget. */
  public static final String LINE_BUDGET_SYMBOL = "xtrace.capture.gap.line-budget";

  private BootstrapBridge() {}

  /** Installs the one process-wide runtime sink. Reinstallation is rejected. */
  public static boolean install(BridgeSink sink) {
    return SINK.compareAndSet(null, Objects.requireNonNull(sink, "sink"));
  }

  /** Disables a failed sink without replacing a newer runtime instance. */
  public static void disable(BridgeSink sink) {
    SINK.compareAndSet(sink, null);
  }

  /** Installs the focused-mode line sink. Only effective focused arming does this. */
  public static boolean installLineSink(LineSink sink) {
    return LINE_SINK.compareAndSet(null, Objects.requireNonNull(sink, "sink"));
  }

  /** Removes a line sink without replacing a newer one. */
  public static void disableLineSink(LineSink sink) {
    LINE_SINK.compareAndSet(sink, null);
  }

  // ---- Probe owner for instrumented application classes (LineProbeAsmWrapper). The descriptors
  // are fixed by the wrapper: ProbeOwnerCheck verifies all eight. Every entry point fails open.

  public static void line(int siteId) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink == null) return;
      RequestContext context = CONTEXT.get();
      if (context == null || context.deferred) {
        sink.lineIgnored();
        return;
      }
      Frame current = context.frames.peek();
      if (current == null || current.eventId.isEmpty()) {
        // Queue capacity can recover before a pending cursor is flushed. Its missing entry must
        // never be replaced with an ancestor's id, even when both methods have the same name.
        context.dropped++;
        sink.lineIgnored();
        return;
      }
      if (context.lineEvents >= MAX_LINE_EVENTS_PER_REQUEST) {
        context.lineDropped++;
        sink.lineIgnored();
        return;
      }
      if (sink.line(
          context.recordingId, context.nextEventId(), current.eventId, siteId,
          System.nanoTime(), current.symbol)) {
        context.lineEvents++;
        context.linePending = true;
      } else {
        context.dropped++;
        sink.lineIgnored();
      }
    } catch (Throwable ignored) {
      // fail open: a probe can never break application code
    }
  }

  public static void valuesBegin(int siteId) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valuesBegin(siteId);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueInt(int slot, int nameId, int value) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valueInt(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueLong(int slot, int nameId, long value) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valueLong(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueFloat(int slot, int nameId, float value) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valueFloat(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valueDouble(int slot, int nameId, double value) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valueDouble(slot, nameId, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  /** Reference-typed local; the value is passed through untouched (never toString'd here). */
  public static void valueRef(int nameId, int role, Object value) {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valueRef(nameId, role, value);
    } catch (Throwable ignored) {
      // fail open
    }
  }

  public static void valuesEnd() {
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.valuesEnd();
    } catch (Throwable ignored) {
      // fail open
    }
  }

  /** Completes the pending line event of this request before any other event is allocated. */
  private static void flushLine(RequestContext context) {
    if (!context.linePending) return;
    context.linePending = false;
    try {
      LineSink sink = LINE_SINK.get();
      if (sink != null) sink.flush();
    } catch (Throwable ignored) {
      // fail open
    }
  }

  /** Opens a request context for one matched route and emits its sanitized request identity. */
  public static boolean requestStart(String method, String route) {
    RequestContext stale = CONTEXT.get();
    // A request whose end was deferred for exception resolution but never resolved on this
    // thread is closed without a status so it cannot leak into the next request. Only the
    // exception that caused deferral can propagate, never a handled frame throw.
    if (stale != null && stale.deferred) requestEnd(0, stale.deferredThrown);
    if (CONTEXT.get() != null || !validMethod(method) || !validRoute(route)) return false;
    BridgeSink sink = SINK.get();
    if (sink == null) return false;
    String recordingId = UuidV7.random().toString();
    long started = System.nanoTime();
    RequestContext context = new RequestContext(recordingId, started);
    if (!safeStart(sink, context, method, route)) {
      safeIncomplete(sink, BridgeSink.INCOMPLETE_START_REJECTED);
      return false;
    }
    CONTEXT.set(context);
    String requestId = context.nextEventId();
    if (safeEvent(
        sink,
        context,
        requestId,
        "",
        BridgeEventKind.REQUEST_UPDATE,
        "http.request " + method + " " + route,
        0)) {
      context.requestEventId = requestId;
    } else {
      context.dropped++;
    }
    return true;
  }

  /** Emits a fixture method entry and pushes its event identity as the active parent. */
  public static void frameEnter(String symbol) {
    frameEnter(symbol, null);
  }

  /** Emits a fixture frame with the method identity used for compile attestation lookup. */
  public static void frameEnter(String symbol, java.lang.reflect.Method method) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (!captureActive(context) || sink == null || !validSymbol(symbol)) return;
    flushLine(context);
    String eventId = context.nextEventId();
    String parent = context.currentParent();
    boolean accepted = safeMethodEvent(
        sink, context, eventId, parent, BridgeEventKind.FRAME_ENTER, symbol, 0, method);
    if (!accepted) {
      context.dropped++;
    }
    context.frames.push(new Frame(symbol, accepted ? eventId : ""));
  }

  /**
   * Emits a method boundary for an in-scope application class. Focused symbols include a hashed
   * declaring-class/method/descriptor identity; source facts are resolved by the runtime,
   * never from reflection on application objects. Standard capture keeps its readable symbols.
   */
  public static String frameEnter(Class<?> type, String method, String descriptor) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (!captureActive(context) || sink == null || type == null || method == null) return null;
    String symbol = LINE_SINK.get() == null ? simpleName(type.getName()) + "." + method
        : MethodIdentity.symbol(type.getName(), method, descriptor);
    if (!validSymbol(symbol)) return null;
    flushLine(context);
    String eventId = context.nextEventId();
    String parent = context.currentParent();
    boolean accepted;
    try {
      accepted = sink.offerFrameEvent(
          context.recordingId, eventId, parent, BridgeEventKind.FRAME_ENTER, symbol,
          System.nanoTime(), 0, type, method, descriptor);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      accepted = false;
    }
    if (!accepted) context.dropped++;
    context.frames.push(new Frame(symbol, accepted ? eventId : ""));
    return symbol;
  }

  /** Constructor body entry; no receiver is passed, and probe failures never escape. */
  public static String constructorEnter(Class<?> type, String descriptor) {
    try {
      return frameEnter(type, "<init>", descriptor);
    } catch (Throwable ignored) {
      return null;
    }
  }

  /** Closes only a constructor body whose entry ran while capture was active. */
  public static void constructorExit(String symbol, Throwable thrown) {
    try {
      if (symbol != null) frameExit(symbol, thrown);
    } catch (Throwable ignored) {
      // Constructor instrumentation must preserve both normal returns and the original throwable.
    }
  }

  /** Emits proxy boundaries on the same parent stack and loss counters as concrete methods. */
  static boolean proxyFrame(
      ProxyBridge.Call call, Object[] arguments, Object result, Throwable thrown, boolean entering) {
    RequestContext context = CONTEXT.get();
    if (!captureActive(context) || SINK.get() == null) return false;
    if (!validSymbol(call.symbol())) {
      context.dropped++;
      return false;
    }
    flushLine(context);
    String parent = context.currentParent();
    if (!entering) {
      if (context.frames.isEmpty()) return false;
      Frame frame = context.frames.pop();
      if (!frame.symbol.equals(call.symbol())) {
        context.dropped++;
        context.frames.clear();
        return false;
      }
      if (!frame.eventId.isEmpty()) parent = frame.eventId;
    }
    String eventId = context.nextEventId();
    int kind = entering ? BridgeEventKind.FRAME_ENTER
        : thrown == null ? BridgeEventKind.FRAME_EXIT : BridgeEventKind.FRAME_THROW;
    boolean accepted = false;
    try {
      accepted = call.sink().offer(context.recordingId, eventId, parent, kind, call.symbol(),
          System.nanoTime(), call.method(), arguments, result, thrown);
    } catch (Throwable ignored) {
      // Count loss and retain the balanced stack even when a sink fails.
    }
    if (!accepted) context.dropped++;
    if (entering) context.frames.push(new Frame(call.symbol(), accepted ? eventId : ""));
    else if (thrown != null) {
      context.lastThrown = thrown;
      if (accepted) context.lastThrowEventId = eventId;
    }
    return true;
  }

  /** Marks the active request as having no resolvable application handler (scope unknown). */
  public static void handlerUnresolved() {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null || context.unresolvedReported) return;
    context.unresolvedReported = true;
    if (!safeEvent(
        sink, context, context.nextEventId(), context.requestEventId, BridgeEventKind.GAP,
        HANDLER_UNRESOLVED_SYMBOL, 0)) {
      context.dropped++;
    }
  }

  /** Symbol of the GAP event that records an unresolvable application handler. */
  public static final String HANDLER_UNRESOLVED_SYMBOL = "xtrace.capture.handler_unresolved";

  /** Returns the sink's scope verdict for a handler type: 1 in scope, 0 out of scope, -1 unknown. */
  public static int scopeOf(Class<?> type) {
    BridgeSink sink = SINK.get();
    if (sink == null || type == null) return 0;
    try {
      return sink.applicationScope(type);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return 0;
    }
  }

  /** True when a live request context is already open on this thread. */
  public static boolean inRequest() {
    RequestContext context = CONTEXT.get();
    return context != null && !context.deferred;
  }

  /**
   * Keeps the request open after the handler threw, so the container's exception resolution can
   * report the response it chose, or (null {@code thrown}) until the dispatch completes and the
   * status at the outer servlet boundary is observed. Returns false when there is no open request.
   */
  public static boolean deferRequestEnd(Throwable thrown) {
    RequestContext context = CONTEXT.get();
    if (context == null) return false;
    if (!context.deferred) context.deferredBoundary = SpringMvcBridge.captureBoundary();
    context.deferred = true;
    context.deferredThrown = thrown;
    if (thrown == null || thrown != context.lastThrown) context.lastThrowEventId = "";
    context.lastThrown = thrown;
    return true;
  }

  /** True when the request on this thread is waiting for exception resolution. */
  public static boolean awaitingResolution() {
    RequestContext context = CONTEXT.get();
    return context != null && context.deferred;
  }

  static Object exceptionResolutionEnter() {
    RequestContext context = CONTEXT.get();
    if (context == null || !context.deferred) return null;
    if (context.deferredBoundary == null ? SpringMvcBridge.captureBoundary() != null
        : !SpringMvcBridge.boundaryActive(context.deferredBoundary)) return null;
    context.resolutionDepth++;
    return context;
  }

  static boolean resolving(Object boundary) {
    return boundary != null && boundary == CONTEXT.get();
  }

  static void exceptionResolutionEnd(Object boundary) {
    if (boundary instanceof RequestContext context && context.resolutionDepth > 0) context.resolutionDepth--;
  }

  static String simpleName(String binaryName) {
    int dot = binaryName.lastIndexOf('.');
    return dot < 0 ? binaryName : binaryName.substring(dot + 1);
  }

  static boolean validMethod(String method) {
    if (method == null) return false;
    switch (method) {
      case "GET":
      case "HEAD":
      case "POST":
      case "PUT":
      case "PATCH":
      case "DELETE":
      case "OPTIONS":
      case "TRACE":
        return true;
      default:
        return false;
    }
  }

  /** A route is a bounded template: leading slash, no query, fragment, control or space chars. */
  static boolean validRoute(String route) {
    if (route == null || route.isEmpty() || route.length() > 200 || route.charAt(0) != '/') {
      return false;
    }
    for (int i = 0; i < route.length(); i++) {
      char c = route.charAt(i);
      if (c <= ' ' || c == 0x7f || c == '?' || c == '#') return false;
    }
    return true;
  }

  static boolean validSymbol(String symbol) {
    if (symbol == null || symbol.isEmpty() || symbol.length() > 200) return false;
    for (int i = 0; i < symbol.length(); i++) {
      if (symbol.charAt(i) <= ' ') return false;
    }
    return true;
  }

  private static boolean safeMethodEvent(
      BridgeSink sink,
      RequestContext context,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      int detail,
      java.lang.reflect.Method method) {
    try {
      return sink.offerMethodEvent(
          context.recordingId, eventId, parentEventId, kind, symbol, System.nanoTime(), detail, method);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  /** Emits a method exit or throw and removes the matching frame on every path. */
  public static void frameExit(String symbol, boolean threw) {
    frameExit(symbol, threw ? UNKNOWN_THROWABLE : null);
  }

  private static final Throwable UNKNOWN_THROWABLE = new Throwable("unknown", null, false, false) {};

  /**
   * Emits a method exit, or a throw carrying the exception's type and message. Only a throwable
   * that leaves the method is a throw; one caught inside it never reaches this call.
   */
  public static void frameExit(String symbol, Throwable thrown) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (!captureActive(context) || sink == null || context.frames.isEmpty()) return;
    flushLine(context);
    Frame frame = context.frames.pop();
    if (!frame.symbol.equals(symbol)) {
      context.dropped++;
      context.frames.clear();
      return;
    }
    String eventId = context.nextEventId();
    String parent = frame.eventId.isEmpty() ? context.currentParent() : frame.eventId;
    boolean accepted;
    if (thrown == null) {
      accepted = safeEvent(sink, context, eventId, parent, BridgeEventKind.FRAME_EXIT, symbol, 0);
    } else {
      accepted = safeThrow(sink, context, eventId, parent, symbol, thrown);
      context.lastThrowEventId = accepted ? eventId : "";
      context.lastThrown = thrown;
    }
    if (!accepted) context.dropped++;
  }

  private static boolean safeThrow(
      BridgeSink sink,
      RequestContext context,
      String eventId,
      String parent,
      String symbol,
      Throwable thrown) {
    String type = null;
    String message = null;
    if (thrown != UNKNOWN_THROWABLE) {
      type = boundedText(thrown.getClass().getName(), 200);
      try {
        // Application-defined getMessage may misbehave; any failure just omits the message.
        message = FORWARD_EXCEPTION_MESSAGES ? boundedText(thrown.getMessage(), 1024) : null;
      } catch (RuntimeException | LinkageError ignored) {
        message = null;
      }
    }
    try {
      return sink.offerThrowEvent(
          context.recordingId, eventId, parent, symbol, System.nanoTime(), type, message);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static String boundedText(String value, int max) {
    if (value == null) return null;
    return value.length() <= max ? value : value.substring(0, max);
  }

  /** Emits the coarse H2 execute boundary without reading SQL or bind values. */
  public static void databaseStart() {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (!captureActive(context) || sink == null || context.databaseActive) return;
    flushLine(context);
    context.databaseActive = true;
    context.databaseEventId = "";
    String eventId = context.nextEventId();
    if (safeEvent(
        sink,
        context,
        eventId,
        context.currentParent(),
        BridgeEventKind.DATABASE_START,
        "h2.executeUpdate",
        0)) {
      context.databaseEventId = eventId;
    } else {
      context.dropped++;
    }
  }

  /** Emits the coarse H2 completion boundary. */
  public static void databaseEnd(boolean threw) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (!captureActive(context) || sink == null || !context.databaseActive) return;
    flushLine(context);
    String start = context.databaseEventId;
    context.databaseActive = false;
    context.databaseEventId = "";
    String eventId = context.nextEventId();
    if (!safeEvent(
        sink,
        context,
        eventId,
        start.isEmpty() ? context.currentParent() : start,
        BridgeEventKind.DATABASE_END,
        threw ? "h2.executeUpdate.failed" : "h2.executeUpdate",
        threw ? 1 : 0)) {
      context.dropped++;
    }
  }

  /** Emits the response marker, offers the terminal signal, and always clears request context. */
  public static void requestEnd(int responseStatus, boolean threw) {
    requestEnd(responseStatus, threw ? UNKNOWN_THROWABLE : null);
  }

  /**
   * Ends the request with an authoritative status supplied by the caller (0 if unobserved).
   * Without a status, a non-null {@code thrown} means EXCEPTION_PROPAGATED; neither means
   * UNOBSERVED. Intermediate statuses must use {@link #provisionalRequestEnd} instead.
   */
  public static void requestEnd(int responseStatus, Throwable thrown) {
    requestEnd(responseStatus, thrown, null);
  }

  /**
   * Records an intermediate servlet status as evidence, never as the authoritative outcome or
   * numeric response interaction. Only a bounded status number enters the explanatory label.
   */
  public static void provisionalRequestEnd(int observedStatus, Throwable thrown) {
    int status = observedStatus >= 100 && observedStatus <= 599 ? observedStatus : 0;
    requestEnd(0, thrown, "http.response unavailable; final status not observed; "
        + (status == 0 ? "provisional status unavailable"
            : "observed status was " + status + " (provisional)"));
  }

  private static void requestEnd(int responseStatus, Throwable thrown, String responseLabel) {
    RequestContext context = CONTEXT.get();
    try {
      BridgeSink sink = SINK.get();
      if (context == null || sink == null) return;
      flushLine(context);
      if (context.lineDropped > 0) {
        long withheld = context.lineDropped;
        context.lineDropped = 0;
        if (!safeEvent(
            sink, context, context.nextEventId(), context.requestEventId, BridgeEventKind.GAP,
            LINE_BUDGET_SYMBOL, (int) Math.min(Integer.MAX_VALUE, withheld))) {
          context.dropped++;
        }
      }
      int sanitizedStatus = responseStatus >= 100 && responseStatus <= 599 ? responseStatus : 0;
      String eventId = context.nextEventId();
      if (!safeEvent(
          sink,
          context,
          eventId,
          context.requestEventId,
          BridgeEventKind.RESPONSE,
          responseLabel != null ? responseLabel
              : sanitizedStatus == 0 ? "http.response unavailable" : "http.response " + sanitizedStatus,
          sanitizedStatus)) {
        context.dropped++;
      }
      // The caller decides whether a status is final. Pending container error handling or an
      // escaping servlet exception supplies only provisional evidence, not a dropped event.
      safeFinish(sink, context, sanitizedStatus, outcome(context, sanitizedStatus, thrown));
    } finally {
      CONTEXT.remove();
    }
  }

  private static BridgeSink.Outcome outcome(
      RequestContext context, int status, Throwable thrown) {
    String thrownFrom = thrown == UNKNOWN_THROWABLE || thrown == context.lastThrown
        ? context.lastThrowEventId : "";
    if (status != 0) {
      // The caller supplied a final status, including buffered responses at normal servlet exit.
      return new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, status, null, null, null);
    }
    if (thrown == null) {
      return new BridgeSink.Outcome(BridgeSink.Outcome.UNOBSERVED, 0, null, null, null);
    }
    String type = null;
    String message = null;
    Throwable source = thrown == UNKNOWN_THROWABLE ? context.lastThrown : thrown;
    if (source != null && source != UNKNOWN_THROWABLE) {
      type = boundedText(source.getClass().getName(), 200);
      try {
        message = FORWARD_EXCEPTION_MESSAGES ? boundedText(source.getMessage(), 1024) : null;
      } catch (RuntimeException | LinkageError ignored) {
        message = null;
      }
    }
    return new BridgeSink.Outcome(
        BridgeSink.Outcome.EXCEPTION_PROPAGATED, 0, type, message,
        thrownFrom.isEmpty() ? null : thrownFrom);
  }

  public static boolean hasContext() {
    return CONTEXT.get() != null;
  }

  private static boolean captureActive(RequestContext context) {
    return context != null && (!context.deferred || context.resolutionDepth > 0
        || SpringMvcBridge.boundaryActive(context.deferredBoundary));
  }

  /** Called only by methods whose focused line probes were skipped at transformation time. */
  public static void lineGap() {
    try {
      RequestContext context = CONTEXT.get();
      BridgeSink sink = SINK.get();
      // A retained thread-local alone is not evidence that later work belongs to this request.
      if (!captureActive(context) || sink == null) return;
      flushLine(context);
      if (!safeEvent(sink, context, context.nextEventId(), context.currentParent(),
          BridgeEventKind.GAP, "xtrace.capture.gap.not-transformed", 1)) context.dropped++;
    } catch (Throwable ignored) {
      // Limitation probes cannot affect application behavior.
    }
  }

  static void resetForTest() {
    CONTEXT.remove();
    LINE_SINK.set(null);
    SINK.set(null);
  }

  private static boolean safeStart(
      BridgeSink sink, RequestContext context, String method, String route) {
    try {
      return sink.offerStart(context.recordingId, context.startedMonotonicNs, method, route);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static boolean safeEvent(
      BridgeSink sink,
      RequestContext context,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      int detail) {
    try {
      return sink.offerEvent(
          context.recordingId,
          eventId,
          parentEventId,
          kind,
          symbol,
          System.nanoTime(),
          detail);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static void safeFinish(
      BridgeSink sink, RequestContext context, int responseStatus, BridgeSink.Outcome outcome) {
    try {
      if (!sink.offerFinishWithOutcome(
          context.recordingId,
          context.startedMonotonicNs,
          System.nanoTime(),
          responseStatus,
          context.dropped,
          outcome)) {
        safeIncomplete(sink, BridgeSink.INCOMPLETE_FINISH_REJECTED);
        disable(sink);
      }
    } catch (RuntimeException | LinkageError ignored) {
      safeIncomplete(sink, BridgeSink.INCOMPLETE_FINISH_REJECTED);
      disable(sink);
    }
  }

  private static void safeIncomplete(BridgeSink sink, int failureKind) {
    try {
      sink.reportIncomplete(failureKind);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
    }
  }

  private static final class RequestContext {
    private final String recordingId;
    private final long startedMonotonicNs;
    private final Deque<Frame> frames = new ArrayDeque<>(3);
    private int nextEvent = 1;
    private String requestEventId = "";
    private boolean deferred;
    private Object deferredBoundary;
    private int resolutionDepth;
    private Throwable deferredThrown;
    private boolean unresolvedReported;
    private String lastThrowEventId = "";
    private Throwable lastThrown;
    private boolean databaseActive;
    private String databaseEventId = "";
    private long dropped;
    private boolean linePending;
    private int lineEvents;
    private long lineDropped;

    private RequestContext(String recordingId, long startedMonotonicNs) {
      this.recordingId = recordingId;
      this.startedMonotonicNs = startedMonotonicNs;
    }

    private String nextEventId() {
      return recordingId + ":" + nextEvent++;
    }

    private String currentParent() {
      for (Frame frame : frames) {
        if (!frame.eventId.isEmpty()) return frame.eventId;
      }
      return requestEventId;
    }
  }

  private record Frame(String symbol, String eventId) {}
}
