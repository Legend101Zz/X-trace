package dev.xtrace.agent.bootstrap;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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

  /** Symbol of the GAP event that records an unresolvable application handler. */
  public static final String HANDLER_UNRESOLVED_SYMBOL = "xtrace.capture.handler_unresolved";

  /** Symbol of the GAP event that records lost reactive or async correlation. */
  public static final String CORRELATION_LOST_SYMBOL = "xtrace.capture.gap.correlation-lost";

  private BootstrapBridge() {}

  /** Installs the one process-wide runtime sink. Reinstallation is rejected. */
  public static boolean install(BridgeSink sink) {
    return SINK.compareAndSet(null, Objects.requireNonNull(sink, "sink"));
  }

  /** Disables a failed sink without replacing a newer runtime instance. */
  public static void disable(BridgeSink sink) {
    SINK.compareAndSet(sink, null);
  }

  static boolean hasBridgeSink() {
    return SINK.get() != null;
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
      if (context == null || context.state.deferred || context.state.closed) {
        sink.lineIgnored();
        return;
      }
      Frame current = context.frames.peek();
      if (current == null || current.eventId.isEmpty()) {
        // Queue capacity can recover before a pending cursor is flushed. Its missing entry must
        // never be replaced with an ancestor's id, even when both methods have the same name.
        context.state.dropped.incrementAndGet();
        sink.lineIgnored();
        return;
      }
      synchronized (context.state.emitLock) {
        if (context.state.closed) {
          sink.lineIgnored();
          return;
        }
        if (context.state.lineEvents.get() >= MAX_LINE_EVENTS_PER_REQUEST) {
          context.state.lineDropped.incrementAndGet();
          sink.lineIgnored();
          return;
        }
        if (sink.line(
            context.state.recordingId, context.state.nextEventId(), current.eventId, siteId,
            System.nanoTime(), current.symbol)) {
          context.state.lineEvents.incrementAndGet();
          context.linePending = true;
        } else {
          context.state.dropped.incrementAndGet();
          sink.lineIgnored();
        }
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
      if (sink == null) return;
      if (context.state.closed) {
        sink.discardPending();
      } else {
        sink.flush();
      }
    } catch (Throwable ignored) {
      // fail open
    }
  }

  /** Opens a request context for one matched route and emits its sanitized request identity. */
  public static boolean requestStart(String method, String route) {
    return requestStart(method, route, 0, false, false);
  }

  /** Closes a route-less root from a completed standard filter-chain observation. */
  static void filterRefusal(String method, long started, int status, boolean errorPending) {
    if (!hasContext() && requestStart(method, "", started, true, false)) {
      if (errorPending) provisionalRequestEnd(status, null);
      else requestEnd(status, (Throwable) null);
    }
  }

  /** The concrete service entry was reached earlier on this thread. */
  static boolean jerseyStart(String method, String route, long serviceStarted) {
    return requestStart(method, route, serviceStarted, false, true);
  }

  private static boolean requestStart(
      String method, String route, long boundaryStarted, boolean filterOnly, boolean jersey) {
    RequestContext stale = CONTEXT.get();
    // A request whose end was deferred for exception resolution but never resolved on this
    // thread is closed without a status so it cannot leak into the next request. Only the
    // exception that caused deferral can propagate, never a handled frame throw.
    if (stale != null && stale.state.deferred) requestEnd(0, stale.state.deferredThrown);
    if (CONTEXT.get() != null || !validMethod(method) || (!filterOnly && !validRoute(route))) {
      return false;
    }
    BridgeSink sink = SINK.get();
    if (sink == null) return false;
    String recordingId = UuidV7.random().toString();
    long started = filterOnly || jersey ? boundaryStarted : System.nanoTime();
    RecordingState state = new RecordingState(recordingId, started);
    if (!safeStart(sink, state, method, route, jersey)) {
      safeIncomplete(sink, BridgeSink.INCOMPLETE_START_REJECTED);
      return false;
    }
    RequestContext context = new RequestContext(state, "");
    CONTEXT.set(context);
    if (jersey) {
      // Emit the buffered concrete service entrance at its observed time, before the
      // later dispatch publishes the matched template. No source binding is implied.
      String service = JerseyBridge.SERVICE;
      String event = state.nextEventId();
      boolean accepted = safeEventAt(sink, state, event, "", BridgeEventKind.FRAME_ENTER,
          service, started, 0);
      if (!accepted) state.dropped.incrementAndGet();
      context.frames.push(new Frame(service, accepted ? event : ""));
    }
    String requestId = state.nextEventId();
    if (safeEvent(
        sink,
        state,
        requestId,
        "",
        BridgeEventKind.REQUEST_UPDATE,
        "http.request " + method + (route.isEmpty() ? "" : " " + route),
        0)) {
      state.requestEventId = requestId;
    } else {
      state.dropped.incrementAndGet();
    }
    return true;
  }

  /** Opens a reactive WebFlux recording without binding a sticky ThreadLocal context. */
  static RecordingState startReactiveRecording(
      String method, String route, long boundaryStarted, boolean unresolvedHandler) {
    if (!validMethod(method) || route == null || (!route.isEmpty() && !validRoute(route))) {
      return null;
    }
    BridgeSink sink = SINK.get();
    if (sink == null) return null;
    String recordingId = UuidV7.random().toString();
    long started = boundaryStarted != 0 ? boundaryStarted : System.nanoTime();
    RecordingState state = new RecordingState(recordingId, started);
    boolean offered;
    try {
      offered = sink.offerWebFluxStart(recordingId, started, method, route);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      offered = false;
    }
    if (!offered) {
      safeIncomplete(sink, BridgeSink.INCOMPLETE_START_REJECTED);
      return null;
    }
    synchronized (state.emitLock) {
      String requestId = state.nextEventId();
      if (safeEvent(
          sink,
          state,
          requestId,
          "",
          BridgeEventKind.REQUEST_UPDATE,
          "http.request " + method + (route.isEmpty() ? "" : " " + route),
          0)) {
        state.requestEventId = requestId;
      } else {
        state.dropped.incrementAndGet();
      }
      if (unresolvedHandler && state.unresolvedReported.compareAndSet(false, true)) {
        if (!safeEvent(
            sink, state, state.nextEventId(), state.requestEventId, BridgeEventKind.GAP,
            HANDLER_UNRESOLVED_SYMBOL, 0)) {
          state.dropped.incrementAndGet();
        }
      }
    }
    return state;
  }

  static String emitReactiveEvent(
      RecordingState state, String parentEventId, int kind, String symbol, int detail) {
    BridgeSink sink = SINK.get();
    if (state == null || sink == null || !validSymbol(symbol)) return null;
    synchronized (state.emitLock) {
      if (state.closed) return null;
      String parent = parentEventId == null || parentEventId.isEmpty()
          ? state.requestEventId : parentEventId;
      String eventId = state.nextEventId();
      if (safeEvent(sink, state, eventId, parent, kind, symbol, detail)) {
        return eventId;
      }
      state.dropped.incrementAndGet();
      return "";
    }
  }

  static String emitReactiveThrow(
      RecordingState state, String parentEventId, String symbol, Throwable thrown) {
    BridgeSink sink = SINK.get();
    if (state == null || sink == null || !validSymbol(symbol)) return null;
    Throwable actual = thrown == null ? UNKNOWN_THROWABLE : thrown;
    synchronized (state.emitLock) {
      if (state.closed) return null;
      String parent = parentEventId == null || parentEventId.isEmpty()
          ? state.requestEventId : parentEventId;
      String eventId = state.nextEventId();
      boolean accepted = safeThrow(sink, state, eventId, parent, symbol, actual);
      state.lastThrowEventId = accepted ? eventId : "";
      state.lastThrown = actual;
      if (!accepted) {
        state.dropped.incrementAndGet();
        return "";
      }
      return eventId;
    }
  }

  static boolean emitCorrelationLostGap(RecordingState state, String parentEventId, int count) {
    BridgeSink sink = SINK.get();
    if (state == null || sink == null) return false;
    synchronized (state.emitLock) {
      if (state.closed) return false;
      String parent = parentEventId == null || parentEventId.isEmpty()
          ? state.requestEventId : parentEventId;
      boolean accepted = safeEvent(
          sink, state, state.nextEventId(), parent, BridgeEventKind.GAP,
          CORRELATION_LOST_SYMBOL, Math.max(1, count));
      if (!accepted) state.dropped.incrementAndGet();
      return accepted;
    }
  }

  static ReactiveScope activateReactiveScope(RecordingState state, String parentEventId) {
    if (state == null || state.closed) return null;
    RequestContext previous = CONTEXT.get();
    String targetParent = parentEventId == null ? "" : parentEventId;
    if (previous != null && previous.state == state
        && (!previous.frames.isEmpty() || previous.rootParentEventId.equals(targetParent))) {
      return new ReactiveScope(previous, previous, false);
    }
    RequestContext activated = new RequestContext(state, targetParent);
    CONTEXT.set(activated);
    return new ReactiveScope(previous, activated, true);
  }

  static ReactiveScope suspendActiveScope() {
    RequestContext previous = CONTEXT.get();
    if (previous == null) return null;
    CONTEXT.remove();
    return new ReactiveScope(previous, null, true);
  }

  static void deactivateReactiveScope(ReactiveScope scope) {
    if (scope == null || !scope.switched) return;
    if (scope.activated != null) {
      synchronized (scope.activated.state.emitLock) {
        flushLine(scope.activated);
      }
    }
    if (scope.previous == null) CONTEXT.remove();
    else CONTEXT.set(scope.previous);
  }

  static RecordingState currentReactiveState() {
    RequestContext context = CONTEXT.get();
    if (context == null || context.state.closed) return null;
    return context.state;
  }

  static String currentReactiveParent() {
    RequestContext context = CONTEXT.get();
    if (context == null || context.state.closed) return "";
    return context.currentParent();
  }

  static boolean finishReactiveRecording(
      RecordingState state,
      int responseStatus,
      Throwable thrown,
      boolean provisional,
      boolean cancelled,
      String... unsupportedCapabilities) {
    if (state == null) return false;
    BridgeSink sink = SINK.get();
    synchronized (state.emitLock) {
      if (state.closed) return false;
      RequestContext active = CONTEXT.get();
      if (active != null && active.state == state) {
        flushLine(active);
      }
      state.closed = true;
      if (sink == null) return false;
      emitPendingLineBudgetGap(sink, state);
      int sanitizedStatus = responseStatus >= 100 && responseStatus <= 599 ? responseStatus : 0;
      String responseLabel;
      int wireStatus;
      BridgeSink.Outcome outcome;
      if (cancelled) {
        wireStatus = 0;
        responseLabel = "http.response unavailable; cancelled";
        outcome = new BridgeSink.Outcome(BridgeSink.Outcome.CLIENT_ABORTED, 0, null, null, null);
      } else if (thrown != null) {
        wireStatus = 0;
        responseLabel = sanitizedStatus == 0
            ? "http.response unavailable"
            : "http.response unavailable; final status not observed; observed status was "
                + sanitizedStatus + " (provisional)";
        outcome = outcome(state, 0, thrown);
      } else if (provisional) {
        wireStatus = 0;
        responseLabel = "http.response unavailable; final status not observed; "
            + (sanitizedStatus == 0 ? "provisional status unavailable"
                : "observed status was " + sanitizedStatus + " (provisional)");
        outcome = new BridgeSink.Outcome(BridgeSink.Outcome.UNOBSERVED, 0, null, null, null);
      } else if (sanitizedStatus != 0) {
        wireStatus = sanitizedStatus;
        responseLabel = "http.response " + sanitizedStatus;
        outcome = new BridgeSink.Outcome(
            BridgeSink.Outcome.RESPONDED, sanitizedStatus, null, null, null);
      } else {
        wireStatus = 0;
        responseLabel = "http.response unavailable";
        outcome = new BridgeSink.Outcome(BridgeSink.Outcome.UNOBSERVED, 0, null, null, null);
      }
      if (!safeEvent(
          sink,
          state,
          state.nextEventId(),
          state.requestEventId,
          BridgeEventKind.RESPONSE,
          responseLabel,
          wireStatus)) {
        state.dropped.incrementAndGet();
      }
      safeFinish(sink, state, wireStatus, outcome, unsupportedCapabilities);
      return true;
    }
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
    synchronized (context.state.emitLock) {
      if (context.state.closed) return;
      flushLine(context);
      String eventId = context.state.nextEventId();
      String parent = context.currentParent();
      boolean accepted = safeMethodEvent(
          sink, context.state, eventId, parent, BridgeEventKind.FRAME_ENTER, symbol, 0, method);
      if (!accepted) {
        context.state.dropped.incrementAndGet();
      }
      context.frames.push(new Frame(symbol, accepted ? eventId : ""));
    }
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
    synchronized (context.state.emitLock) {
      if (context.state.closed) return null;
      flushLine(context);
      String eventId = context.state.nextEventId();
      String parent = context.currentParent();
      boolean accepted;
      try {
        accepted = sink.offerFrameEvent(
            context.state.recordingId, eventId, parent, BridgeEventKind.FRAME_ENTER, symbol,
            System.nanoTime(), 0, type, method, descriptor);
      } catch (RuntimeException | LinkageError ignored) {
        disable(sink);
        accepted = false;
      }
      if (!accepted) context.state.dropped.incrementAndGet();
      context.frames.push(new Frame(symbol, accepted ? eventId : ""));
      return symbol;
    }
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
      context.state.dropped.incrementAndGet();
      return false;
    }
    synchronized (context.state.emitLock) {
      flushLine(context);
      String parent = context.currentParent();
      if (!entering) {
        if (context.frames.isEmpty()) return false;
        Frame frame = context.frames.pop();
        if (!frame.symbol.equals(call.symbol())) {
          context.state.dropped.incrementAndGet();
          context.frames.clear();
          return false;
        }
        if (!frame.eventId.isEmpty()) parent = frame.eventId;
      }
      if (context.state.closed) return false;
      String eventId = context.state.nextEventId();
      int kind = entering ? BridgeEventKind.FRAME_ENTER
          : thrown == null ? BridgeEventKind.FRAME_EXIT : BridgeEventKind.FRAME_THROW;
      boolean accepted = false;
      try {
        accepted = call.sink().offer(context.state.recordingId, eventId, parent, kind, call.symbol(),
            System.nanoTime(), call.method(), arguments, result, thrown);
      } catch (Throwable ignored) {
        // Count loss and retain the balanced stack even when a sink fails.
      }
      if (!accepted) context.state.dropped.incrementAndGet();
      if (entering) context.frames.push(new Frame(call.symbol(), accepted ? eventId : ""));
      else if (thrown != null) {
        context.state.lastThrown = thrown;
        if (accepted) context.state.lastThrowEventId = eventId;
      }
      return true;
    }
  }

  /** Marks the active request as having no resolvable application handler (scope unknown). */
  public static void handlerUnresolved() {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null) return;
    synchronized (context.state.emitLock) {
      if (context.state.closed || !context.state.unresolvedReported.compareAndSet(false, true)) return;
      if (!safeEvent(
          sink, context.state, context.state.nextEventId(), context.state.requestEventId,
          BridgeEventKind.GAP, HANDLER_UNRESOLVED_SYMBOL, 0)) {
        context.state.dropped.incrementAndGet();
      }
    }
  }

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
    return context != null && !context.state.deferred && !context.state.closed;
  }

  /**
   * Keeps the request open after the handler threw, so the container's exception resolution can
   * report the response it chose, or (null {@code thrown}) until the dispatch completes and the
   * status at the outer servlet boundary is observed. Returns false when there is no open request.
   */
  public static boolean deferRequestEnd(Throwable thrown) {
    RequestContext context = CONTEXT.get();
    if (context == null) return false;
    if (!context.state.deferred) context.state.deferredBoundary = SpringMvcBridge.captureBoundary();
    context.state.deferred = true;
    context.state.deferredThrown = thrown;
    if (thrown == null || thrown != context.state.lastThrown) context.state.lastThrowEventId = "";
    context.state.lastThrown = thrown;
    return true;
  }

  /** True when the request on this thread is waiting for exception resolution. */
  public static boolean awaitingResolution() {
    RequestContext context = CONTEXT.get();
    return context != null && context.state.deferred;
  }

  static Object exceptionResolutionEnter() {
    RequestContext context = CONTEXT.get();
    if (context == null || !context.state.deferred) return null;
    if (context.state.deferredBoundary == null ? SpringMvcBridge.captureBoundary() != null
        : !SpringMvcBridge.boundaryActive(context.state.deferredBoundary)) return null;
    context.state.resolutionDepth++;
    return context;
  }

  static boolean resolving(Object boundary) {
    return boundary != null && boundary == CONTEXT.get();
  }

  static void exceptionResolutionEnd(Object boundary) {
    if (boundary instanceof RequestContext context && context.state.resolutionDepth > 0) {
      context.state.resolutionDepth--;
    }
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
      RecordingState state,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      int detail,
      java.lang.reflect.Method method) {
    try {
      return sink.offerMethodEvent(
          state.recordingId, eventId, parentEventId, kind, symbol, System.nanoTime(), detail, method);
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
    synchronized (context.state.emitLock) {
      flushLine(context);
      Frame frame = context.frames.pop();
      if (!frame.symbol.equals(symbol)) {
        context.state.dropped.incrementAndGet();
        context.frames.clear();
        return;
      }
      if (context.state.closed) return;
      String eventId = context.state.nextEventId();
      String parent = frame.eventId.isEmpty() ? context.currentParent() : frame.eventId;
      boolean accepted;
      if (thrown == null) {
        accepted = safeEvent(sink, context.state, eventId, parent, BridgeEventKind.FRAME_EXIT, symbol, 0);
      } else {
        accepted = safeThrow(sink, context.state, eventId, parent, symbol, thrown);
        context.state.lastThrowEventId = accepted ? eventId : "";
        context.state.lastThrown = thrown;
      }
      if (!accepted) context.state.dropped.incrementAndGet();
    }
  }

  private static boolean safeThrow(
      BridgeSink sink,
      RecordingState state,
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
          state.recordingId, eventId, parent, symbol, System.nanoTime(), type, message);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static String boundedText(String value, int max) {
    if (value == null) return null;
    return value.length() <= max ? value : value.substring(0, max);
  }

  /** Opens a coarse JDBC boundary without reading SQL, bind values or driver objects. */
  public static String databaseStart(JdbcOperation operation) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (operation == null || !captureActive(context) || sink == null
        || context.databaseToken != null) return null;
    synchronized (context.state.emitLock) {
      if (context.state.closed) return null;
      flushLine(context);
      context.databaseEventId = "";
      String eventId = context.state.nextEventId();
      context.databaseToken = eventId;
      context.databaseOperation = operation;
      if (safeEvent(
          sink,
          context.state,
          eventId,
          context.currentParent(),
          BridgeEventKind.DATABASE_START,
          operation.symbol(false),
          0)) {
        context.databaseEventId = eventId;
      } else {
        context.state.dropped.incrementAndGet();
      }
      return eventId;
    }
  }

  /** Only the entry that opened this boundary can close it. */
  public static void databaseEnd(String token, boolean threw) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (token == null || !captureActive(context) || sink == null
        || context.databaseToken != token) return;
    synchronized (context.state.emitLock) {
      flushLine(context);
      String start = context.databaseEventId;
      JdbcOperation operation = context.databaseOperation;
      context.databaseToken = null;
      context.databaseOperation = null;
      context.databaseEventId = "";
      if (context.state.closed) return;
      String eventId = context.state.nextEventId();
      if (!safeEvent(
          sink,
          context.state,
          eventId,
          start.isEmpty() ? context.currentParent() : start,
          BridgeEventKind.DATABASE_END,
          operation.symbol(threw),
          threw ? 1 : 0)) {
        context.state.dropped.incrementAndGet();
      }
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
      synchronized (context.state.emitLock) {
        if (context.state.closed) return;
        flushLine(context);
        context.state.closed = true;
        emitPendingLineBudgetGap(sink, context.state);
        int sanitizedStatus = responseStatus >= 100 && responseStatus <= 599 ? responseStatus : 0;
        String eventId = context.state.nextEventId();
        if (!safeEvent(
            sink,
            context.state,
            eventId,
            context.state.requestEventId,
            BridgeEventKind.RESPONSE,
            responseLabel != null ? responseLabel
                : sanitizedStatus == 0 ? "http.response unavailable" : "http.response " + sanitizedStatus,
            sanitizedStatus)) {
          context.state.dropped.incrementAndGet();
        }
        // The caller decides whether a status is final. Pending container error handling or an
        // escaping servlet exception supplies only provisional evidence, not a dropped event.
        safeFinish(sink, context.state, sanitizedStatus, outcome(context.state, sanitizedStatus, thrown));
      }
    } finally {
      CONTEXT.remove();
    }
  }

  private static void emitPendingLineBudgetGap(BridgeSink sink, RecordingState state) {
    long withheld = state.lineDropped.getAndSet(0);
    if (withheld > 0) {
      if (!safeEvent(
          sink, state, state.nextEventId(), state.requestEventId, BridgeEventKind.GAP,
          LINE_BUDGET_SYMBOL, (int) Math.min(Integer.MAX_VALUE, withheld))) {
        state.dropped.incrementAndGet();
      }
    }
  }

  private static BridgeSink.Outcome outcome(
      RecordingState state, int status, Throwable thrown) {
    String thrownFrom = thrown == UNKNOWN_THROWABLE || thrown == state.lastThrown
        ? state.lastThrowEventId : "";
    if (status != 0) {
      // The caller supplied a final status, including buffered responses at normal servlet exit.
      return new BridgeSink.Outcome(BridgeSink.Outcome.RESPONDED, status, null, null, null);
    }
    if (thrown == null) {
      return new BridgeSink.Outcome(BridgeSink.Outcome.UNOBSERVED, 0, null, null, null);
    }
    String type = null;
    String message = null;
    Throwable source = thrown == UNKNOWN_THROWABLE ? state.lastThrown : thrown;
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
    RequestContext context = CONTEXT.get();
    return context != null && !context.state.closed;
  }

  private static boolean captureActive(RequestContext context) {
    return context != null && !context.state.closed
        && (!context.state.deferred || context.state.resolutionDepth > 0
            || SpringMvcBridge.boundaryActive(context.state.deferredBoundary));
  }

  /** Called only by methods whose focused line probes were skipped at transformation time. */
  public static void lineGap() {
    try {
      RequestContext context = CONTEXT.get();
      BridgeSink sink = SINK.get();
      // A retained thread-local alone is not evidence that later work belongs to this request.
      if (!captureActive(context) || sink == null) return;
      synchronized (context.state.emitLock) {
        if (context.state.closed) return;
        flushLine(context);
        if (!safeEvent(sink, context.state, context.state.nextEventId(), context.currentParent(),
            BridgeEventKind.GAP, "xtrace.capture.gap.not-transformed", 1)) {
          context.state.dropped.incrementAndGet();
        }
      }
    } catch (Throwable ignored) {
      // Limitation probes cannot affect application behavior.
    }
  }

  static void resetForTest() {
    CONTEXT.remove();
    LINE_SINK.set(null);
    SINK.set(null);
    ReactorContextBridge.resetForTest();
    WebFluxBridge.resetForTest();
  }

  private static boolean safeStart(
      BridgeSink sink, RecordingState state, String method, String route, boolean jersey) {
    try {
      if (jersey) return sink.offerJerseyStart(state.recordingId, state.startedMonotonicNs, method, route);
      return sink.offerStart(state.recordingId, state.startedMonotonicNs, method, route);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static boolean safeEvent(
      BridgeSink sink,
      RecordingState state,
      String eventId,
      String parentEventId,
      int kind,
      String symbol,
      int detail) {
    return safeEventAt(sink, state, eventId, parentEventId, kind, symbol, System.nanoTime(), detail);
  }

  private static boolean safeEventAt(BridgeSink sink, RecordingState state, String eventId,
      String parentEventId, int kind, String symbol, long observedAt, int detail) {
    try {
      return sink.offerEvent(state.recordingId, eventId, parentEventId, kind, symbol, observedAt, detail);
    } catch (RuntimeException | LinkageError ignored) {
      disable(sink);
      return false;
    }
  }

  private static void safeFinish(
      BridgeSink sink, RecordingState state, int responseStatus, BridgeSink.Outcome outcome,
      String... unsupportedCapabilities) {
    try {
      boolean accepted = unsupportedCapabilities == null || unsupportedCapabilities.length == 0
          ? sink.offerFinishWithOutcome(
              state.recordingId,
              state.startedMonotonicNs,
              System.nanoTime(),
              responseStatus,
              state.dropped.get(),
              outcome)
          : sink.offerFinishWithOutcome(
              state.recordingId,
              state.startedMonotonicNs,
              System.nanoTime(),
              responseStatus,
              state.dropped.get(),
              outcome,
              unsupportedCapabilities);
      if (!accepted) {
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

  static final class RecordingState {
    final String recordingId;
    final long startedMonotonicNs;
    final Object emitLock = new Object();
    final AtomicInteger nextEvent = new AtomicInteger(1);
    volatile String requestEventId = "";
    volatile boolean closed;
    final AtomicBoolean unresolvedReported = new AtomicBoolean();
    final AtomicLong dropped = new AtomicLong();
    final AtomicInteger lineEvents = new AtomicInteger();
    final AtomicLong lineDropped = new AtomicLong();
    volatile String lastThrowEventId = "";
    volatile Throwable lastThrown;
    volatile boolean deferred;
    volatile Object deferredBoundary;
    volatile int resolutionDepth;
    volatile Throwable deferredThrown;

    RecordingState(String recordingId, long startedMonotonicNs) {
      this.recordingId = recordingId;
      this.startedMonotonicNs = startedMonotonicNs;
    }

    String nextEventId() {
      return recordingId + ":" + nextEvent.getAndIncrement();
    }
  }

  static final class ReactiveScope {
    final RequestContext previous;
    final RequestContext activated;
    final boolean switched;

    ReactiveScope(RequestContext previous, RequestContext activated, boolean switched) {
      this.previous = previous;
      this.activated = activated;
      this.switched = switched;
    }
  }

  private static final class RequestContext {
    private final RecordingState state;
    private final String rootParentEventId;
    private final Deque<Frame> frames = new ArrayDeque<>(3);
    private String databaseToken;
    private JdbcOperation databaseOperation;
    private String databaseEventId = "";
    private boolean linePending;

    private RequestContext(RecordingState state, String rootParentEventId) {
      this.state = state;
      this.rootParentEventId = rootParentEventId == null ? "" : rootParentEventId;
    }

    private String currentParent() {
      for (Frame frame : frames) {
        if (!frame.eventId.isEmpty()) return frame.eventId;
      }
      return rootParentEventId.isEmpty() ? state.requestEventId : rootParentEventId;
    }
  }

  private record Frame(String symbol, String eventId) {}
}
