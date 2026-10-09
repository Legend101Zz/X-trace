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
  private static final AtomicReference<BridgeSink> SINK = new AtomicReference<>();
  private static final ThreadLocal<RequestContext> CONTEXT = new ThreadLocal<>();

  private BootstrapBridge() {}

  /** Installs the one process-wide runtime sink. Reinstallation is rejected. */
  public static boolean install(BridgeSink sink) {
    return SINK.compareAndSet(null, Objects.requireNonNull(sink, "sink"));
  }

  /** Disables a failed sink without replacing a newer runtime instance. */
  public static void disable(BridgeSink sink) {
    SINK.compareAndSet(sink, null);
  }

  /** Opens a request context for one matched route and emits its sanitized request identity. */
  public static boolean requestStart(String method, String route) {
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
    if (context == null || sink == null || !validSymbol(symbol)) return;
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
   * Emits a method boundary for an in-scope application class. The symbol is the simple class
   * name plus the method name; source facts are resolved by the runtime from the declaring class,
   * method name and descriptor, never from reflection on application objects.
   */
  public static String frameEnter(Class<?> type, String method, String descriptor) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null || type == null || method == null) return null;
    String symbol = simpleName(type.getName()) + "." + method;
    if (!validSymbol(symbol)) return null;
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

  /** True when a request context is already open on this thread. */
  public static boolean inRequest() {
    return CONTEXT.get() != null;
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

  /** Emits a fixture method exit or throw and removes the matching frame on every path. */
  public static void frameExit(String symbol, boolean threw) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null || context.frames.isEmpty()) return;
    Frame frame = context.frames.pop();
    if (!frame.symbol.equals(symbol)) {
      context.dropped++;
      context.frames.clear();
      return;
    }
    String eventId = context.nextEventId();
    int kind = threw ? BridgeEventKind.FRAME_THROW : BridgeEventKind.FRAME_EXIT;
    String parent = frame.eventId.isEmpty() ? context.currentParent() : frame.eventId;
    if (!safeEvent(sink, context, eventId, parent, kind, symbol, 0)) {
      context.dropped++;
    }
  }

  /** Emits the coarse H2 execute boundary without reading SQL or bind values. */
  public static void databaseStart() {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null || context.databaseActive) return;
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
    if (context == null || sink == null || !context.databaseActive) return;
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
    RequestContext context = CONTEXT.get();
    try {
      BridgeSink sink = SINK.get();
      if (context == null || sink == null) return;
      int sanitizedStatus = responseStatus >= 100 && responseStatus <= 599 ? responseStatus : 0;
      String eventId = context.nextEventId();
      if (!safeEvent(
          sink,
          context,
          eventId,
          context.requestEventId,
          BridgeEventKind.RESPONSE,
          sanitizedStatus == 0 ? "http.response unavailable" : "http.response " + sanitizedStatus,
          sanitizedStatus)) {
        context.dropped++;
      }
      if (threw && sanitizedStatus < 500) context.dropped++;
      safeFinish(sink, context, sanitizedStatus);
    } finally {
      CONTEXT.remove();
    }
  }

  public static boolean hasContext() {
    return CONTEXT.get() != null;
  }

  static void resetForTest() {
    CONTEXT.remove();
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

  private static void safeFinish(BridgeSink sink, RequestContext context, int responseStatus) {
    try {
      if (!sink.offerFinish(
          context.recordingId,
          context.startedMonotonicNs,
          System.nanoTime(),
          responseStatus,
          context.dropped)) {
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
    private boolean unresolvedReported;
    private boolean databaseActive;
    private String databaseEventId = "";
    private long dropped;

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
