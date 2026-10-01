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

  /** Opens a fixture request context and emits its sanitized request identity. */
  public static boolean requestStart(String method, String route) {
    if (CONTEXT.get() != null || !"POST".equals(method) || !"/orders".equals(route)) return false;
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
        "http.request POST /orders",
        0)) {
      context.requestEventId = requestId;
    } else {
      context.dropped++;
    }
    return true;
  }

  /** Emits a fixture method entry and pushes its event identity as the active parent. */
  public static void frameEnter(String symbol) {
    RequestContext context = CONTEXT.get();
    BridgeSink sink = SINK.get();
    if (context == null || sink == null || !isFixtureSymbol(symbol)) return;
    String eventId = context.nextEventId();
    String parent = context.currentParent();
    boolean accepted =
        safeEvent(
        sink,
        context,
        eventId,
        parent,
        BridgeEventKind.FRAME_ENTER,
        symbol,
        0);
    if (!accepted) {
      context.dropped++;
    }
    context.frames.push(new Frame(symbol, accepted ? eventId : ""));
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

  static boolean hasContext() {
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

  private static boolean isFixtureSymbol(String symbol) {
    return symbol != null
        && (symbol.equals("OrderController.create")
            || symbol.equals("OrderService.place")
            || symbol.equals("OrderRepository.save"));
  }

  private static final class RequestContext {
    private final String recordingId;
    private final long startedMonotonicNs;
    private final Deque<Frame> frames = new ArrayDeque<>(3);
    private int nextEvent = 1;
    private String requestEventId = "";
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
