package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SpringMvcBridgeTest {
  private final Sink sink = new Sink();

  @BeforeEach
  void install() {
    BootstrapBridge.resetForTest();
    SpringMvcBridge.resetForTest();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void reset() {
    BootstrapBridge.resetForTest();
    SpringMvcBridge.resetForTest();
  }

  @Test
  void matchesAnyHandlerMethodAndRecordsTemplateNotPath() {
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals("GET", sink.method);
    assertEquals("/owners/{ownerId}", sink.route);
    assertEquals("http.request GET /owners/{ownerId}", sink.symbols.get(0));
    assertEquals("http.response 200", sink.symbols.get(1));
    assertEquals(200, sink.status);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void asyncStartedHandlerClosesUnobservedAndTheAsyncRedispatchOpensNoSecondRoot() {
    Request async = new Request("GET", "/slow");
    async.asyncStarted = true;
    assertTrue(SpringMvcBridge.start(async, new Handler(Controller.class)));
    SpringMvcBridge.end(async, new Response(200), null);
    assertEquals(0, sink.status);
    assertEquals("http.response unavailable", sink.symbols.get(1));
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertFalse(BootstrapBridge.hasContext());
    int before = sink.symbols.size();
    Request redispatch = new Request("GET", "/slow");
    redispatch.dispatcher = Dispatch.ASYNC;
    assertFalse(SpringMvcBridge.start(redispatch, new Handler(Controller.class)));
    assertEquals(before, sink.symbols.size());
  }

  @Test
  void syncHandlerWithAsyncNotStartedStillReportsRespondedStatus() {
    Request sync = new Request("GET", "/fast");
    assertTrue(SpringMvcBridge.start(sync, new Handler(Controller.class)));
    SpringMvcBridge.end(sync, new Response(201), null);
    assertEquals(201, sink.status);
  }

  @Test
  void requestWithoutMatchedPatternIsNotRecordedAndNeverFallsBackToThePath() {
    Request request = new Request("GET", null);
    assertFalse(SpringMvcBridge.start(request, new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void nonMatchedRequestIsNotRecorded() {
    assertFalse(SpringMvcBridge.start(new Request("GET", "/x"), null));
    assertFalse(SpringMvcBridge.start(null, new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void queryOrFragmentOrSpaceInATemplateRejectsTheRecording() {
    for (String bad : new String[] {"/a?b=1", "/a#f", "/a b", "a/b", "", "/" + "x".repeat(300)}) {
      assertFalse(
          SpringMvcBridge.start(new Request("GET", bad), new Handler(Controller.class)), bad);
    }
    assertFalse(
        SpringMvcBridge.start(new Request("BREW", "/pot"), new Handler(Controller.class)));
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void outOfScopeHandlerIsNotRecorded() {
    sink.scope = 0;
    assertFalse(SpringMvcBridge.start(new Request("GET", "/error"), new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void unknownScopeRecordsTheRootAndReportsHandlerUnresolved() {
    sink.scope = -1;
    assertTrue(SpringMvcBridge.start(new Request("GET", "/ping"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(
        List.of(
            "http.request GET /ping",
            BootstrapBridge.HANDLER_UNRESOLVED_SYMBOL,
            "http.response 200"),
        sink.symbols);
    assertEquals(BridgeEventKind.GAP, sink.kinds.get(1));
  }

  @Test
  void nestedDispatchDoesNotOpenASecondRoot() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/a"), new Handler(Controller.class)));
    assertFalse(SpringMvcBridge.start(new Request("GET", "/b"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(1, sink.starts());
  }

  @Test
  void redirectStatusSetWhileTheViewRendersIsTheRecordedOutcome() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("POST", "/owners/new");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    Response response = new Response(200);
    SpringMvcBridge.end(request, response, null);
    // The handler returned with the default status; the redirect view has not run yet.
    assertTrue(BootstrapBridge.awaitingResolution());
    assertEquals(1, sink.symbols.size(), "no response event before the dispatch ends");
    response.status = 302;
    SpringMvcBridge.dispatchEnd(response, null);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
    assertEquals(302, sink.outcome.httpStatus());
    assertEquals("http.response 302", sink.symbols.get(1));
    assertEquals(1, sink.starts());
  }

  @Test
  void withoutTheDispatchHookTheRootStillClosesWhenTheHandlerReturns() {
    Request request = new Request("GET", "/owners");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(200, sink.outcome.httpStatus());
  }

  @Test
  void dispatchThatThrowsAfterTheHandlerReturnedPropagatesTheExceptionWithoutAStatus() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.dispatchEnd(new Response(200), new IllegalStateException("render failed"));
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals(0, sink.status);
  }

  @Test
  void mappedExceptionWaitsForTheErrorViewStatusWhenTheDispatchHookIsLive() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    IllegalArgumentException failure = new IllegalArgumentException("no owner");
    SpringMvcBridge.end(request, new Response(200), failure);
    Response response = new Response(200);
    SpringMvcBridge.exceptionResolved(response, new Object(), null);
    assertTrue(BootstrapBridge.awaitingResolution(), "the error view has not rendered yet");
    response.status = 404;
    SpringMvcBridge.dispatchEnd(response, null);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(404, sink.outcome.httpStatus());
  }

  @Test
  void dispatchEndWithoutAnOpenRootIsIgnored() {
    SpringMvcBridge.dispatchEnd(new Response(200), null);
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void respondedWithStatus() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/owners"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
    assertEquals(200, sink.outcome.httpStatus());
  }

  @Test
  void exceptionPropagated500() {
    assertTrue(SpringMvcBridge.start(new Request("POST", "/orders"), new Handler(Controller.class)));
    IllegalStateException failure = new IllegalStateException("handler failed");
    SpringMvcBridge.end(new Response(200), failure);
    // The handler threw: the request stays open and the container's default status is not used.
    assertTrue(BootstrapBridge.awaitingResolution());
    assertTrue(sink.symbols.size() == 1, "no response event before resolution");
    SpringMvcBridge.exceptionResolved(new Response(200), null, failure);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals(0, sink.outcome.httpStatus());
    assertEquals("java.lang.IllegalStateException", sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.exceptionMessage());
    assertEquals("http.response unavailable", sink.symbols.get(1));
  }

  @Test
  void mappedExceptionIs4xxResponded() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/owners/{id}"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalArgumentException("no owner"));
    SpringMvcBridge.exceptionResolved(new Response(404), new Object(), null);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
    assertEquals(404, sink.outcome.httpStatus());
    assertEquals(null, sink.outcome.exceptionType());
    assertEquals(404, sink.status);
  }

  @Test
  void unresolvedStatusAfterAMappedExceptionIsUnobservedNotInvented() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/x"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalArgumentException("x"));
    SpringMvcBridge.exceptionResolved(null, new Object(), null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertEquals(0, sink.outcome.httpStatus());
  }

  @Test
  void resolutionWithoutADeferredRequestIsIgnored() {
    SpringMvcBridge.exceptionResolved(new Response(500), new Object(), null);
    assertTrue(sink.symbols.isEmpty());
    assertTrue(SpringMvcBridge.start(new Request("GET", "/ok"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    SpringMvcBridge.exceptionResolved(new Response(500), new Object(), null);
    assertEquals(200, sink.outcome.httpStatus());
  }

  @Test
  void staleDeferredRequestIsClosedUnobservedWhenTheNextRequestStarts() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/a"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalStateException("never resolved"));
    assertTrue(BootstrapBridge.awaitingResolution());
    assertTrue(SpringMvcBridge.start(new Request("GET", "/b"), new Handler(Controller.class)));
    assertEquals(2, sink.starts());
    assertFalse(BootstrapBridge.awaitingResolution());
    SpringMvcBridge.end(new Response(204), null);
    assertEquals(204, sink.outcome.httpStatus());
  }

  @Test
  void throwEventCarriesExceptionTypeAndWithholdsMessage() {
    assertTrue(BootstrapBridge.requestStart("GET", "/x"));
    assertEquals("SpringMvcBridgeTest$Controller.go", BootstrapBridge.frameEnter(Controller.class, "go", "()V"));
    BootstrapBridge.frameExit("SpringMvcBridgeTest$Controller.go", new IllegalStateException("m".repeat(5000)));
    assertEquals("java.lang.IllegalStateException", sink.thrownType);
    assertEquals(null, sink.thrownMessage);
    BootstrapBridge.requestEnd(500, false);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
  }

  @Test
  void throwingGetMessageNeverEscapes() {
    assertTrue(BootstrapBridge.requestStart("GET", "/x"));
    BootstrapBridge.frameEnter(Controller.class, "go", "()V");
    BootstrapBridge.frameExit(
        "SpringMvcBridgeTest$Controller.go",
        new RuntimeException() {
          @Override
          public String getMessage() {
            throw new IllegalStateException("hostile getMessage");
          }
        });
    assertEquals(null, sink.thrownMessage);
    BootstrapBridge.requestEnd(0, new IllegalStateException("x"));
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertTrue(sink.outcome.thrownFromEventId() != null);
  }

  @Test
  void reflectionFailureIsContained() {
    Object hostile = new Object();
    assertFalse(SpringMvcBridge.start(hostile, new Handler(Controller.class)));
    assertEquals(0, SpringMvcBridge.status(hostile));
  }

  @Test
  void concurrentRequestsKeepOwnRoot() throws Exception {
    List<Thread> threads = new ArrayList<>();
    List<String> failures = java.util.Collections.synchronizedList(new ArrayList<>());
    for (int i = 0; i < 8; i++) {
      String route = "/r" + i;
      Thread thread =
          new Thread(
              () -> {
                for (int n = 0; n < 50; n++) {
                  if (!SpringMvcBridge.start(
                      new Request("GET", route), new Handler(Controller.class))) {
                    failures.add("start " + route);
                    return;
                  }
                  SpringMvcBridge.end(new Response(200), null);
                }
              });
      threads.add(thread);
      thread.start();
    }
    for (Thread thread : threads) thread.join();
    assertTrue(failures.isEmpty(), failures.toString());
    assertEquals(8 * 50, sink.routesByMethod("GET").size());
    Map<String, Integer> perRoute = new HashMap<>();
    for (String route : sink.routesByMethod("GET")) perRoute.merge(route, 1, Integer::sum);
    assertEquals(8, perRoute.size());
    perRoute.values().forEach(count -> assertEquals(50, count));
  }

  public static final class Controller {}

  public static final class Handler {
    private final Class<?> beanType;

    Handler(Class<?> beanType) {
      this.beanType = beanType;
    }

    public Class<?> getBeanType() {
      return beanType;
    }
  }

  public enum Dispatch { REQUEST, ASYNC }

  public static final class Request {
    boolean asyncStarted;
    Dispatch dispatcher = Dispatch.REQUEST;
    public boolean isAsyncStarted() {
      return asyncStarted;
    }

    public Dispatch getDispatcherType() {
      return dispatcher;
    }

    private final String method;
    private final String pattern;

    Request(String method, String pattern) {
      this.method = method;
      this.pattern = pattern;
    }

    public String getMethod() {
      return method;
    }

    public Object getAttribute(String name) {
      return SpringMvcBridge.BEST_MATCHING_PATTERN.equals(name) ? pattern : null;
    }
  }

  public static final class Response {
    int status;

    Response(int status) {
      this.status = status;
    }

    public int getStatus() {
      return status;
    }
  }

  private static final class Sink implements BridgeSink {
    private final List<String> symbols = java.util.Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> kinds = java.util.Collections.synchronizedList(new ArrayList<>());
    private final List<String[]> starts = new ArrayList<>();
    private volatile String method;
    private volatile String route;
    private volatile int status = -1;
    private volatile int scope = 1;
    private volatile BridgeSink.Outcome outcome;
    private volatile String thrownType;
    private volatile String thrownMessage;

    int starts() {
      return starts.size();
    }

    List<String> routesByMethod(String wanted) {
      List<String> result = new ArrayList<>();
      synchronized (starts) {
        for (String[] start : starts) if (start[0].equals(wanted)) result.add(start[1]);
      }
      return result;
    }

    @Override
    public boolean offerStart(String id, long ns, String method, String route) {
      this.method = method;
      this.route = route;
      synchronized (starts) {
        starts.add(new String[] {method, route});
      }
      return true;
    }

    @Override
    public boolean offerEvent(
        String id, String event, String parent, int kind, String symbol, long ns, int detail) {
      symbols.add(symbol);
      kinds.add(kind);
      return true;
    }

    @Override
    public boolean offerThrowEvent(
        String id, String event, String parent, String symbol, long ns, String type, String text) {
      thrownType = type;
      thrownMessage = text;
      symbols.add(symbol);
      kinds.add(BridgeEventKind.FRAME_THROW);
      return true;
    }

    @Override
    public boolean offerFinishWithOutcome(
        String id, long started, long finished, int status, long dropped, Outcome outcome) {
      this.outcome = outcome;
      return offerFinish(id, started, finished, status, dropped);
    }

    @Override
    public int applicationScope(Class<?> type) {
      return scope;
    }

    @Override
    public boolean offerFinish(String id, long started, long finished, int status, long dropped) {
      this.status = status;
      return true;
    }

    @Override
    public void reportIncomplete(int failureKind) {}
  }
}
