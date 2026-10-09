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
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void reset() {
    BootstrapBridge.resetForTest();
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
  void thrownHandlerDoesNotReportTheContainersDefaultStatus() {
    assertTrue(SpringMvcBridge.start(new Request("POST", "/orders"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalStateException("handler failed"));
    assertEquals("http.response unavailable", sink.symbols.get(1));
    assertEquals(0, sink.status);
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

  public static final class Request {
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
    private final int status;

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
