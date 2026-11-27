package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WebFluxBridgeTest {
  private ReactorContextBridgeTest.RecordingTestSink sink;
  private final AtomicInteger scopeVerdict = new AtomicInteger(1);

  @BeforeEach
  void setUp() {
    BootstrapBridge.resetForTest();
    scopeVerdict.set(1);
    sink =
        new ReactorContextBridgeTest.RecordingTestSink() {
          @Override
          public int applicationScope(Class<?> type) {
            return scopeVerdict.get();
          }
        };
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void tearDown() {
    BootstrapBridge.resetForTest();
  }

  @Test
  void dispatcherControllerLifecycleTracksRouteTemplateAsyncFramesAndHttpStatus()
      throws Exception {
    FakeExchange exchange = new FakeExchange(Spring6Method.GET);
    FakePathPattern pattern = new FakePathPattern("/orders/{id}");
    exchange.getAttributes().put(WebFluxBridge.BEST_MATCHING_PATTERN, pattern);
    FakeHandlerMethod handler = new FakeHandlerMethod(SampleController.class);

    Object httpAct = WebFluxBridge.httpBoundaryEnter(exchange.getRequest(), exchange.getResponse());
    Object dispAct = WebFluxBridge.boundaryEnter(exchange, true);

    Object handlerAct = WebFluxBridge.handlerEnter(exchange, handler);
    assertNotNull(handlerAct);
    assertTrue(BootstrapBridge.hasContext());
    BootstrapBridge.frameEnter("SampleController.show");
    BootstrapBridge.frameExit("SampleController.show", null);

    @SuppressWarnings("unchecked")
    ReactivePublisher<String> handlerMono =
        (ReactivePublisher<String>)
            WebFluxBridge.handlerExit(
                handlerAct,
                new ReactivePublisher<>(
                    () -> {
                      BootstrapBridge.frameEnter("SampleService.loadAsync");
                      BootstrapBridge.frameExit("SampleService.loadAsync", null);
                      return "ok";
                    }),
                null);

    Object dispMonoObj =
        WebFluxBridge.boundaryExit(
            dispAct,
            ReactivePublisher.deferVoid(
                ctx -> {
                  handlerMono.subscribe(ctx);
                  exchange.response.statusCode = new FakeStatusCode(200);
                }),
            null);
    Object outerMonoObj = WebFluxBridge.boundaryExit(httpAct, dispMonoObj, null);

    // No ThreadLocal state may leak synchronously after exiting WebFlux boundary.
    assertFalse(BootstrapBridge.hasContext());
    assertNull(ReactorContextBridge.currentToken());

    ExecutorService worker = Executors.newSingleThreadExecutor();
    try {
      @SuppressWarnings("unchecked")
      ReactivePublisher<Void> outerMono = (ReactivePublisher<Void>) outerMonoObj;
      Future<?> done =
          worker.submit(
              () -> outerMono.subscribe(new ReactorContextBridgeTest.FakeContext()));
      done.get(5, TimeUnit.SECONDS);
      assertTrue(
          worker
              .submit(
                  () -> !BootstrapBridge.hasContext() && ReactorContextBridge.currentToken() == null)
              .get(5, TimeUnit.SECONDS));
    } finally {
      worker.shutdownNow();
    }

    assertEquals(1, sink.startedOrder.size());
    var rec = sink.recordings.get(sink.startedOrder.get(0));
    assertEquals("GET", rec.method);
    assertEquals("/orders/{id}", rec.route);
    assertEquals(1, rec.finishes.get());
    assertEquals(BridgeSink.Outcome.RESPONDED, rec.lastOutcome.kind());
    assertEquals(200, rec.lastOutcome.httpStatus());

    var handlerEnter =
        rec.events.stream()
            .filter(
                e -> e.kind == BridgeEventKind.FRAME_ENTER
                    && e.symbol.equals(WebFluxBridge.HANDLER_ADAPTER_SYMBOL))
            .findFirst()
            .orElseThrow();
    var asyncService =
        rec.events.stream()
            .filter(
                e -> e.kind == BridgeEventKind.FRAME_ENTER
                    && e.symbol.equals("SampleService.loadAsync"))
            .findFirst()
            .orElseThrow();
    assertEquals(handlerEnter.eventId, asyncService.parentEventId);
    assertTrue(
        rec.events.stream()
            .anyMatch(e -> e.kind == BridgeEventKind.RESPONSE && e.symbol.equals("http.response 200")));
  }

  @Test
  void functionalRoutingAvoidsDuplicateRootsAndResolvesLambdaScope() {
    FakeExchange exchange = new FakeExchange(Spring5Method.POST);
    exchange.getAttributes().put(WebFluxBridge.ROUTER_MATCHING_PATTERN, "/fn/{slug}");
    FakeServerRequest serverRequest = new FakeServerRequest(exchange);
    Function<Object, Object> fnHandler = req -> ReactivePublisher.just(new FakeServerResponse(201));

    // Step 1: inside DispatcherHandler + HandlerAdapter, functionalHandlerEnter must NOT open a
    // second handler frame or reset the active handlerToken parent.
    Object httpAct = WebFluxBridge.httpBoundaryEnter(exchange.getRequest(), exchange.getResponse());
    Object dispAct = WebFluxBridge.boundaryEnter(exchange, true);
    Object adapterAct = WebFluxBridge.handlerEnter(exchange, fnHandler);
    Object routeAct = WebFluxBridge.routeEnter(serverRequest);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> routeMono =
        (ReactivePublisher<Object>)
            WebFluxBridge.routeExit(routeAct, ReactivePublisher.just(fnHandler), null);
    routeMono.subscribe(new ReactorContextBridgeTest.FakeContext());

    Object fnAct = WebFluxBridge.functionalHandlerEnter(fnHandler, serverRequest);
    assertNotNull(fnAct);
    BootstrapBridge.frameEnter("FunctionalBody.run");
    BootstrapBridge.frameExit("FunctionalBody.run", null);
    Object fnResult =
        WebFluxBridge.functionalHandlerExit(
            fnAct, ReactivePublisher.just(new FakeServerResponse(201)), null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> adaptedMono =
        (ReactivePublisher<Object>) WebFluxBridge.handlerExit(adapterAct, fnResult, null);
    Object dispMono =
        WebFluxBridge.boundaryExit(
            dispAct,
            ReactivePublisher.deferVoid(
                ctx -> {
                  adaptedMono.subscribe(ctx);
                  exchange.response.rawStatus = 201;
                }),
            null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Void> outerMono =
        (ReactivePublisher<Void>) WebFluxBridge.boundaryExit(httpAct, dispMono, null);
    outerMono.subscribe(new ReactorContextBridgeTest.FakeContext());

    assertEquals(1, sink.startedOrder.size());
    var rec = sink.recordings.get(sink.startedOrder.get(0));
    long handlerFrameEnters =
        rec.events.stream()
            .filter(
                e -> e.kind == BridgeEventKind.FRAME_ENTER
                    && (e.symbol.equals(WebFluxBridge.HANDLER_FUNCTION_SYMBOL)
                        || e.symbol.equals(WebFluxBridge.HANDLER_ADAPTER_SYMBOL)))
            .count();
    assertEquals(1, handlerFrameEnters, "HandlerAdapter + HandlerFunction must open only 1 frame");
    var bodyEnter =
        rec.events.stream()
            .filter(e -> e.symbol.equals("FunctionalBody.run") && e.kind == BridgeEventKind.FRAME_ENTER)
            .findFirst()
            .orElseThrow();
    var handlerEnter =
        rec.events.stream()
            .filter(
                e -> e.kind == BridgeEventKind.FRAME_ENTER
                    && (e.symbol.equals(WebFluxBridge.HANDLER_FUNCTION_SYMBOL)
                        || e.symbol.equals(WebFluxBridge.HANDLER_ADAPTER_SYMBOL)))
            .findFirst()
            .orElseThrow();
    assertEquals(handlerEnter.eventId, bodyEnter.parentEventId);
    assertEquals(BridgeSink.Outcome.RESPONDED, rec.lastOutcome.kind());
    assertEquals(201, rec.lastOutcome.httpStatus());

    // Step 2: Standalone functionalHandlerEnter without outer boundary reports provisional status
    // honestly as UNOBSERVED rather than claiming final RESPONDED status.
    FakeExchange standaloneExchange = new FakeExchange(Spring6Method.GET);
    standaloneExchange.getAttributes().put(WebFluxBridge.ROUTER_MATCHING_PATTERN, "/standalone");
    FakeServerRequest standaloneReq = new FakeServerRequest(standaloneExchange);
    Object standaloneAct = WebFluxBridge.functionalHandlerEnter(fnHandler, standaloneReq);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> standaloneMono =
        (ReactivePublisher<Object>)
            WebFluxBridge.functionalHandlerExit(
                standaloneAct, ReactivePublisher.just(new FakeServerResponse(202)), null);
    standaloneMono.subscribe(new ReactorContextBridgeTest.FakeContext());
    assertEquals(2, sink.startedOrder.size());
    var standaloneRec = sink.recordings.get(sink.startedOrder.get(1));
    assertEquals(BridgeSink.Outcome.UNOBSERVED, standaloneRec.lastOutcome.kind());
    assertTrue(
        standaloneRec.events.stream()
            .anyMatch(e -> e.kind == BridgeEventKind.RESPONSE && e.symbol.contains("provisional")));
  }

  @Test
  void reactiveErrorAndCancellationProduceHonestOutcomes() {
    // 1) Unhandled reactive error -> EXCEPTION_PROPAGATED with thrownFromEventId.
    FakeExchange errExchange = new FakeExchange(Spring6Method.POST);
    errExchange.getAttributes().put(WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/err"));
    Object errHttp = WebFluxBridge.httpBoundaryEnter(errExchange.getRequest(), errExchange.getResponse());
    Object errDisp = WebFluxBridge.boundaryEnter(errExchange, true);
    Object errHandler =
        WebFluxBridge.handlerEnter(errExchange, new FakeHandlerMethod(SampleController.class));
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> failingMono =
        (ReactivePublisher<Object>)
            WebFluxBridge.handlerExit(
                errHandler,
                new ReactivePublisher<>(
                    () -> {
                      throw new IllegalStateException("downstream reactive boom");
                    }),
                null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Void> outerErr =
        (ReactivePublisher<Void>)
            WebFluxBridge.boundaryExit(
                errHttp,
                WebFluxBridge.boundaryExit(
                    errDisp, ReactivePublisher.deferVoid(failingMono::subscribe), null),
                null);
    try {
      outerErr.subscribe(new ReactorContextBridgeTest.FakeContext());
    } catch (IllegalStateException expected) {
      // Expected propagation out of publisher.
    }
    var errRec = sink.recordings.get(sink.startedOrder.get(0));
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, errRec.lastOutcome.kind());
    assertEquals("java.lang.IllegalStateException", errRec.lastOutcome.exceptionType());
    assertNotNull(errRec.lastOutcome.thrownFromEventId());

    // 2) Upstream error handled by outer boundary (HTTP 500 response committed) -> RESPONDED 500.
    FakeExchange handledExchange = new FakeExchange(Spring6Method.GET);
    handledExchange.getAttributes().put(
        WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/handled"));
    Object hHttp =
        WebFluxBridge.httpBoundaryEnter(handledExchange.getRequest(), handledExchange.getResponse());
    Object hDisp = WebFluxBridge.boundaryEnter(handledExchange, true);
    Object hAdapter =
        WebFluxBridge.handlerEnter(handledExchange, new FakeHandlerMethod(SampleController.class));
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> innerFail =
        (ReactivePublisher<Object>)
            WebFluxBridge.handlerExit(
                hAdapter,
                new ReactivePublisher<>(
                    () -> {
                      throw new IllegalArgumentException("bad payload");
                    }),
                null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Void> handledOuter =
        (ReactivePublisher<Void>)
            WebFluxBridge.boundaryExit(
                hHttp,
                WebFluxBridge.boundaryExit(
                    hDisp,
                    ReactivePublisher.deferVoid(
                        ctx -> {
                          try {
                            innerFail.subscribe(ctx);
                          } catch (IllegalArgumentException handled) {
                            handledExchange.response.statusCode = new FakeStatusCode(500);
                          }
                        }),
                    null),
                null);
    handledOuter.subscribe(new ReactorContextBridgeTest.FakeContext());
    var handledRec = sink.recordings.get(sink.startedOrder.get(1));
    assertTrue(handledRec.events.stream().anyMatch(e -> e.kind == BridgeEventKind.FRAME_THROW));
    assertEquals(BridgeSink.Outcome.RESPONDED, handledRec.lastOutcome.kind());
    assertEquals(500, handledRec.lastOutcome.httpStatus());

    // 3) Downstream client cancellation -> CLIENT_ABORTED and never claims a response status.
    FakeExchange cancelExchange = new FakeExchange(Spring6Method.GET);
    cancelExchange.getAttributes().put(
        WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/cancel"));
    Object cHttp =
        WebFluxBridge.httpBoundaryEnter(cancelExchange.getRequest(), cancelExchange.getResponse());
    Object cDisp = WebFluxBridge.boundaryEnter(cancelExchange, true);
    Object cAdapter =
        WebFluxBridge.handlerEnter(cancelExchange, new FakeHandlerMethod(SampleController.class));
    Object cHandlerMono =
        WebFluxBridge.handlerExit(cAdapter, new ReactivePublisher<>(() -> "pending"), null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Void> cancelOuter =
        (ReactivePublisher<Void>)
            WebFluxBridge.boundaryExit(
                cHttp, WebFluxBridge.boundaryExit(cDisp, cHandlerMono, null), null);
    cancelOuter.cancel();
    var cancelRec = sink.recordings.get(sink.startedOrder.get(2));
    assertEquals(BridgeSink.Outcome.CLIENT_ABORTED, cancelRec.lastOutcome.kind());
    assertEquals(0, cancelRec.lastOutcome.httpStatus());
    assertTrue(
        cancelRec.events.stream()
            .anyMatch(e -> e.kind == BridgeEventKind.RESPONSE && e.symbol.contains("cancelled")));
  }

  @Test
  void scopeExclusionUnknownScopeInvalidRouteAndUnwrappableMonoFailClosed() {
    // Out-of-scope handler must never open a recording and must clean exchange session attributes.
    scopeVerdict.set(0);
    FakeExchange excluded = new FakeExchange(Spring6Method.GET);
    excluded.getAttributes().put(WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/skip"));
    Object exHttp = WebFluxBridge.httpBoundaryEnter(excluded.getRequest(), excluded.getResponse());
    Object exDisp = WebFluxBridge.boundaryEnter(excluded, true);
    assertNull(WebFluxBridge.handlerEnter(excluded, new FakeHandlerMethod(SampleController.class)));
    Object exDispRet = WebFluxBridge.boundaryExit(exDisp, ReactivePublisher.just("ok"), null);
    WebFluxBridge.boundaryExit(exHttp, exDispRet, null);
    assertEquals(0, sink.startedOrder.size());
    assertFalse(excluded.getAttributes().containsKey(WebFluxBridge.EXCHANGE_SESSION_ATTR));

    // Unknown handler scope starts recording with HANDLER_UNRESOLVED_SYMBOL gap.
    scopeVerdict.set(-1);
    FakeExchange unknown = new FakeExchange(Spring6Method.GET);
    unknown.getAttributes().put(WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/unk"));
    Object uHttp = WebFluxBridge.httpBoundaryEnter(unknown.getRequest(), unknown.getResponse());
    Object uDisp = WebFluxBridge.boundaryEnter(unknown, true);
    Object uHandler =
        WebFluxBridge.handlerEnter(unknown, new FakeHandlerMethod(SampleController.class));
    assertNotNull(uHandler);
    Object uHandlerRet = WebFluxBridge.handlerExit(uHandler, ReactivePublisher.just("ok"), null);
    @SuppressWarnings("unchecked")
    ReactivePublisher<Object> uOuter =
        (ReactivePublisher<Object>)
            WebFluxBridge.boundaryExit(
                uHttp, WebFluxBridge.boundaryExit(uDisp, uHandlerRet, null), null);
    uOuter.subscribe(new ReactorContextBridgeTest.FakeContext());
    var uRec = sink.recordings.get(sink.startedOrder.get(0));
    assertTrue(
        uRec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.HANDLER_UNRESOLVED_SYMBOL.equals(e.symbol)));

    // Invalid route containing query string must be rejected cleanly.
    scopeVerdict.set(1);
    FakeExchange invalid = new FakeExchange(Spring6Method.GET);
    invalid.getAttributes().put(WebFluxBridge.BEST_MATCHING_PATTERN, "/raw?secret=1");
    Object invHttp = WebFluxBridge.httpBoundaryEnter(invalid.getRequest(), invalid.getResponse());
    Object invDisp = WebFluxBridge.boundaryEnter(invalid, true);
    assertNull(WebFluxBridge.handlerEnter(invalid, new FakeHandlerMethod(SampleController.class)));
    WebFluxBridge.boundaryExit(
        invHttp, WebFluxBridge.boundaryExit(invDisp, ReactivePublisher.just("ok"), null), null);
    assertEquals(1, sink.startedOrder.size());

    // Unwrappable return value at outer boundary closes recording immediately and flags capability gap.
    FakeExchange unwrappable = new FakeExchange(Spring6Method.GET);
    unwrappable.getAttributes().put(
        WebFluxBridge.BEST_MATCHING_PATTERN, new FakePathPattern("/fail-closed"));
    Object wHttp =
        WebFluxBridge.httpBoundaryEnter(unwrappable.getRequest(), unwrappable.getResponse());
    Object wDisp = WebFluxBridge.boundaryEnter(unwrappable, true);
    Object wHandler =
        WebFluxBridge.handlerEnter(unwrappable, new FakeHandlerMethod(SampleController.class));
    // Handler return itself is also unwrappable.
    WebFluxBridge.handlerExit(wHandler, new Object(), null);
    WebFluxBridge.boundaryExit(wHttp, WebFluxBridge.boundaryExit(wDisp, new Object(), null), null);
    assertEquals(2, sink.startedOrder.size());
    var closedRec = sink.recordings.get(sink.startedOrder.get(1));
    assertEquals(1, closedRec.finishes.get());
    assertTrue(closedRec.unsupportedCapabilities.contains("async_correlation"));
    assertTrue(
        closedRec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.CORRELATION_LOST_SYMBOL.equals(e.symbol)));
    assertTrue(ReactorContextBridge.takePropagationUnavailable());
  }

  public static final class SampleController {}

  public enum Spring6Method {
    GET,
    POST
  }

  public enum Spring5Method {
    POST
  }

  public static final class FakePathPattern {
    private final String pattern;

    FakePathPattern(String pattern) {
      this.pattern = pattern;
    }

    public String getPatternString() {
      return pattern;
    }
  }

  public static final class FakeHandlerMethod {
    private final Class<?> beanType;

    FakeHandlerMethod(Class<?> beanType) {
      this.beanType = beanType;
    }

    public Class<?> getBeanType() {
      return beanType;
    }
  }

  public static final class FakeStatusCode {
    private final int code;

    FakeStatusCode(int code) {
      this.code = code;
    }

    public int value() {
      return code;
    }
  }

  public static final class FakeRequest {
    private final Object method;

    FakeRequest(Object method) {
      this.method = method;
    }

    public Object getMethod() {
      return method instanceof Spring6Method ? method : null;
    }

    public String getMethodValue() {
      return method.toString();
    }
  }

  public static final class FakeResponse {
    FakeStatusCode statusCode;
    Integer rawStatus;

    public FakeStatusCode getStatusCode() {
      return statusCode;
    }

    public Integer getRawStatusCode() {
      return rawStatus;
    }
  }

  public static final class FakeExchange {
    final FakeRequest request;
    final FakeResponse response = new FakeResponse();
    final Map<String, Object> attrs = new ConcurrentHashMap<>();

    FakeExchange(Object method) {
      this.request = new FakeRequest(method);
    }

    public FakeRequest getRequest() {
      return request;
    }

    public FakeResponse getResponse() {
      return response;
    }

    public Object getAttribute(String key) {
      return attrs.get(key);
    }

    public Map<String, Object> getAttributes() {
      return attrs;
    }
  }

  public static final class FakeServerRequest {
    private final FakeExchange exchange;

    FakeServerRequest(FakeExchange exchange) {
      this.exchange = exchange;
    }

    public Object method() {
      return exchange.getRequest().getMethod();
    }

    public String methodName() {
      return exchange.getRequest().getMethodValue();
    }

    public Optional<Object> attribute(String key) {
      return Optional.ofNullable(exchange.getAttributes().get(key));
    }

    public Map<String, Object> attributes() {
      return exchange.getAttributes();
    }

    public FakeExchange exchange() {
      return exchange;
    }
  }

  public static final class FakeServerResponse {
    private final int code;

    FakeServerResponse(int code) {
      this.code = code;
    }

    public FakeStatusCode statusCode() {
      return new FakeStatusCode(code);
    }

    public Integer rawStatusCode() {
      return code;
    }
  }

  public static final class ReactivePublisher<T> {
    private final Function<ReactorContextBridgeTest.FakeContext, T> runner;
    private Function<Object, Object> ctxModifier = Function.identity();
    private Consumer<Object> onSuccess;
    private Consumer<Throwable> onError;
    private Runnable onCancel;

    ReactivePublisher(Callable<T> callable) {
      this(
          ctx -> {
            try (var ignored =
                ReactorContextBridge.enterScope(ReactorContextBridge.fromReactorContext(ctx))) {
              return callable.call();
            } catch (Exception e) {
              if (e instanceof RuntimeException rt) throw rt;
              throw new RuntimeException(e);
            }
          });
    }

    private ReactivePublisher(Function<ReactorContextBridgeTest.FakeContext, T> runner) {
      this.runner = runner;
    }

    static <T> ReactivePublisher<T> just(T value) {
      return new ReactivePublisher<>(() -> value);
    }

    static ReactivePublisher<Void> deferVoid(
        Consumer<ReactorContextBridgeTest.FakeContext> action) {
      return new ReactivePublisher<>(
          ctx -> {
            try (var ignored =
                ReactorContextBridge.enterScope(ReactorContextBridge.fromReactorContext(ctx))) {
              action.accept(ctx);
              return null;
            }
          });
    }

    public ReactivePublisher<T> contextWrite(Function<Object, Object> fn) {
      ReactivePublisher<T> next = new ReactivePublisher<>(runner);
      next.ctxModifier = ctxModifier.andThen(fn);
      next.onSuccess = onSuccess;
      next.onError = onError;
      next.onCancel = onCancel;
      return next;
    }

    public ReactivePublisher<T> doOnSuccess(Consumer<Object> fn) {
      ReactivePublisher<T> next = copy();
      next.onSuccess = combineConsumer(onSuccess, fn);
      return next;
    }

    public ReactivePublisher<T> doOnError(Consumer<Throwable> fn) {
      ReactivePublisher<T> next = copy();
      next.onError = combineConsumer(onError, fn);
      return next;
    }

    public ReactivePublisher<T> doOnCancel(Runnable fn) {
      ReactivePublisher<T> next = copy();
      Runnable prev = onCancel;
      next.onCancel =
          prev == null
              ? fn
              : () -> {
                fn.run();
                prev.run();
              };
      return next;
    }

    private ReactivePublisher<T> copy() {
      ReactivePublisher<T> next = new ReactivePublisher<>(runner);
      next.ctxModifier = ctxModifier;
      next.onSuccess = onSuccess;
      next.onError = onError;
      next.onCancel = onCancel;
      return next;
    }

    private static <X> Consumer<X> combineConsumer(Consumer<X> first, Consumer<X> second) {
      if (first == null) return second;
      return x -> {
        first.accept(x);
        second.accept(x);
      };
    }

    public T subscribe(ReactorContextBridgeTest.FakeContext context) {
      ReactorContextBridgeTest.FakeContext effective =
          (ReactorContextBridgeTest.FakeContext) ctxModifier.apply(context);
      try {
        T val = runner.apply(effective);
        if (onSuccess != null) onSuccess.accept(val);
        return val;
      } catch (Throwable err) {
        if (onError != null) onError.accept(err);
        throw err;
      }
    }

    public void cancel() {
      if (onCancel != null) onCancel.run();
    }
  }
}
