package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ReactorContextBridgeTest {
  private RecordingTestSink sink;

  @BeforeEach
  void setUp() {
    BootstrapBridge.resetForTest();
    sink = new RecordingTestSink();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void tearDown() {
    BootstrapBridge.resetForTest();
  }

  @Test
  void tokenTravelsAcrossAsyncThreadHopsWithoutThreadLocalAffinity() throws Exception {
    ReactorContextBridge.Token root =
        ReactorContextBridge.startRoot(
            "POST", "/orders", (tok, err, cancelled) ->
                BootstrapBridge.finishReactiveRecording(
                    tok.slot.state(), 202, err, false, cancelled));
    assertNotNull(root);
    assertFalse(BootstrapBridge.hasContext(), "startRoot must not bind sticky ThreadLocal");
    assertNull(ReactorContextBridge.currentToken());

    ReactorContextBridge.Token asyncToken = ReactorContextBridge.onAsyncLink(root, "reactor.hop");
    assertNotNull(asyncToken);
    assertEquals(root.recordingId(), asyncToken.recordingId());

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      CallableMono<String> mono =
          new CallableMono<>(
              () -> {
                assertSame(asyncToken, ReactorContextBridge.currentToken());
                assertTrue(BootstrapBridge.hasContext());
                BootstrapBridge.frameEnter("OrderService.processAsync");
                BootstrapBridge.frameExit("OrderService.processAsync", null);
                return "done";
              });
      @SuppressWarnings("unchecked")
      FakeMono<String> wrapped =
          (FakeMono<String>)
              ReactorContextBridge.wrapMono(
                  mono,
                  asyncToken,
                  (tok, err, cancelled) -> {
                    if (cancelled) ReactorContextBridge.signalCancel(tok);
                    else if (err != null) ReactorContextBridge.signalError(tok, err);
                    else ReactorContextBridge.signalComplete(tok);
                  },
                  null);
      assertNotNull(wrapped);

      Future<String> future =
          executor.submit(() -> wrapped.subscribeOnCurrentThread(new FakeContext()));
      assertEquals("done", future.get(5, TimeUnit.SECONDS));

      // Worker thread must have zero leftover request/token context after signal completion.
      boolean workerClean =
          executor
              .submit(
                  () -> !BootstrapBridge.hasContext() && ReactorContextBridge.currentToken() == null)
              .get(5, TimeUnit.SECONDS);
      assertTrue(workerClean);
    } finally {
      executor.shutdownNow();
    }

    RecordedRequest req = sink.recordings.get(root.recordingId());
    assertNotNull(req);
    assertEquals(1, req.finishes.get());
    assertEquals(BridgeSink.Outcome.RESPONDED, req.lastOutcome.kind());
    assertEquals(202, req.lastOutcome.httpStatus());
    assertTrue(req.events.stream().anyMatch(e -> e.kind == BridgeEventKind.ASYNC_LINK));
    RecordedEvent serviceEnter =
        req.events.stream()
            .filter(e -> e.kind == BridgeEventKind.FRAME_ENTER
                && e.symbol.equals("OrderService.processAsync"))
            .findFirst()
            .orElseThrow();
    assertEquals(asyncToken.parentEventId(), serviceEnter.parentEventId);
  }

  @Test
  void concurrentInterleavedRequestsMaintainStrictIsolationOnSharedThreads() throws Exception {
    ReactorContextBridge.Token tokenA =
        ReactorContextBridge.startRoot("GET", "/a", null);
    ReactorContextBridge.Token tokenB =
        ReactorContextBridge.startRoot("GET", "/b", null);
    assertNotNull(tokenA);
    assertNotNull(tokenB);

    ReactorContextBridge.Token branchA1 = ReactorContextBridge.onAsyncLink(tokenA, "link.a1");
    ReactorContextBridge.Token branchA2 = ReactorContextBridge.onAsyncLink(tokenA, "link.a2");
    ReactorContextBridge.Token branchB1 = ReactorContextBridge.onAsyncLink(tokenB, "link.b1");

    ExecutorService sharedPool = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch phase1 = new CountDownLatch(2);
      CountDownLatch phase2 = new CountDownLatch(1);
      Future<?> fA =
          sharedPool.submit(
              () -> {
                try (var s1 = ReactorContextBridge.enterScope(branchA1)) {
                  BootstrapBridge.frameEnter("A.step1");
                  phase1.countDown();
                  phase2.await(5, TimeUnit.SECONDS);
                  BootstrapBridge.frameExit("A.step1", null);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                }
                try (var s2 = ReactorContextBridge.enterScope(branchA2)) {
                  BootstrapBridge.frameEnter("A.step2");
                  BootstrapBridge.frameExit("A.step2", null);
                }
                assertNull(ReactorContextBridge.currentToken());
                assertFalse(BootstrapBridge.hasContext());
              });
      Future<?> fB =
          sharedPool.submit(
              () -> {
                try (var sB = ReactorContextBridge.enterScope(branchB1)) {
                  BootstrapBridge.frameEnter("B.step1");
                  phase1.countDown();
                  phase2.await(5, TimeUnit.SECONDS);
                  BootstrapBridge.frameExit("B.step1", null);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                }
                assertNull(ReactorContextBridge.currentToken());
                assertFalse(BootstrapBridge.hasContext());
              });
      assertTrue(phase1.await(5, TimeUnit.SECONDS));
      phase2.countDown();
      fA.get(5, TimeUnit.SECONDS);
      fB.get(5, TimeUnit.SECONDS);
    } finally {
      sharedPool.shutdownNow();
    }

    assertTrue(ReactorContextBridge.signalComplete(tokenA));
    assertTrue(ReactorContextBridge.signalComplete(tokenB));

    RecordedRequest recA = sink.recordings.get(tokenA.recordingId());
    RecordedRequest recB = sink.recordings.get(tokenB.recordingId());
    assertTrue(recA.events.stream().noneMatch(e -> e.symbol.startsWith("B.")));
    assertTrue(recB.events.stream().noneMatch(e -> e.symbol.startsWith("A.")));
    assertTrue(recA.events.stream().anyMatch(e -> e.symbol.equals("A.step1")));
    assertTrue(recA.events.stream().anyMatch(e -> e.symbol.equals("A.step2")));
    assertTrue(recB.events.stream().anyMatch(e -> e.symbol.equals("B.step1")));
  }

  @Test
  void terminalSignalsAreIdempotentAndDetachedZombieDoesNotBleedIntoActiveRequest() {
    ReactorContextBridge.Token tokenA =
        ReactorContextBridge.startRoot("DELETE", "/zombies", null);
    assertTrue(ReactorContextBridge.signalCancel(tokenA));
    assertFalse(ReactorContextBridge.signalComplete(tokenA));
    assertFalse(ReactorContextBridge.signalError(tokenA, new IllegalStateException("late")));

    RecordedRequest recA = sink.recordings.get(tokenA.recordingId());
    assertEquals(1, recA.finishes.get());
    assertEquals(BridgeSink.Outcome.CLIENT_ABORTED, recA.lastOutcome.kind());

    ReactorContextBridge.Token activeB =
        ReactorContextBridge.startRoot("GET", "/live", null);
    try (var liveScope = ReactorContextBridge.enterScope(activeB)) {
      BootstrapBridge.frameEnter("LiveHandler.begin");
      try (var zombieScope = ReactorContextBridge.enterScope(tokenA)) {
        // Suspended active request must not observe zombie activity, nor vice versa.
        assertFalse(BootstrapBridge.hasContext());
        BootstrapBridge.frameEnter("ZombieHandler.shouldNotRecord");
        BootstrapBridge.frameExit("ZombieHandler.shouldNotRecord", null);
      }
      assertTrue(BootstrapBridge.hasContext());
      assertSame(activeB, ReactorContextBridge.currentToken());
      BootstrapBridge.frameExit("LiveHandler.begin", null);
    }
    assertTrue(ReactorContextBridge.signalComplete(activeB));

    assertEquals(1, ReactorContextBridge.detachedContextCount());
    assertTrue(ReactorContextBridge.takeCorrelationGapObserved());

    RecordedRequest recB = sink.recordings.get(activeB.recordingId());
    assertTrue(recA.events.stream().noneMatch(e -> e.symbol.contains("shouldNotRecord")));
    assertTrue(recB.events.stream().noneMatch(e -> e.symbol.contains("shouldNotRecord")));
    assertTrue(recB.events.stream().anyMatch(e -> e.symbol.equals("LiveHandler.begin")));
  }

  @Test
  void missingContextAndIncompatibleMonoReportExplicitGapsWithoutFabrication() {
    assertNull(ReactorContextBridge.onAsyncLink(null, "missing.parent"));
    assertEquals(1, ReactorContextBridge.correlationGapCount());
    assertTrue(ReactorContextBridge.takeCorrelationGapObserved());
    assertFalse(BootstrapBridge.hasContext());
    assertNull(ReactorContextBridge.currentToken());

    ReactorContextBridge.Token token =
        ReactorContextBridge.startRoot("PUT", "/gap", null);
    assertTrue(ReactorContextBridge.reportCorrelationGap(token, "context_lost"));
    assertTrue(ReactorContextBridge.signalComplete(token));

    RecordedRequest rec = sink.recordings.get(token.recordingId());
    assertTrue(
        rec.events.stream()
            .anyMatch(
                e -> e.kind == BridgeEventKind.GAP
                    && BootstrapBridge.CORRELATION_LOST_SYMBOL.equals(e.symbol)));

    // Wrap fails closed (returns null) when publisher lacks Mono contextWrite/doOn* contracts.
    assertNull(ReactorContextBridge.wrapMono(new Object(), token, null, null));

    Runnable wrappedTask;
    try (var scope = ReactorContextBridge.enterScope(token.detach())) {
      wrappedTask = ReactorContextBridge.wrapRunnable(() -> {});
    }
    assertNotNull(wrappedTask);
    wrappedTask.run();
    assertNull(ReactorContextBridge.currentToken());
  }

  public interface MonoApi<T> {
    MonoApi<T> contextWrite(Function<Object, Object> fn);

    MonoApi<T> doOnSuccess(Consumer<Object> fn);

    MonoApi<T> doOnError(Consumer<Throwable> fn);

    MonoApi<T> doOnCancel(Runnable fn);
  }

  /** Public context verifying SpringMvcBridge.publicMethod access. */
  public static final class FakeContext {
    private final Map<Object, Object> values;

    FakeContext() {
      this(Map.of());
    }

    FakeContext(Map<Object, Object> values) {
      this.values = values;
    }

    public boolean hasKey(Object key) {
      return values.containsKey(key);
    }

    public Object get(Object key) {
      return values.get(key);
    }

    public FakeContext put(Object key, Object value) {
      Map<Object, Object> next = new ConcurrentHashMap<>(values);
      next.put(key, value);
      return new FakeContext(next);
    }
  }

  private abstract static class FakeMono<T> implements MonoApi<T> {
    @Override
    public FakeMono<T> contextWrite(Function<Object, Object> fn) {
      return new ContextWriteMono<>(this, fn);
    }

    @Override
    public FakeMono<T> doOnSuccess(Consumer<Object> fn) {
      return new HookMono<>(this, fn, null, null);
    }

    @Override
    public FakeMono<T> doOnError(Consumer<Throwable> fn) {
      return new HookMono<>(this, null, fn, null);
    }

    @Override
    public FakeMono<T> doOnCancel(Runnable fn) {
      return new HookMono<>(this, null, null, fn);
    }

    abstract T subscribeOnCurrentThread(FakeContext context);
  }

  private static final class CallableMono<T> extends FakeMono<T> {
    private final java.util.concurrent.Callable<T> action;

    CallableMono(java.util.concurrent.Callable<T> action) {
      this.action = action;
    }

    @Override
    T subscribeOnCurrentThread(FakeContext context) {
      ReactorContextBridge.Token token = ReactorContextBridge.fromReactorContext(context);
      try (var ignored = ReactorContextBridge.enterScope(token)) {
        return action.call();
      } catch (Exception error) {
        if (error instanceof RuntimeException rt) throw rt;
        throw new RuntimeException(error);
      }
    }
  }

  private static final class ContextWriteMono<T> extends FakeMono<T> {
    private final FakeMono<T> upstream;
    private final Function<Object, Object> fn;

    ContextWriteMono(FakeMono<T> upstream, Function<Object, Object> fn) {
      this.upstream = upstream;
      this.fn = fn;
    }

    @Override
    T subscribeOnCurrentThread(FakeContext context) {
      FakeContext enriched = (FakeContext) fn.apply(context);
      return upstream.subscribeOnCurrentThread(enriched);
    }
  }

  private static final class HookMono<T> extends FakeMono<T> {
    private final FakeMono<T> upstream;
    private final Consumer<Object> onSuccess;
    private final Consumer<Throwable> onError;
    private final Runnable onCancel;

    HookMono(
        FakeMono<T> upstream,
        Consumer<Object> onSuccess,
        Consumer<Throwable> onError,
        Runnable onCancel) {
      this.upstream = upstream;
      this.onSuccess = onSuccess;
      this.onError = onError;
      this.onCancel = onCancel;
    }

    @Override
    T subscribeOnCurrentThread(FakeContext context) {
      try {
        T value = upstream.subscribeOnCurrentThread(context);
        if (onSuccess != null) onSuccess.accept(value);
        return value;
      } catch (Throwable error) {
        if (onError != null) onError.accept(error);
        throw error;
      }
    }
  }

  static final class RecordedEvent {
    final String eventId;
    final String parentEventId;
    final int kind;
    final String symbol;
    final int detail;

    RecordedEvent(String eventId, String parentEventId, int kind, String symbol, int detail) {
      this.eventId = eventId;
      this.parentEventId = parentEventId;
      this.kind = kind;
      this.symbol = symbol;
      this.detail = detail;
    }
  }

  static final class RecordedRequest {
    final String recordingId;
    final String method;
    final String route;
    final List<RecordedEvent> events = new CopyOnWriteArrayList<>();
    final AtomicInteger finishes = new AtomicInteger();
    volatile BridgeSink.Outcome lastOutcome;
    volatile List<String> unsupportedCapabilities = List.of();

    RecordedRequest(String recordingId, String method, String route) {
      this.recordingId = recordingId;
      this.method = method;
      this.route = route;
    }
  }

  static class RecordingTestSink implements BridgeSink {
    final Map<String, RecordedRequest> recordings = new ConcurrentHashMap<>();
    final List<String> startedOrder = Collections.synchronizedList(new ArrayList<>());
    final AtomicInteger incompleteReports = new AtomicInteger();

    @Override
    public boolean offerStart(String recordingId, long monotonicNs, String method, String route) {
      recordings.put(recordingId, new RecordedRequest(recordingId, method, route));
      startedOrder.add(recordingId);
      return true;
    }

    @Override
    public boolean offerWebFluxStart(
        String recordingId, long monotonicNs, String method, String route) {
      return offerStart(recordingId, monotonicNs, method, route);
    }

    @Override
    public boolean offerEvent(
        String recordingId,
        String eventId,
        String parentEventId,
        int kind,
        String symbol,
        long monotonicNs,
        int detail) {
      RecordedRequest req = recordings.get(recordingId);
      if (req == null) return false;
      req.events.add(new RecordedEvent(eventId, parentEventId, kind, symbol, detail));
      return true;
    }

    @Override
    public boolean offerFinish(
        String recordingId,
        long startedMonotonicNs,
        long finishedMonotonicNs,
        int responseStatus,
        long droppedEvents) {
      return offerFinishWithOutcome(
          recordingId,
          startedMonotonicNs,
          finishedMonotonicNs,
          responseStatus,
          droppedEvents,
          null,
          null);
    }

    @Override
    public boolean offerFinishWithOutcome(
        String recordingId,
        long startedMonotonicNs,
        long finishedMonotonicNs,
        int responseStatus,
        long droppedEvents,
        Outcome outcome) {
      return offerFinishWithOutcome(
          recordingId,
          startedMonotonicNs,
          finishedMonotonicNs,
          responseStatus,
          droppedEvents,
          outcome,
          null);
    }

    @Override
    public boolean offerFinishWithOutcome(
        String recordingId,
        long startedMonotonicNs,
        long finishedMonotonicNs,
        int responseStatus,
        long droppedEvents,
        Outcome outcome,
        String[] unsupportedCapabilities) {
      RecordedRequest req = recordings.get(recordingId);
      if (req == null) return false;
      req.finishes.incrementAndGet();
      req.lastOutcome = outcome;
      req.unsupportedCapabilities =
          unsupportedCapabilities == null ? List.of() : List.of(unsupportedCapabilities);
      return true;
    }

    @Override
    public int applicationScope(Class<?> type) {
      return 1;
    }

    @Override
    public void reportIncomplete(int failureKind) {
      incompleteReports.incrementAndGet();
    }
  }
}
