package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeSink;
import dev.xtrace.agent.bootstrap.ReactorContextBridge;
import dev.xtrace.agent.bootstrap.WebFluxBridge;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.MethodDelegation;
import net.bytebuddy.implementation.bind.annotation.AllArguments;
import net.bytebuddy.implementation.bind.annotation.Origin;
import net.bytebuddy.implementation.bind.annotation.RuntimeType;
import net.bytebuddy.implementation.bind.annotation.This;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.OutcomeKind;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;

class WebFluxInstrumentationTest {
  @BeforeEach
  void resetFlags() {
    ReactorContextInstrumentation.resetForTest();
    WebFluxInstrumentation.resetForTest();
    ReactorContextBridge.takePropagationUnavailable();
    ReactorContextBridge.takeCorrelationGapObserved();
    WebFluxBridge.takeObservationUnavailable();
    WebFluxBridge.takeInstrumentationUnavailable();
  }

  @AfterEach
  void cleanup() {
    ReactorContextInstrumentation.resetForTest();
    WebFluxInstrumentation.resetForTest();
    ReactorContextBridge.takePropagationUnavailable();
    ReactorContextBridge.takeCorrelationGapObserved();
    WebFluxBridge.takeObservationUnavailable();
    WebFluxBridge.takeInstrumentationUnavailable();
  }

  @Test
  void acceptsSpring53Through7AndRejectsOlderOrNewerVersions() {
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("5.3.39", 5, 3, 8));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("6.0.0", 5, 3, 8));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("6.1.14", 5, 3, 8));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("7.0.0-M1", 5, 3, 8));

    assertFalse(ReactorContextInstrumentation.isSupportedVersion("5.2.25.RELEASE", 5, 3, 8));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("5.0.0", 5, 3, 8));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("8.0.0", 5, 3, 8));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("bad", 5, 3, 8));
  }

  @Test
  void transformsWebFluxContractsAcrossVersionsAndRejectsUnsupportedSpringJar(
      @TempDir Path tempDir) throws Exception {
    Map<String, byte[]> defs = new LinkedHashMap<>();
    defs.putAll(ReactorContextInstrumentationTest.buildReactorStubDefinitions(true));
    defs.putAll(buildWebFluxStubDefinitions(true));

    Path spring6Jar =
        ReactorContextInstrumentationTest.writeJar(
            tempDir.resolve("spring-webflux-6.1.14.jar"), "6.1.14", defs);
    Path spring52Jar =
        ReactorContextInstrumentationTest.writeJar(
            tempDir.resolve("spring-webflux-5.2.9.jar"), "5.2.9.RELEASE", defs);

    var listener = WebFluxInstrumentation.failureListener(() -> {});
    var locator =
        new ClassFileLocator.Compound(
            new ClassFileLocator.Simple(defs),
            ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    TypePool pool = TypePool.Default.of(locator);
    var transformer =
        WebFluxInstrumentation.configure(
                new AgentBuilder.Default()
                    .disableClassFormatChanges()
                    .with(new AgentBuilder.LocationStrategy.Simple(locator))
                    .with(listener),
                listener,
                pool)
            .makeRaw();

    try (URLClassLoader loader =
        new ReactorContextInstrumentationTest.TransformingJarClassLoader(
            new URL[] {spring6Jar.toUri().toURL()},
            getClass().getClassLoader(),
            defs,
            transformer)) {
      byte[] originalDispatcher = defs.get(WebFluxInstrumentation.DISPATCHER_HANDLER);
      byte[] transformedDispatcher =
          transformer.transform(
              loader,
              WebFluxInstrumentation.DISPATCHER_HANDLER.replace('.', '/'),
              null,
              null,
              originalDispatcher);
      assertNotNull(transformedDispatcher, "Spring 6.1.14 DispatcherHandler should transform");
      assertFalse(WebFluxBridge.takeInstrumentationUnavailable());

      byte[] originalHttp = defs.get(WebFluxInstrumentation.HTTP_WEB_HANDLER_ADAPTER);
      byte[] transformedHttp =
          transformer.transform(
              loader,
              WebFluxInstrumentation.HTTP_WEB_HANDLER_ADAPTER.replace('.', '/'),
              null,
              null,
              originalHttp);
      assertNotNull(transformedHttp, "Spring 6.1.14 HttpWebHandlerAdapter should transform");
    }

    // Unsupported Spring 5.2 JAR must fail closed and stay untransformed.
    try (URLClassLoader oldLoader =
        new URLClassLoader(new URL[] {spring52Jar.toUri().toURL()}, getClass().getClassLoader())) {
      byte[] originalDispatcher = defs.get(WebFluxInstrumentation.DISPATCHER_HANDLER);
      byte[] transformed =
          transformer.transform(
              oldLoader,
              WebFluxInstrumentation.DISPATCHER_HANDLER.replace('.', '/'),
              null,
              null,
              originalDispatcher);
      assertNull(transformed, "Spring 5.2.9 DispatcherHandler must fail closed");
      assertTrue(WebFluxBridge.takeInstrumentationUnavailable());
    }

    // Missing DispatcherHandler contract fails closed in TypePool verification.
    Map<String, byte[]> incompleteDefs = new LinkedHashMap<>();
    incompleteDefs.putAll(ReactorContextInstrumentationTest.buildReactorStubDefinitions(true));
    incompleteDefs.putAll(buildWebFluxStubDefinitions(false));
    TypePool incompletePool =
        TypePool.Default.of(
            new ClassFileLocator.Compound(
                new ClassFileLocator.Simple(incompleteDefs),
                ClassFileLocator.ForClassLoader.of(getClass().getClassLoader())));
    assertFalse(WebFluxInstrumentation.supportsWebFluxContract(incompletePool));
  }

  @Test
  void blindClassLoaderWithoutBootstrapVisibilityFailsClosed() {
    URLClassLoader blind =
        new URLClassLoader(new URL[0], ClassLoader.getPlatformClassLoader());
    assertFalse(
        ReactorContextInstrumentation.bootstrapVisible(
            blind, ReactorContextBridge.class));
    assertFalse(
        ReactorContextInstrumentation.bootstrapVisible(
            blind, WebFluxBridge.class));
  }

  @Test
  void recordingWriterEncodesWebFluxDriverCapabilitiesAsyncLinksGapsAndCancelOnWire()
      throws Exception {
    CapturingTransport transport = new CapturingTransport();
    BoundedEventQueue queue = new BoundedEventQueue(256, 256 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    try (RecordingWriter writer =
        new RecordingWriter(transport, queue, sink, Duration.ofSeconds(2))) {
      writer.start();
      assertTrue(BootstrapBridge.install(sink));

      try {
        ReactorContextBridge.Token tok =
            ReactorContextBridge.startRoot(
                "GET",
                "/webflux/{id}",
                (t, error, cancelled) -> {});
        assertNotNull(tok);
        ReactorContextBridge.Token link = ReactorContextBridge.onAsyncLink(tok, "reactor.hop");
        ReactorContextBridge.reportCorrelationGap(link, "detached_test");
        String recordingId = tok.recordingId();

        // Emit explicit cancelled finish with unsupported capability via BridgeSink.
        assertTrue(
            sink.offerFinishWithOutcome(
                recordingId,
                System.nanoTime() - 10_000,
                System.nanoTime(),
                0,
                0,
                new BridgeSink.Outcome(BridgeSink.Outcome.CLIENT_ABORTED, 0, null, null, null),
                new String[] {"async_correlation", "Invalid-Code!"}));
      } finally {
        BootstrapBridge.disable(sink);
      }
    }

    assertNotNull(transport.capabilities);
    assertTrue(
        transport.capabilities.getCapabilitiesList().stream()
            .anyMatch(c -> "async_correlation".equals(c.getName())));

    assertEquals(1, transport.starts.size());
    RecordingStarted started = transport.starts.get(0);
    assertEquals("GET", started.getMethod());
    assertEquals("/webflux/{id}", started.getMatchedRouteTemplate());

    var events =
        transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    var reqUpdate =
        events.stream()
            .filter(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_REQUEST_UPDATE)
            .findFirst()
            .orElseThrow();
    assertEquals("spring-webflux", reqUpdate.getInteraction().getDriver());
    assertEquals("GET", reqUpdate.getInteraction().getMethod());
    assertEquals("/webflux/{id}", reqUpdate.getInteraction().getPath());

    assertTrue(
        events.stream()
            .anyMatch(e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_ASYNC_LINK));
    assertTrue(
        events.stream()
            .anyMatch(
                e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
                    && e.getGap().getReason() == GapReason.GAP_REASON_CORRELATION_LOST));

    assertEquals(1, transport.finishes.size());
    RecordingFinished finished = transport.finishes.get(0);
    assertEquals(OutcomeKind.OUTCOME_KIND_CLIENT_ABORTED, finished.getOutcome().getKind());
    assertEquals(List.of("async_correlation"), finished.getUnsupportedCapabilityCodesList());
  }

  @Test
  void executesTransformedWebFluxPipelineWithAsyncReactorHopThroughRecordingWriter(
      @TempDir Path tempDir) throws Exception {
    Map<String, byte[]> defs = new LinkedHashMap<>();
    defs.putAll(ReactorContextInstrumentationTest.buildReactorStubDefinitions(true));
    defs.putAll(buildWebFluxStubDefinitions(true));

    Path combinedJar =
        ReactorContextInstrumentationTest.writeJar(
            tempDir.resolve("spring-webflux-6.2.1.jar"), "6.2.1", defs);

    var wfListener = WebFluxInstrumentation.failureListener(() -> {});
    var rxListener = new ReactorContextInstrumentation.FailureListener(() -> {});
    var locator =
        new ClassFileLocator.Compound(
            new ClassFileLocator.Simple(defs),
            ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    TypePool pool = TypePool.Default.of(locator);
    AgentBuilder base =
        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(new AgentBuilder.LocationStrategy.Simple(locator));
    var wfTransformer =
        WebFluxInstrumentation.configure(base.with(wfListener), wfListener, pool).makeRaw();
    var rxTransformer =
        ReactorContextInstrumentation.configure(base.with(rxListener), rxListener, pool).makeRaw();

    java.lang.instrument.ClassFileTransformer combined =
        new java.lang.instrument.ClassFileTransformer() {
          @Override
          public byte[] transform(
              ClassLoader loader,
              String className,
              Class<?> classBeingRedefined,
              java.security.ProtectionDomain domain,
              byte[] bytes)
              throws java.lang.instrument.IllegalClassFormatException {
            byte[] current = bytes;
            byte[] step1 =
                wfTransformer.transform(loader, className, classBeingRedefined, domain, current);
            if (step1 != null) current = step1;
            byte[] step2 =
                rxTransformer.transform(loader, className, classBeingRedefined, domain, current);
            return step2 != null ? step2 : (step1 != null ? current : null);
          }
        };

    CapturingTransport transport = new CapturingTransport();
    BoundedEventQueue queue = new BoundedEventQueue(256, 256 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    sink.useScope(new ApplicationScope(List.of("demo.webflux"), List.of()));

    try (RecordingWriter writer =
            new RecordingWriter(transport, queue, sink, Duration.ofSeconds(2));
        URLClassLoader loader =
            new ReactorContextInstrumentationTest.TransformingJarClassLoader(
                new URL[] {combinedJar.toUri().toURL()},
                getClass().getClassLoader(),
                defs,
                combined)) {
      writer.start();
      assertTrue(BootstrapBridge.install(sink));
      try {
        Object httpReq =
            loader.loadClass("org.springframework.http.server.reactive.TestRequest")
                .getDeclaredConstructor()
                .newInstance();
        Object httpResp =
            loader.loadClass("org.springframework.http.server.reactive.TestResponse")
                .getDeclaredConstructor()
                .newInstance();
        Object adapter =
            loader.loadClass("org.springframework.web.reactive.TestHandlerAdapter")
                .getDeclaredConstructor()
                .newInstance();
        Object sampleController =
            loader.loadClass("demo.webflux.SampleController")
                .getDeclaredConstructor()
                .newInstance();
        Object dispatcher =
            loader.loadClass(WebFluxInstrumentation.DISPATCHER_HANDLER)
                .getDeclaredConstructor()
                .newInstance();
        dispatcher.getClass().getField("adapter").set(dispatcher, adapter);
        dispatcher.getClass().getField("handler").set(dispatcher, sampleController);
        dispatcher.getClass().getField("routePattern").set(dispatcher, "/api/items/{id}");

        Object httpAdapter =
            loader.loadClass(WebFluxInstrumentation.HTTP_WEB_HANDLER_ADAPTER)
                .getDeclaredConstructor()
                .newInstance();
        httpAdapter.getClass().getField("delegate").set(httpAdapter, dispatcher);

        Method httpHandle =
            httpAdapter
                .getClass()
                .getMethod(
                    "handle",
                    loader.loadClass(WebFluxInstrumentation.SERVER_HTTP_REQUEST),
                    loader.loadClass(WebFluxInstrumentation.SERVER_HTTP_RESPONSE));

        Object outerMono = httpHandle.invoke(httpAdapter, httpReq, httpResp);
        assertFalse(BootstrapBridge.hasContext(), "assembly thread must stay clean");
        assertNull(ReactorContextBridge.currentToken());

        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
          Object ctx =
              loader.loadClass("reactor.util.context.TestContext")
                  .getDeclaredConstructor()
                  .newInstance();
          Method runMono = outerMono.getClass().getMethod("run", Object.class);
          worker
              .submit(
                  () -> {
                    try {
                      return runMono.invoke(outerMono, ctx);
                    } catch (Exception e) {
                      throw new RuntimeException(e);
                    }
                  })
              .get(5, TimeUnit.SECONDS);
          assertTrue(
              worker
                  .submit(
                      () ->
                          !BootstrapBridge.hasContext()
                              && ReactorContextBridge.currentToken() == null)
                  .get(5, TimeUnit.SECONDS));
        } finally {
          worker.shutdownNow();
        }
      } finally {
        BootstrapBridge.disable(sink);
      }
    }

    assertEquals(1, transport.starts.size());
    assertEquals("POST", transport.starts.get(0).getMethod());
    assertEquals("/api/items/{id}", transport.starts.get(0).getMatchedRouteTemplate());
    var events = transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertTrue(
        events.stream()
            .anyMatch(
                e ->
                    e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_REQUEST_UPDATE
                        && "spring-webflux".equals(e.getInteraction().getDriver())));
    assertTrue(
        events.stream()
            .anyMatch(
                e ->
                    e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER
                        && "AsyncService.step".equals(e.getSymbol())));
    assertEquals(1, transport.finishes.size());
    assertEquals(OutcomeKind.OUTCOME_KIND_RESPONDED, transport.finishes.get(0).getOutcome().getKind());
    assertEquals(201, transport.finishes.get(0).getOutcome().getHttpStatus());
  }

  private static Map<String, byte[]> buildWebFluxStubDefinitions(boolean validDispatcher) {
    Map<String, byte[]> map = new LinkedHashMap<>();

    DynamicType.Unloaded<?> req =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.SERVER_HTTP_REQUEST)
            .defineMethod("getMethod", Object.class, Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(req.getTypeDescription().getName(), req.getBytes());

    DynamicType.Unloaded<?> resp =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.SERVER_HTTP_RESPONSE)
            .defineMethod("getStatusCode", Object.class, Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(resp.getTypeDescription().getName(), resp.getBytes());

    DynamicType.Unloaded<?> exchange =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.SERVER_WEB_EXCHANGE)
            .defineMethod("getRequest", req.getTypeDescription(), Visibility.PUBLIC)
            .withoutCode()
            .defineMethod("getResponse", resp.getTypeDescription(), Visibility.PUBLIC)
            .withoutCode()
            .defineMethod("getAttributes", Map.class, Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(exchange.getTypeDescription().getName(), exchange.getBytes());

    DynamicType.Unloaded<?> serverRequest =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.SERVER_REQUEST)
            .defineMethod("exchange", exchange.getTypeDescription(), Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(serverRequest.getTypeDescription().getName(), serverRequest.getBytes());

    var monoDesc =
        new net.bytebuddy.description.type.TypeDescription.Latent(
            WebFluxInstrumentation.MONO, java.lang.reflect.Modifier.PUBLIC, null);

    DynamicType.Unloaded<?> webHandler =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.WEB_HANDLER)
            .defineMethod("handle", monoDesc, Visibility.PUBLIC)
            .withParameters(exchange.getTypeDescription())
            .withoutCode()
            .make();
    map.put(webHandler.getTypeDescription().getName(), webHandler.getBytes());

    DynamicType.Builder<Object> dispatcherBuilder =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(webHandler.getTypeDescription())
            .name(WebFluxInstrumentation.DISPATCHER_HANDLER)
            .defineField("adapter", Object.class, Visibility.PUBLIC)
            .defineField("handler", Object.class, Visibility.PUBLIC)
            .defineField("routePattern", String.class, Visibility.PUBLIC);
    if (validDispatcher) {
      dispatcherBuilder =
          dispatcherBuilder
              .defineMethod("handle", monoDesc, Visibility.PUBLIC)
              .withParameters(exchange.getTypeDescription())
              .intercept(MethodDelegation.to(ExecBehavior.class));
    }
    DynamicType.Unloaded<?> dispatcher = dispatcherBuilder.make();
    map.put(dispatcher.getTypeDescription().getName(), dispatcher.getBytes());

    DynamicType.Unloaded<?> httpAdapter =
        new ByteBuddy()
            .subclass(Object.class)
            .name(WebFluxInstrumentation.HTTP_WEB_HANDLER_ADAPTER)
            .defineField("delegate", Object.class, Visibility.PUBLIC)
            .defineMethod("handle", monoDesc, Visibility.PUBLIC)
            .withParameters(req.getTypeDescription(), resp.getTypeDescription())
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(httpAdapter.getTypeDescription().getName(), httpAdapter.getBytes());

    DynamicType.Unloaded<?> handlerAdapter =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.HANDLER_ADAPTER)
            .defineMethod("handle", monoDesc, Visibility.PUBLIC)
            .withParameters(
                exchange.getTypeDescription(), TypeDescription.ForLoadedType.of(Object.class))
            .withoutCode()
            .make();
    map.put(handlerAdapter.getTypeDescription().getName(), handlerAdapter.getBytes());

    DynamicType.Unloaded<?> routerFn =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.ROUTER_FUNCTION)
            .defineMethod("route", monoDesc, Visibility.PUBLIC)
            .withParameters(serverRequest.getTypeDescription())
            .withoutCode()
            .make();
    map.put(routerFn.getTypeDescription().getName(), routerFn.getBytes());

    DynamicType.Unloaded<?> handlerFn =
        new ByteBuddy()
            .makeInterface()
            .name(WebFluxInstrumentation.HANDLER_FUNCTION)
            .defineMethod("handle", monoDesc, Visibility.PUBLIC)
            .withParameters(serverRequest.getTypeDescription())
            .withoutCode()
            .make();
    map.put(handlerFn.getTypeDescription().getName(), handlerFn.getBytes());

    // Concrete test execution classes for live ByteBuddy advice verification:
    var reactorMonoDesc =
        new TypeDescription.Latent(
            WebFluxInstrumentation.MONO, java.lang.reflect.Modifier.PUBLIC, null);
    DynamicType.Unloaded<?> execMono =
        new ByteBuddy()
            .subclass(reactorMonoDesc)
            .name("reactor.core.publisher.TestExecMono")
            .defineField("action", Runnable.class, Visibility.PUBLIC)
            .defineField("ctxModifier", Function.class, Visibility.PUBLIC)
            .defineField("onSuccess", Consumer.class, Visibility.PUBLIC)
            .defineField("onError", Consumer.class, Visibility.PUBLIC)
            .defineField("onCancel", Runnable.class, Visibility.PUBLIC)
            .defineMethod("contextWrite", reactorMonoDesc, Visibility.PUBLIC)
            .withParameters(Function.class)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("doOnSuccess", reactorMonoDesc, Visibility.PUBLIC)
            .withParameters(Consumer.class)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("doOnError", reactorMonoDesc, Visibility.PUBLIC)
            .withParameters(Consumer.class)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("doOnCancel", reactorMonoDesc, Visibility.PUBLIC)
            .withParameters(Runnable.class)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("run", Object.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(execMono.getTypeDescription().getName(), execMono.getBytes());

    DynamicType.Unloaded<?> testReq =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(req.getTypeDescription())
            .name("org.springframework.http.server.reactive.TestRequest")
            .defineMethod("getMethod", Object.class, Visibility.PUBLIC)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(testReq.getTypeDescription().getName(), testReq.getBytes());

    DynamicType.Unloaded<?> testResp =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(resp.getTypeDescription())
            .name("org.springframework.http.server.reactive.TestResponse")
            .defineField("status", int.class, Visibility.PUBLIC)
            .defineMethod("getStatusCode", Object.class, Visibility.PUBLIC)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(testResp.getTypeDescription().getName(), testResp.getBytes());

    DynamicType.Unloaded<?> testExchange =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(exchange.getTypeDescription())
            .name("org.springframework.web.server.TestExchange")
            .defineField("req", req.getTypeDescription(), Visibility.PUBLIC)
            .defineField("resp", resp.getTypeDescription(), Visibility.PUBLIC)
            .defineField("attrs", Map.class, Visibility.PUBLIC)
            .defineMethod("getRequest", req.getTypeDescription(), Visibility.PUBLIC)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("getResponse", resp.getTypeDescription(), Visibility.PUBLIC)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .defineMethod("getAttributes", Map.class, Visibility.PUBLIC)
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(testExchange.getTypeDescription().getName(), testExchange.getBytes());

    DynamicType.Unloaded<?> sampleController =
        new ByteBuddy()
            .subclass(Object.class)
            .name("demo.webflux.SampleController")
            .make();
    map.put(sampleController.getTypeDescription().getName(), sampleController.getBytes());

    DynamicType.Unloaded<?> testHandlerAdapter =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(handlerAdapter.getTypeDescription())
            .name("org.springframework.web.reactive.TestHandlerAdapter")
            .defineMethod("handle", monoDesc, Visibility.PUBLIC)
            .withParameters(
                exchange.getTypeDescription(), TypeDescription.ForLoadedType.of(Object.class))
            .intercept(MethodDelegation.to(ExecBehavior.class))
            .make();
    map.put(testHandlerAdapter.getTypeDescription().getName(), testHandlerAdapter.getBytes());

    return map;
  }

  public static final class ExecBehavior {
    private ExecBehavior() {}

    @SuppressWarnings("unchecked")
    @RuntimeType
    public static Object dispatch(
        @This Object self, @Origin Method method, @AllArguments Object[] args) throws Exception {
      String cls = self.getClass().getName();
      String name = method.getName();
      if ("org.springframework.http.server.reactive.TestRequest".equals(cls)) {
        return "POST";
      }
      if ("org.springframework.http.server.reactive.TestResponse".equals(cls)) {
        int status = self.getClass().getField("status").getInt(self);
        return status == 0 ? null : status;
      }
      if ("org.springframework.web.server.TestExchange".equals(cls)) {
        if ("getRequest".equals(name)) return self.getClass().getField("req").get(self);
        if ("getResponse".equals(name)) return self.getClass().getField("resp").get(self);
        if ("getAttributes".equals(name)) {
          Map<String, Object> attrs =
              (Map<String, Object>) self.getClass().getField("attrs").get(self);
          if (attrs == null) {
            attrs = new ConcurrentHashMap<>();
            self.getClass().getField("attrs").set(self, attrs);
          }
          return attrs;
        }
      }
      if ("reactor.core.publisher.TestExecMono".equals(cls)) {
        if ("contextWrite".equals(name) || "doOnSuccess".equals(name)
            || "doOnError".equals(name) || "doOnCancel".equals(name)) {
          Object copy = self.getClass().getDeclaredConstructor().newInstance();
          copyField(self, copy, "action");
          copyField(self, copy, "ctxModifier");
          copyField(self, copy, "onSuccess");
          copyField(self, copy, "onError");
          copyField(self, copy, "onCancel");
          if ("contextWrite".equals(name)) {
            Function<Object, Object> prev =
                (Function<Object, Object>) self.getClass().getField("ctxModifier").get(self);
            Function<Object, Object> next = (Function<Object, Object>) args[0];
            Function<Object, Object> combinedFn = prev == null ? next : prev.andThen(next);
            copy.getClass().getField("ctxModifier").set(copy, combinedFn);
          } else if ("doOnSuccess".equals(name)) {
            Consumer<Object> prev =
                (Consumer<Object>) self.getClass().getField("onSuccess").get(self);
            Consumer<Object> next = (Consumer<Object>) args[0];
            Consumer<Object> combinedSuccess =
                prev == null
                    ? next
                    : (Object v) -> {
                      prev.accept(v);
                      next.accept(v);
                    };
            copy.getClass().getField("onSuccess").set(copy, combinedSuccess);
          } else if ("doOnError".equals(name)) {
            Consumer<Throwable> prev =
                (Consumer<Throwable>) self.getClass().getField("onError").get(self);
            Consumer<Throwable> next = (Consumer<Throwable>) args[0];
            Consumer<Throwable> combinedError =
                prev == null
                    ? next
                    : (Throwable e) -> {
                      prev.accept(e);
                      next.accept(e);
                    };
            copy.getClass().getField("onError").set(copy, combinedError);
          } else if ("doOnCancel".equals(name)) {
            copy.getClass().getField("onCancel").set(copy, args[0]);
          }
          return copy;
        }
        if ("run".equals(name)) {
          Function<Object, Object> mod =
              (Function<Object, Object>) self.getClass().getField("ctxModifier").get(self);
          Object effectiveCtx = mod == null ? args[0] : mod.apply(args[0]);
          ReactorContextBridge.Token tok = ReactorContextBridge.fromReactorContext(effectiveCtx);
          try (var ignored = ReactorContextBridge.enterScope(tok)) {
            Runnable action = (Runnable) self.getClass().getField("action").get(self);
            if (action != null) action.run();
            Consumer<Object> onSuccess =
                (Consumer<Object>) self.getClass().getField("onSuccess").get(self);
            if (onSuccess != null) onSuccess.accept("ok");
            return "ok";
          } catch (Throwable err) {
            Consumer<Throwable> onError =
                (Consumer<Throwable>) self.getClass().getField("onError").get(self);
            if (onError != null) onError.accept(err);
            throw err;
          }
        }
      }
      if (WebFluxInstrumentation.HTTP_WEB_HANDLER_ADAPTER.equals(cls)) {
        ClassLoader cl = self.getClass().getClassLoader();
        Object exch =
            cl.loadClass("org.springframework.web.server.TestExchange")
                .getDeclaredConstructor()
                .newInstance();
        exch.getClass().getField("req").set(exch, args[0]);
        exch.getClass().getField("resp").set(exch, args[1]);
        Object delegate = self.getClass().getField("delegate").get(self);
        Method m =
            delegate
                .getClass()
                .getMethod("handle", cl.loadClass(WebFluxInstrumentation.SERVER_WEB_EXCHANGE));
        return m.invoke(delegate, exch);
      }
      if (WebFluxInstrumentation.DISPATCHER_HANDLER.equals(cls)) {
        Object exch = args[0];
        @SuppressWarnings("unchecked")
        Map<String, Object> attrs =
            (Map<String, Object>) exch.getClass().getMethod("getAttributes").invoke(exch);
        String route = (String) self.getClass().getField("routePattern").get(self);
        attrs.put(
            "org.springframework.web.reactive.HandlerMapping.bestMatchingPattern", route);
        Object adapter = self.getClass().getField("adapter").get(self);
        Object handler = self.getClass().getField("handler").get(self);
        Method m =
            adapter
                .getClass()
                .getMethod(
                    "handle",
                    self.getClass()
                        .getClassLoader()
                        .loadClass(WebFluxInstrumentation.SERVER_WEB_EXCHANGE),
                    Object.class);
        Object innerMono = m.invoke(adapter, exch, handler);
        Object resp = exch.getClass().getMethod("getResponse").invoke(exch);
        Object wrappedOuter =
            self.getClass()
                .getClassLoader()
                .loadClass("reactor.core.publisher.TestExecMono")
                .getDeclaredConstructor()
                .newInstance();
        Method innerRun = innerMono.getClass().getMethod("run", Object.class);
        Runnable outerAction =
            () -> {
              try {
                Object c =
                    self.getClass()
                        .getClassLoader()
                        .loadClass("reactor.util.context.TestContext")
                        .getDeclaredConstructor()
                        .newInstance();
                innerRun.invoke(innerMono, c);
                resp.getClass().getField("status").setInt(resp, 201);
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            };
        wrappedOuter.getClass().getField("action").set(wrappedOuter, outerAction);
        return wrappedOuter;
      }
      if ("org.springframework.web.reactive.TestHandlerAdapter".equals(cls)) {
        Object mono =
            self.getClass()
                .getClassLoader()
                .loadClass("reactor.core.publisher.TestExecMono")
                .getDeclaredConstructor()
                .newInstance();
        Runnable handlerAsync =
            () -> {
              BootstrapBridge.frameEnter("AsyncService.step");
              BootstrapBridge.frameExit("AsyncService.step", null);
            };
        mono.getClass().getField("action").set(mono, handlerAsync);
        return mono;
      }
      return null;
    }

    private static void copyField(Object src, Object dst, String field) throws Exception {
      dst.getClass().getField(field).set(dst, src.getClass().getField(field).get(src));
    }
  }

  private static final class CapturingTransport implements RecordingWriter.Transport {
    volatile CapabilitySet capabilities;
    final List<RecordingStarted> starts = new CopyOnWriteArrayList<>();
    final List<EventBatch> batches = new CopyOnWriteArrayList<>();
    final List<RecordingFinished> finishes = new CopyOnWriteArrayList<>();

    @Override
    public Ack send(String messageId, String correlationToken, Message payload)
        throws ClientException {
      long seq = 0;
      if (payload instanceof CapabilitySet caps) {
        capabilities = caps;
      } else if (payload instanceof RecordingStarted started) {
        starts.add(started);
        seq = started.getRecordingSeq();
      } else if (payload instanceof EventBatch batch) {
        batches.add(batch);
        seq = batch.getEventsCount() == 0
            ? 0 : batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq();
      } else if (payload instanceof RecordingFinished finished) {
        finishes.add(finished);
        seq = finished.getFinalRecordingSeq();
      }
      Ack.Builder ack =
          Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(1);
      if (correlationToken != null && !correlationToken.isEmpty() && seq > 0) {
        ack.putHighestContiguousRecordingSeq(correlationToken, seq);
      }
      return ack.build();
    }

    @Override
    public boolean fitsEnvelope(String messageId, String correlationToken, Message payload) {
      return true;
    }

    @Override
    public void close() {}
  }
}
