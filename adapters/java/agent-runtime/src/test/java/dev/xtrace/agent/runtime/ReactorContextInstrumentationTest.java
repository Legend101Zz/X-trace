package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeSink;
import dev.xtrace.agent.bootstrap.ReactorContextBridge;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.TargetType;
import net.bytebuddy.implementation.MethodDelegation;
import net.bytebuddy.implementation.StubMethod;
import net.bytebuddy.implementation.bind.annotation.AllArguments;
import net.bytebuddy.implementation.bind.annotation.Origin;
import net.bytebuddy.implementation.bind.annotation.RuntimeType;
import net.bytebuddy.implementation.bind.annotation.This;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReactorContextInstrumentationTest {
  private RecordingSink sink;

  @BeforeEach
  void setUp() {
    ReactorContextInstrumentation.resetForTest();
    ReactorContextBridge.takePropagationUnavailable();
    ReactorContextBridge.takeCorrelationGapObserved();
    sink = new RecordingSink();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void tearDown() {
    BootstrapBridge.disable(sink);
    ReactorContextInstrumentation.resetForTest();
    ReactorContextBridge.takePropagationUnavailable();
    ReactorContextBridge.takeCorrelationGapObserved();
  }

  @Test
  void versionGuardsAcceptOnlyReactor34Through3x() throws Exception {
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("3.4.0", 3, 4, 4));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("3.5.11", 3, 4, 4));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("3.6.9", 3, 4, 4));
    assertTrue(ReactorContextInstrumentation.isSupportedVersion("3.7.0-M1", 3, 4, 4));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("3.3.9.RELEASE", 3, 4, 4));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("4.0.0", 3, 4, 4));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("garbage", 3, 4, 4));
    assertFalse(ReactorContextInstrumentation.isSupportedVersion("", 3, 4, 4));
  }

  @Test
  void transformsSyntheticReactorPipelineAndPropagatesInterleavedRequestsAcrossScheduler(
      @TempDir Path tempDir) throws Exception {
    Map<String, byte[]> defs = buildReactorStubDefinitions(true);
    Path reactorJar = writeJar(tempDir.resolve("reactor-core-3.6.5.jar"), "3.6.5", defs);

    AtomicInteger limitations = new AtomicInteger();
    var listener = new ReactorContextInstrumentation.FailureListener(limitations::incrementAndGet);
    var locator =
        new ClassFileLocator.Compound(
            new ClassFileLocator.Simple(defs),
            ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    TypePool pool = TypePool.Default.of(locator);
    var transformer =
        ReactorContextInstrumentation.configure(
                new AgentBuilder.Default()
                    .disableClassFormatChanges()
                    .with(new AgentBuilder.LocationStrategy.Simple(locator))
                    .with(listener),
                listener,
                pool)
            .makeRaw();

    try (URLClassLoader loader =
        new TransformingJarClassLoader(
            new URL[] {reactorJar.toUri().toURL()},
            getClass().getClassLoader(),
            defs,
            transformer)) {
      Class<?> subCls = loader.loadClass("reactor.core.publisher.TestSubscriber");
      Class<?> pubCls = loader.loadClass("reactor.core.publisher.TestCallableMono");
      Class<?> schedCls = loader.loadClass("reactor.core.scheduler.TestScheduler");
      Class<?> ctxCls = loader.loadClass("reactor.util.context.TestContext");

      Object scheduler = schedCls.getDeclaredConstructor().newInstance();

      ReactorContextBridge.Token tokA = ReactorContextBridge.startRoot("GET", "/alpha", null);
      ReactorContextBridge.Token tokB = ReactorContextBridge.startRoot("POST", "/beta", null);
      assertNotNull(tokA);
      assertNotNull(tokB);

      Object ctxA =
          ReactorContextBridge.attachToReactorContext(
              ctxCls.getDeclaredConstructor().newInstance(), tokA);
      Object ctxB =
          ReactorContextBridge.attachToReactorContext(
              ctxCls.getDeclaredConstructor().newInstance(), tokB);

      ExecutorService poolExec = Executors.newFixedThreadPool(2);
      try {
        CountDownLatch entered = new CountDownLatch(2);
        CountDownLatch proceed = new CountDownLatch(1);
        Behavior.HOOK =
            (tag) -> {
              if ("pause".equals(tag)) {
                entered.countDown();
                try {
                  proceed.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                }
              }
            };

        Object pubA = pubCls.getDeclaredConstructor().newInstance();
        pubCls.getField("symbol").set(pubA, "WorkA.run");
        Object pubB = pubCls.getDeclaredConstructor().newInstance();
        pubCls.getField("symbol").set(pubB, "WorkB.run");
        Object subA = subCls.getDeclaredConstructor().newInstance();
        subCls.getField("ctx").set(subA, ctxA);
        Object subB = subCls.getDeclaredConstructor().newInstance();
        subCls.getField("ctx").set(subB, ctxB);

        // First exercise Scheduler.schedule(Runnable) via Advice arg wrapping from active token A.
        try (var scopeA = ReactorContextBridge.enterScope(tokA)) {
          Method schedule = schedCls.getMethod("schedule", Runnable.class);
          Future<?> scheduledFuture =
              poolExec.submit(
                  () -> {
                    try {
                      Runnable wrapped =
                          (Runnable)
                              schedule.invoke(
                                  scheduler,
                                  (Runnable)
                                      () -> {
                                        BootstrapBridge.frameEnter("ScheduledA.task");
                                        BootstrapBridge.frameExit("ScheduledA.task", null);
                                      });
                      wrapped.run();
                    } catch (Exception e) {
                      throw new RuntimeException(e);
                    }
                  });
          scheduledFuture.get(5, TimeUnit.SECONDS);
        }

        // Now run concurrent subscribers across worker threads with interleaved frames.
        Method subscribe = pubCls.getMethod("subscribe", loader.loadClass("reactor.core.CoreSubscriber"));
        Future<?> fa =
            poolExec.submit(
                () -> {
                  try {
                    subscribe.invoke(pubA, subA);
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                });
        Future<?> fb =
            poolExec.submit(
                () -> {
                  try {
                    subscribe.invoke(pubB, subB);
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                });

        assertTrue(entered.await(5, TimeUnit.SECONDS));
        proceed.countDown();
        fa.get(5, TimeUnit.SECONDS);
        fb.get(5, TimeUnit.SECONDS);

        boolean workersClean =
            poolExec
                .submit(
                    () -> !BootstrapBridge.hasContext() && ReactorContextBridge.currentToken() == null)
                .get(5, TimeUnit.SECONDS);
        assertTrue(workersClean);
      } finally {
        Behavior.HOOK = tag -> {};
        poolExec.shutdownNow();
      }

      assertTrue(ReactorContextBridge.signalComplete(tokA));
      assertTrue(ReactorContextBridge.signalComplete(tokB));

      var recA = sink.recordings.get(tokA.recordingId());
      var recB = sink.recordings.get(tokB.recordingId());
      assertTrue(recA.symbols().contains("ScheduledA.task"));
      assertTrue(recA.symbols().contains("WorkA.run"));
      assertTrue(recB.symbols().contains("WorkB.run"));
      assertFalse(recA.symbols().contains("WorkB.run"));
      assertFalse(recB.symbols().contains("WorkA.run"));
      assertEquals(0, limitations.get());
      assertFalse(ReactorContextBridge.isPropagationUnavailable());
    }
  }

  @Test
  void failsClosedOnOldReactorJarAndMissingMonoContract(@TempDir Path tempDir) throws Exception {
    // 1) JAR version < 3.4 fails closed without transforming Reactor classes.
    Map<String, byte[]> defs = buildReactorStubDefinitions(true);
    Path oldJar = writeJar(tempDir.resolve("reactor-core-3.3.9.jar"), "3.3.9.RELEASE", defs);
    var listener = new ReactorContextInstrumentation.FailureListener(() -> {});
    var locator =
        new ClassFileLocator.Compound(
            new ClassFileLocator.Simple(defs),
            ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    TypePool pool = TypePool.Default.of(locator);
    var transformer =
        ReactorContextInstrumentation.configure(
                new AgentBuilder.Default()
                    .disableClassFormatChanges()
                    .with(new AgentBuilder.LocationStrategy.Simple(locator))
                    .with(listener),
                listener,
                pool)
            .makeRaw();

    try (URLClassLoader oldLoader =
        new URLClassLoader(new URL[] {oldJar.toUri().toURL()}, getClass().getClassLoader())) {
      byte[] originalSub = defs.get("reactor.core.publisher.TestSubscriber");
      byte[] transformed =
          transformer.transform(
              oldLoader, "reactor/core/publisher/TestSubscriber", null, null, originalSub);
      assertNull(transformed, "Reactor 3.3.9 JAR must fail closed and stay untransformed");
      assertTrue(ReactorContextBridge.isPropagationUnavailable());
    }

    // 2) Missing Mono.contextWrite signature rejects Reactor contract cleanly.
    ReactorContextInstrumentation.resetForTest();
    ReactorContextBridge.takePropagationUnavailable();
    Map<String, byte[]> brokenDefs = buildReactorStubDefinitions(false);
    TypePool brokenPool =
        TypePool.Default.of(
            new ClassFileLocator.Compound(
                new ClassFileLocator.Simple(brokenDefs),
                ClassFileLocator.ForClassLoader.of(getClass().getClassLoader())));
    assertFalse(ReactorContextInstrumentation.supportsReactorContract(brokenPool));
  }

  @Test
  void unrelatedUnresolvableHierarchyNeverMarksPropagationUnavailable() throws Exception {
    var missingParent = new ByteBuddy().subclass(Object.class).name("demo.MissingReactorParent").make();
    var child =
        new ByteBuddy().subclass(missingParent.getTypeDescription()).name("demo.UnrelatedApp").make();
    AtomicInteger limitations = new AtomicInteger();
    var listener = new ReactorContextInstrumentation.FailureListener(limitations::incrementAndGet);
    var locator =
        new ClassFileLocator.Compound(
            ClassFileLocator.Simple.of("demo.UnrelatedApp", child.getBytes()),
            ClassFileLocator.ForClassLoader.ofPlatformLoader());
    var transformer =
        new AgentBuilder.Default()
            .with(new AgentBuilder.LocationStrategy.Simple(locator))
            .with(listener)
            .type(listener.selected((type, loader, m, r, d) ->
                hasSuperType(named(ReactorContextInstrumentation.CORE_SUBSCRIBER)).matches(type)))
            .transform((target, type, loader, module, domain) -> target)
            .makeRaw();

    assertThrows(
        IllegalStateException.class,
        () ->
            transformer.transform(
                getClass().getClassLoader(), "demo/UnrelatedApp", null, null, child.getBytes()));
    assertEquals(0, limitations.get());
    assertFalse(ReactorContextBridge.isPropagationUnavailable());
  }

  static Map<String, byte[]> buildReactorStubDefinitions(boolean includeMonoContextWrite) {
    Map<String, byte[]> map = new LinkedHashMap<>();

    DynamicType.Unloaded<?> contextView =
        new ByteBuddy()
            .makeInterface()
            .name(ReactorContextInstrumentation.CONTEXT_VIEW)
            .defineMethod("hasKey", boolean.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .withoutCode()
            .defineMethod("get", Object.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .withoutCode()
            .make();
    map.put(contextView.getTypeDescription().getName(), contextView.getBytes());

    DynamicType.Unloaded<?> context =
        new ByteBuddy()
            .makeInterface(contextView.getTypeDescription())
            .name(ReactorContextInstrumentation.CONTEXT)
            .defineMethod("put", TargetType.DESCRIPTION, Visibility.PUBLIC)
            .withParameters(Object.class, Object.class)
            .withoutCode()
            .make();
    map.put(context.getTypeDescription().getName(), context.getBytes());

    DynamicType.Unloaded<?> subscription =
        new ByteBuddy()
            .makeInterface()
            .name(ReactorContextInstrumentation.RS_SUBSCRIPTION)
            .defineMethod("request", void.class, Visibility.PUBLIC)
            .withParameters(long.class)
            .withoutCode()
            .defineMethod("cancel", void.class, Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(subscription.getTypeDescription().getName(), subscription.getBytes());

    DynamicType.Unloaded<?> subscriber =
        new ByteBuddy()
            .makeInterface()
            .name(ReactorContextInstrumentation.CORE_SUBSCRIBER)
            .defineMethod("currentContext", context.getTypeDescription(), Visibility.PUBLIC)
            .withoutCode()
            .defineMethod("onSubscribe", void.class, Visibility.PUBLIC)
            .withParameters(subscription.getTypeDescription())
            .withoutCode()
            .defineMethod("onNext", void.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .withoutCode()
            .defineMethod("onError", void.class, Visibility.PUBLIC)
            .withParameters(Throwable.class)
            .withoutCode()
            .defineMethod("onComplete", void.class, Visibility.PUBLIC)
            .withoutCode()
            .make();
    map.put(subscriber.getTypeDescription().getName(), subscriber.getBytes());

    DynamicType.Unloaded<?> publisher =
        new ByteBuddy()
            .makeInterface()
            .name(ReactorContextInstrumentation.CORE_PUBLISHER)
            .defineMethod("subscribe", void.class, Visibility.PUBLIC)
            .withParameters(subscriber.getTypeDescription())
            .withoutCode()
            .make();
    map.put(publisher.getTypeDescription().getName(), publisher.getBytes());

    var monoBuilder =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(publisher.getTypeDescription())
            .name(ReactorContextInstrumentation.MONO)
            .defineMethod("subscribe", void.class, Visibility.PUBLIC)
            .withParameters(subscriber.getTypeDescription())
            .intercept(MethodDelegation.to(Behavior.class))
            .defineMethod("doOnSuccess", TargetType.DESCRIPTION, Visibility.PUBLIC)
            .withParameters(Consumer.class)
            .intercept(StubMethod.INSTANCE)
            .defineMethod("doOnError", TargetType.DESCRIPTION, Visibility.PUBLIC)
            .withParameters(Consumer.class)
            .intercept(StubMethod.INSTANCE)
            .defineMethod("doOnCancel", TargetType.DESCRIPTION, Visibility.PUBLIC)
            .withParameters(Runnable.class)
            .intercept(StubMethod.INSTANCE);
    if (includeMonoContextWrite) {
      monoBuilder =
          monoBuilder
              .defineMethod("contextWrite", TargetType.DESCRIPTION, Visibility.PUBLIC)
              .withParameters(Function.class)
              .intercept(StubMethod.INSTANCE);
    }
    DynamicType.Unloaded<?> mono = monoBuilder.make();
    map.put(mono.getTypeDescription().getName(), mono.getBytes());

    DynamicType.Unloaded<?> scheduler =
        new ByteBuddy()
            .makeInterface()
            .name(ReactorContextInstrumentation.SCHEDULER)
            .defineMethod("schedule", Object.class, Visibility.PUBLIC)
            .withParameters(Runnable.class)
            .withoutCode()
            .make();
    map.put(scheduler.getTypeDescription().getName(), scheduler.getBytes());

    // Concrete runtime implementations for execution test:
    DynamicType.Unloaded<?> testContext =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(context.getTypeDescription())
            .name("reactor.util.context.TestContext")
            .defineField("entries", Map.class, Visibility.PUBLIC)
            .defineMethod("hasKey", boolean.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .intercept(MethodDelegation.to(Behavior.class))
            .defineMethod("get", Object.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .intercept(MethodDelegation.to(Behavior.class))
            .defineMethod("put", context.getTypeDescription(), Visibility.PUBLIC)
            .withParameters(Object.class, Object.class)
            .intercept(MethodDelegation.to(Behavior.class))
            .make();
    map.put(testContext.getTypeDescription().getName(), testContext.getBytes());

    DynamicType.Unloaded<?> testSub =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(subscriber.getTypeDescription())
            .name("reactor.core.publisher.TestSubscriber")
            .defineField("ctx", Object.class, Visibility.PUBLIC)
            .defineMethod("currentContext", context.getTypeDescription(), Visibility.PUBLIC)
            .intercept(MethodDelegation.to(Behavior.class))
            .defineMethod("onSubscribe", void.class, Visibility.PUBLIC)
            .withParameters(subscription.getTypeDescription())
            .intercept(StubMethod.INSTANCE)
            .defineMethod("onNext", void.class, Visibility.PUBLIC)
            .withParameters(Object.class)
            .intercept(MethodDelegation.to(Behavior.class))
            .defineMethod("onError", void.class, Visibility.PUBLIC)
            .withParameters(Throwable.class)
            .intercept(StubMethod.INSTANCE)
            .defineMethod("onComplete", void.class, Visibility.PUBLIC)
            .intercept(StubMethod.INSTANCE)
            .make();
    map.put(testSub.getTypeDescription().getName(), testSub.getBytes());

    DynamicType.Unloaded<?> testMono =
        new ByteBuddy()
            .subclass(mono.getTypeDescription())
            .name("reactor.core.publisher.TestCallableMono")
            .defineField("symbol", String.class, Visibility.PUBLIC)
            .defineMethod("subscribe", void.class, Visibility.PUBLIC)
            .withParameters(subscriber.getTypeDescription())
            .intercept(MethodDelegation.to(Behavior.class))
            .make();
    map.put(testMono.getTypeDescription().getName(), testMono.getBytes());

    DynamicType.Unloaded<?> testSched =
        new ByteBuddy()
            .subclass(Object.class)
            .implement(scheduler.getTypeDescription())
            .name("reactor.core.scheduler.TestScheduler")
            .defineMethod("schedule", Object.class, Visibility.PUBLIC)
            .withParameters(Runnable.class)
            .intercept(MethodDelegation.to(Behavior.class))
            .make();
    map.put(testSched.getTypeDescription().getName(), testSched.getBytes());

    return map;
  }

  /** Static stateless behavior target so transformed ByteBuddy classes retain zero static state. */
  public static final class Behavior {
    static volatile Consumer<String> HOOK = tag -> {};

    private Behavior() {}

    @SuppressWarnings("unchecked")
    @RuntimeType
    public static Object dispatch(
        @This Object self, @Origin Method method, @AllArguments Object[] args) throws Exception {
      String cls = self.getClass().getName();
      String name = method.getName();
      if ("reactor.util.context.TestContext".equals(cls)) {
        Map<Object, Object> entries =
            (Map<Object, Object>) self.getClass().getField("entries").get(self);
        if (entries == null) entries = Map.of();
        if ("hasKey".equals(name)) return entries.containsKey(args[0]);
        if ("get".equals(name)) return entries.get(args[0]);
        if ("put".equals(name)) {
          Object next = self.getClass().getDeclaredConstructor().newInstance();
          Map<Object, Object> nextMap = new ConcurrentHashMap<>(entries);
          nextMap.put(args[0], args[1]);
          next.getClass().getField("entries").set(next, nextMap);
          return next;
        }
      } else if ("reactor.core.publisher.TestSubscriber".equals(cls)) {
        if ("currentContext".equals(name)) return self.getClass().getField("ctx").get(self);
        if ("onNext".equals(name)) {
          HOOK.accept("pause");
          BootstrapBridge.frameEnter(String.valueOf(args[0]));
          BootstrapBridge.frameExit(String.valueOf(args[0]), null);
          return null;
        }
      } else if ("reactor.core.publisher.TestCallableMono".equals(cls)) {
        if ("subscribe".equals(name)) {
          String sym = (String) self.getClass().getField("symbol").get(self);
          Method onNext = args[0].getClass().getMethod("onNext", Object.class);
          onNext.invoke(args[0], sym);
          return null;
        }
      } else if ("reactor.core.scheduler.TestScheduler".equals(cls)) {
        if ("schedule".equals(name)) return args[0];
      }
      return null;
    }
  }

  static Path writeJar(Path jarPath, String implVersion, Map<String, byte[]> classes)
      throws IOException {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (implVersion != null) {
      manifest.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_VERSION, implVersion);
    }
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarPath), manifest)) {
      for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
        JarEntry je = new JarEntry(entry.getKey().replace('.', '/') + ".class");
        out.putNextEntry(je);
        out.write(entry.getValue());
        out.closeEntry();
      }
    }
    return jarPath;
  }

  static final class TransformingJarClassLoader extends URLClassLoader {
    private final Map<String, byte[]> definitions;
    private final java.lang.instrument.ClassFileTransformer transformer;

    TransformingJarClassLoader(
        URL[] urls,
        ClassLoader parent,
        Map<String, byte[]> definitions,
        java.lang.instrument.ClassFileTransformer transformer) {
      super(urls, parent);
      this.definitions = definitions;
      this.transformer = transformer;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
      byte[] raw = definitions.get(name);
      if (raw == null) return super.findClass(name);
      byte[] defined = raw;
      if (transformer != null) {
        try {
          URL resource = findResource(name.replace('.', '/') + ".class");
          URL codeSourceUrl = null;
          if (resource != null && "jar".equals(resource.getProtocol())) {
            String ext = resource.toExternalForm();
            int idx = ext.indexOf("!/");
            if (idx > 4) codeSourceUrl = new URL(ext.substring(4, idx));
          }
          var domain =
              codeSourceUrl != null
                  ? new java.security.ProtectionDomain(
                      new java.security.CodeSource(
                          codeSourceUrl, (java.security.cert.Certificate[]) null),
                      null)
                  : null;
          byte[] transformed =
              transformer.transform(this, name.replace('.', '/'), null, domain, raw);
          if (transformed != null) defined = transformed;
        } catch (Exception e) {
          throw new ClassNotFoundException("Failed transforming " + name, e);
        }
      }
      return defineClass(name, defined, 0, defined.length);
    }
  }

  static final class RecordedRequest {
    final List<String> symbols = new CopyOnWriteArrayList<>();
    volatile BridgeSink.Outcome outcome;

    List<String> symbols() {
      return symbols;
    }
  }

  static final class RecordingSink implements BridgeSink {
    final Map<String, RecordedRequest> recordings = new ConcurrentHashMap<>();

    @Override
    public boolean offerStart(String recordingId, long monotonicNs, String method, String route) {
      recordings.put(recordingId, new RecordedRequest());
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
      if (req != null) req.symbols.add(symbol);
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
          recordingId, startedMonotonicNs, finishedMonotonicNs, responseStatus, droppedEvents, null);
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
      if (req != null) req.outcome = outcome;
      return true;
    }

    @Override
    public int applicationScope(Class<?> type) {
      return 1;
    }

    @Override
    public void reportIncomplete(int failureKind) {}
  }
}
