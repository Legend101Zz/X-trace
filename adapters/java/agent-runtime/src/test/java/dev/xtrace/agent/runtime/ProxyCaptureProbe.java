package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.ProxyBridge;
import dev.xtrace.agent.runtime.line.ValueSnapshot;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Child JVM corpus: actual Instrumentation transforms the real JDK-generated proxy classes. */
public class ProxyCaptureProbe {
  @Retention(RetentionPolicy.RUNTIME)
  @interface Case {
    boolean focused() default true;
  }

  public static void main(String[] args) {
    try {
      if (args.length != 0) throw new IllegalArgumentException("proxy capture probe accepts no arguments");
      runCases();
    } catch (Throwable failure) {
      System.err.println("proxy-capture-probe failed");
      failure.printStackTrace(System.err);
      System.exit(1);
    }
  }

  private static void runCases() throws Exception {
    assertNull(BootstrapBridge.class.getClassLoader(), "bridge must resolve from bootstrap");
    assertNull(ProxyBridge.class.getClassLoader(), "proxy bridge must resolve from bootstrap");
    assertNull(ProxyBridge.Call.class.getClassLoader(), "call metadata must resolve from bootstrap");
    assertNull(ProxyBridge.EventSink.class.getClassLoader(), "event sink must resolve from bootstrap");
    boolean attach = Boolean.getBoolean("xtrace.proxy.probe.attach");
    Object preloaded = attach
        ? demo.framework.RepositoryProxyFactory.create(demo.proxy.SpringRepository.class) : null;
    java.util.concurrent.atomic.AtomicBoolean failed = new java.util.concurrent.atomic.AtomicBoolean();
    ProxyInstrumentation.install(ProxyProbeAgent.instrumentation, error -> {
      failed.set(true);
      System.err.println("proxy capture transformer failed");
      error.printStackTrace(System.err);
    }, attach);
    if (attach) {
      ProxyCaptureProbe probe = new ProxyCaptureProbe(false);
      try {
        probe.install();
        probe.assertSpringStyleRepository(preloaded);
        assertFalse(failed.get(), "production retransformation failed");
        System.out.println("preloaded-proxy-capture-cases=1");
      } finally {
        probe.close();
      }
    }
    Method[] methods = ProxyCaptureProbe.class.getDeclaredMethods();
    java.util.Arrays.sort(methods, java.util.Comparator.comparing(Method::getName));
    int count = 0;
    for (Method method : methods) {
      Case testCase = method.getAnnotation(Case.class);
      if (testCase == null) continue;
      ProxyCaptureProbe probe = new ProxyCaptureProbe(testCase.focused());
      try {
        probe.install();
        method.invoke(probe);
        assertFalse(failed.get(), "production transformer failed");
        count++;
      } catch (Throwable failure) {
        throw new AssertionError("proxy capture case failed: " + method.getName(), failure);
      } finally {
        probe.close();
      }
    }
    System.out.println("proxy-capture-cases=" + count);
  }
  private final BoundedEventQueue queue = new BoundedEventQueue(128, 128 * 1024);
  private final ApplicationScope scope = new ApplicationScope(
      List.of("demo.proxy"), List.of("src/test/java"));
  private final RuntimeBridgeSink events = new RuntimeBridgeSink(queue);
  private final ProxyCaptureSink sink;
  private Class<?> contract;
  private Object proxy;
  private InvocationHandler handler;

  private ProxyCaptureProbe(boolean focused) {
    sink = new ProxyCaptureSink(queue, scope, focused);
  }

  void install() throws Exception {
    events.useScope(scope);
    assertTrue(BootstrapBridge.install(events));
    assertTrue(ProxyBridge.install(sink));
    ClassLoader parent = getClass().getClassLoader();
    Map<String, byte[]> definitions = new HashMap<>();
    String name = "demo.proxy.RepositoryContract";
    byte[] original = ClassFileLocator.ForClassLoader.of(parent).locate(name).resolve();
    // Exercise declared parameter names even though the build does not request -parameters.
    ClassWriter writer = new ClassWriter(0);
    new ClassReader(original).accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String method, String descriptor,
          String signature, String[] exceptions) {
        MethodVisitor target = super.visitMethod(access, method, descriptor, signature, exceptions);
        int count = net.bytebuddy.jar.asm.Type.getArgumentTypes(descriptor).length;
        for (int i = 0; i < count; i++) {
          target.visitParameter(method.equals("secret") ? "password" : "value" + i, 0);
        }
        return target;
      }
    }, 0);
    definitions.put(name, writer.toByteArray());
    ClassLoader isolated = new Isolated(parent, definitions);
    // Observe the same bytes and source facts as the production load callback, under its loader.
    SourceIdentity.observe(isolated, name.replace('.', '/'), original, scope.sourceRoots(), sourceBase());
    ProxyInterfaceSources.observe(isolated, name.replace('.', '/'), original,
        new ApplicationScope(scope.packages(), scope.sourceRoots(), sourceBase()));
    contract = isolated.loadClass(name);
    this.handler = new demo.proxy.RepositoryHandler();
    proxy = Proxy.newProxyInstance(isolated, new Class<?>[] {contract}, this.handler);
  }

  private Path sourceBase() {
    Path current = Path.of(System.getProperty("user.dir"));
    if (Files.isDirectory(current.resolve("src/test/java/demo/proxy"))) return current;
    return current.resolve("agent-runtime");
  }

  void close() {
    if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, false);
    sink.close();
    BootstrapBridge.disable(events);
  }

  private Object call(String name, Class<?> parameter, Object argument) throws Exception {
    return contract.getMethod(name, parameter).invoke(proxy, argument);
  }

  private List<QueueSignal.Event> drain() throws Exception {
    List<QueueSignal.Event> result = new ArrayList<>();
    QueueSignal next;
    while ((next = queue.poll(Duration.ZERO)) != null) {
      if (next instanceof QueueSignal.Event event) result.add(event);
    }
    return result;
  }

  @Case(focused = false)
  void inheritedGenericFinderRecordsFoundAndMissingOwnerReads() throws Exception {
    var repository = (demo.proxy.SpringRepository)
        demo.framework.RepositoryProxyFactory.create(demo.proxy.SpringRepository.class);
    assertTrue(BootstrapBridge.requestStart("GET", "/owners/{ownerId}"));
    assertEquals(java.util.Optional.of("found"), repository.findById(1));
    assertEquals(java.util.Optional.empty(), repository.findById(999999));
    BootstrapBridge.requestEnd(200, false);
    var frames = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER
        || e.kind() == BridgeEventKind.FRAME_EXIT).toList();
    assertEquals(List.of(2, 3, 2, 3), frames.stream().map(QueueSignal.Event::kind).toList());
    for (var frame : frames) {
      assertEquals("demo.framework.RepositoryProxyFactory$Finder.findById", frame.symbol());
      assertNull(frame.sourcePath(), "framework declarations must not borrow application source");
    }
  }

  @Case(focused = false)
  void covariantProxyReturnDescriptorsEachGetTheirOwnBoundary() throws Exception {
    Object repository = Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] {demo.proxy.CovariantRepository.class}, (instance, method, args) -> "found");
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("found", ((demo.proxy.CovariantRepository) repository).read());
    assertEquals("found", ((demo.framework.RepositoryProxyFactory.CovariantFinder) repository).read());
    BootstrapBridge.requestEnd(200, false);
    var frames = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER
        || e.kind() == BridgeEventKind.FRAME_EXIT).toList();
    assertEquals(List.of(2, 3, 2, 3), frames.stream().map(QueueSignal.Event::kind).toList());
    assertTrue(frames.stream().allMatch(e -> e.symbol().equals("demo.proxy.CovariantRepository.read")));
    assertEquals(frames.get(0).eventId(), frames.get(1).parentEventId());
    assertEquals(frames.get(2).eventId(), frames.get(3).parentEventId());
  }

  @Case(focused = false)
  void springStyleInfrastructureInterfacesAndFrameworkHandlerDoNotHideRepositoryCalls()
      throws Exception {
    assertSpringStyleRepository(
        demo.framework.RepositoryProxyFactory.create(demo.proxy.SpringRepository.class));
  }

  private void assertSpringStyleRepository(Object springProxy) throws Exception {
    Class<?> repository = demo.proxy.SpringRepository.class;
    byte[] bytes = ClassFileLocator.ForClassLoader.of(repository.getClassLoader())
        .locate(repository.getName()).resolve();
    ProxyInterfaceSources.observe(repository.getClassLoader(), repository.getName().replace('.', '/'),
        bytes, new ApplicationScope(scope.packages(), scope.sourceRoots(), sourceBase()));
    assertTrue(Proxy.isProxyClass(springProxy.getClass()));
    assertTrue(springProxy.getClass().getName().startsWith("jdk.proxy"));
    assertSame(repository.getClassLoader(), springProxy.getClass().getClassLoader());
    assertEquals(ApplicationScope.NOT_APPLICATION, scope.verdict(springProxy.getClass()));
    assertEquals(ApplicationScope.APPLICATION, scope.verdict(repository));
    assertEquals(ApplicationScope.NOT_APPLICATION,
        scope.verdict(Proxy.getInvocationHandler(springProxy).getClass()));
    assertEquals(4, springProxy.getClass().getInterfaces().length);
    for (Class<?> extra : springProxy.getClass().getInterfaces()) {
      if (extra != repository) assertEquals(ApplicationScope.NOT_APPLICATION, scope.verdict(extra));
    }

    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    BootstrapBridge.frameEnter("Controller.find");
    assertFalse(((demo.framework.RepositoryProxyFactory.Advised) springProxy).isFrozen());
    assertSame(repository,
        ((demo.framework.RepositoryProxyFactory.DecoratingProxy) springProxy).getDecoratedClass());
    assertEquals("repository", springProxy.toString());
    assertEquals("found", ((demo.proxy.SpringRepository) springProxy).findByName("found"));
    assertEquals("saved", ((demo.proxy.SpringRepository) springProxy).save("saved"));
    BootstrapBridge.frameExit("Controller.find", false);
    BootstrapBridge.requestEnd(200, false);

    var captured = drain();
    assertEquals(List.of(1, 2, 2, 7, 8, 3, 2, 7, 8, 3, 3, 13),
        captured.stream().map(QueueSignal.Event::kind).toList());
    assertEquals("demo.proxy.SpringRepository.findByName", captured.get(2).symbol());
    assertTrue(captured.get(2).sourcePath().endsWith("demo/proxy/SpringRepository.java"));
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, captured.get(2).sourceBinding());
    assertTrue(Files.readAllLines(sourceBase().resolve("src/test/java/demo/proxy/SpringRepository.java"))
        .get(captured.get(2).sourceStartLine() - 1).contains("String findByName(String name)"));
    // The inherited method remains a framework declaration, not an invented application method.
    assertEquals("demo.framework.RepositoryProxyFactory$CrudRepository.save", captured.get(6).symbol());
    for (int entry : List.of(2, 6)) {
      assertEquals(captured.get(1).eventId(), captured.get(entry).parentEventId());
      assertEquals(captured.get(entry).eventId(), captured.get(entry + 1).parentEventId());
      assertEquals(captured.get(entry).eventId(), captured.get(entry + 3).parentEventId());
      assertTrue(captured.get(entry).values().isEmpty());
      assertTrue(captured.get(entry + 3).values().isEmpty());
    }
    assertNull(captured.get(6).sourcePath());
    assertFalse(captured.stream().anyMatch(event -> event.kind() == BridgeEventKind.LINE_CURSOR));
  }

  @Case(focused = false)
  void standardModeCapturesBoundariesWithoutArgumentReturnOrThrowValues() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("standard-value-canary", call("save", String.class, "standard-value-canary"));
    var failure = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> contract.getMethod("fail").invoke(proxy));
    assertInstanceOf(IllegalStateException.class, failure.getCause());
    BootstrapBridge.requestEnd(200, false);
    var captured = drain();
    var frames = captured.stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER
        || e.kind() == BridgeEventKind.FRAME_EXIT || e.kind() == BridgeEventKind.FRAME_THROW).toList();
    assertEquals(List.of(2, 3, 2, 4), frames.stream().map(QueueSignal.Event::kind).toList());
    for (var frame : frames) assertTrue(frame.values().isEmpty(), frame.symbol());
    assertEquals("demo.proxy.RepositoryContract.save", frames.get(0).symbol());
    assertTrue(frames.get(0).sourcePath().endsWith("demo/proxy/RepositoryContract.java"));
    assertEquals(captured.get(0).eventId(), frames.get(0).parentEventId());
    assertEquals(frames.get(0).eventId(), frames.get(1).parentEventId());
    assertEquals("java.lang.IllegalStateException", frames.get(3).exceptionType());
    assertNull(frames.get(3).exceptionMessage());
  }

  @Case
  void unrelatedInMemorySuperclassDoesNotStopProxyCapture() throws Exception {
    String parent = "demo.proxy.MemoryBase";
    String child = "demo.proxy.MemoryChild";
    ClassLoader isolated = new Isolated(getClass().getClassLoader(), Map.of(
        parent, memoryType(parent, "java.lang.Object"), child, memoryType(child, parent)));
    // These types are defined from bytes, with no .class resources for Byte Buddy's type pool.
    Class<?> loaded = isolated.loadClass(child);
    assertEquals(parent, loaded.getSuperclass().getName());
    assertNull(isolated.getResource(child.replace('.', '/') + ".class"));
    assertNull(isolated.getResource(parent.replace('.', '/') + ".class"));
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("value", call("save", String.class, "value"));
    BootstrapBridge.requestEnd(200, false);
    assertEquals(1, drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).count());
  }

  private static byte[] memoryType(String name, String parent) {
    ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
        name.replace('.', '/'), null, parent.replace('.', '/'), null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  @Case
  void packagePrivateContractProxyCanCallTheBootstrapBridge() throws Exception {
    Object privateProxy = demo.proxy.PackagePrivateRepository.create(handler);
    assertTrue(Proxy.isProxyClass(privateProxy.getClass()));
    assertFalse(java.lang.reflect.Modifier.isPublic(privateProxy.getClass().getModifiers()));
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("private-contract", demo.proxy.PackagePrivateRepository.save(privateProxy, "private-contract"));
    BootstrapBridge.requestEnd(200, false);
    var frames = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER
        || e.kind() == BridgeEventKind.FRAME_EXIT).toList();
    assertEquals(List.of(2, 3), frames.stream().map(QueueSignal.Event::kind).toList());
    assertEquals("demo.proxy.PackagePrivateRepository$Contract.save", frames.get(0).symbol());
    assertEquals(frames.get(0).eventId(), frames.get(1).parentEventId());
    assertEquals("private-contract", frames.get(1).values().get(0).preview());
  }

  @Case
  void declarationAndSourceMetadataAreCachedPerProxyClassAndMethod() throws Exception {
    Method method = proxy.getClass().getMethod("save", String.class);
    ProxyBridge.Call boundary = sink.resolve(proxy, method);
    assertNotNull(boundary);
    assertSame(boundary, sink.resolve(proxy, proxy.getClass().getMethod("save", String.class)));
    assertNotSame(boundary, sink.resolve(proxy, proxy.getClass().getMethod("save", long.class)));
    Object other = Proxy.newProxyInstance(contract.getClassLoader(),
        new Class<?>[] {contract, java.io.Serializable.class}, handler);
    assertNotSame(boundary, sink.resolve(other, other.getClass().getMethod("save", String.class)));

    Path temporary = Files.createTempDirectory("proxy-source-cache-");
    try {
      Path source = temporary.resolve("src/test/java/demo/proxy/RepositoryContract.java");
      Files.createDirectories(source.getParent());
      String original = Files.readString(sourceBase().resolve("src/test/java/demo/proxy/RepositoryContract.java"));
      Files.writeString(source, "\n" + original);
      byte[] bytes = ClassFileLocator.ForClassLoader.of(getClass().getClassLoader())
          .locate(contract.getName()).resolve();
      var before = ProxyInterfaceSources.lookup(boundary.method());
      ProxyInterfaceSources.observe(contract.getClassLoader(), contract.getName().replace('.', '/'),
          bytes, new ApplicationScope(scope.packages(), scope.sourceRoots(), temporary));
      var after = ProxyInterfaceSources.lookup(boundary.method());
      assertEquals(before.startLine() + 1, after.startLine());
      assertFalse(java.util.Arrays.equals(before.hash(), after.hash()));

      assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
      assertEquals("cached", call("save", String.class, "cached"));
      BootstrapBridge.requestEnd(200, false);
      var frames = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER
          || e.kind() == BridgeEventKind.FRAME_EXIT).toList();
      assertEquals(2, frames.size());
      for (var frame : frames) {
        assertEquals(before.startLine(), frame.sourceStartLine());
        assertArrayEquals(before.hash(), frame.sourceHash());
      }
    } finally {
      try (var paths = Files.walk(temporary)) {
        for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
      }
    }
  }

  @Case
  void realProxyNestsRepositoryBetweenServiceAndDatabaseWithInterfaceSource() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    BootstrapBridge.frameEnter("Service.place");
    assertEquals("saved", call("save", String.class, "saved"));
    BootstrapBridge.frameExit("Service.place", false);
    BootstrapBridge.requestEnd(200, false);
    List<QueueSignal.Event> captured = drain();
    assertEquals(List.of(1, 2, 2, 7, 8, 3, 3, 13), captured.stream().map(QueueSignal.Event::kind).toList());
    QueueSignal.Event service = captured.get(1);
    QueueSignal.Event repository = captured.get(2);
    assertEquals("demo.proxy.RepositoryContract.save", repository.symbol());
    assertEquals(service.eventId(), repository.parentEventId());
    assertEquals(repository.eventId(), captured.get(3).parentEventId());
    assertEquals(repository.eventId(), captured.get(5).parentEventId());
    assertTrue(repository.sourcePath().endsWith("demo/proxy/RepositoryContract.java"));
    assertEquals(SourceIdentity.OBSERVED_UNATTESTED, repository.sourceBinding());
    String line = Files.readAllLines(sourceBase().resolve("src/test/java/demo/proxy/RepositoryContract.java"))
        .get(repository.sourceStartLine() - 1);
    assertTrue(line.contains("String save(String description)"), line);
    assertEquals("saved", repository.values().get(0).preview());
    assertEquals(ValueSnapshot.Role.RETURN, captured.get(5).values().get(0).role());
    assertFalse(captured.stream().anyMatch(event -> event.kind() == BridgeEventKind.LINE_CURSOR));
  }

  @Case
  void exceptionsAndVoidReturnsPreserveSemanticsAndBalanceParents() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    var failure = assertThrows(java.lang.reflect.InvocationTargetException.class,
        () -> contract.getMethod("fail").invoke(proxy));
    assertInstanceOf(IllegalStateException.class, failure.getCause());
    contract.getMethod("nothing").invoke(proxy);
    BootstrapBridge.requestEnd(200, false);
    var captured = drain();
    var thrown = captured.stream().filter(e -> e.kind() == BridgeEventKind.FRAME_THROW).findFirst().orElseThrow();
    assertEquals("java.lang.IllegalStateException", thrown.exceptionType());
    assertNull(thrown.exceptionMessage());
    assertEquals(captured.get(1).eventId(), thrown.parentEventId());
    assertEquals(captured.get(0).eventId(), captured.get(3).parentEventId());
    assertTrue(captured.get(4).values().isEmpty());
  }

  @Case
  void nameAndContentRedactionBoundsAndOpaqueValuesUseExistingSanitizer() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    call("secret", String.class, "private-argument-canary");
    call("save", String.class, "Bearer private-content-canary");
    // Opaque alphanumeric runs are secrets under the content rule. Use ordinary long text
    // to exercise truncation without weakening the independent redaction assertions.
    call("save", String.class, "x ".repeat(512));
    Object hostile = new Object() {
      @Override public String toString() { throw new AssertionError("must not render"); }
    };
    assertSame(hostile, call("opaque", Object.class, hostile));
    call("save", String.class, "x".repeat(1024));
    BootstrapBridge.requestEnd(200, false);
    var entries = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).toList();
    assertEquals(ValueSnapshot.State.REDACTED, entries.get(0).values().get(0).state());
    assertEquals("name.secret", entries.get(0).values().get(0).ruleId());
    assertNull(entries.get(0).values().get(0).contentHash());
    assertEquals(ValueSnapshot.State.REDACTED, entries.get(1).values().get(0).state());
    assertEquals(ValueSnapshot.State.TRUNCATED, entries.get(2).values().get(0).state());
    assertEquals(256, entries.get(2).values().get(0).preview().length());
    assertEquals(ValueSnapshot.State.UNAVAILABLE, entries.get(3).values().get(0).state());
    assertEquals(ValueSnapshot.State.REDACTED, entries.get(4).values().get(0).state());
    assertEquals("content.secret_pattern", entries.get(4).values().get(0).ruleId());
    assertNull(entries.get(4).values().get(0).preview());
  }

  @Case
  void absentParameterNamesWithholdArgumentsInsteadOfBypassingNameRedaction() throws Exception {
    Class<?> noNames = demo.proxy.RepositoryContract.class;
    assertFalse(noNames.getMethod("secret", String.class).getParameters()[0].isNamePresent());
    Object original = Proxy.newProxyInstance(noNames.getClassLoader(), new Class<?>[] {noNames}, handler);
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("stored", noNames.getMethod("secret", String.class).invoke(original, "unknown-name-canary"));
    BootstrapBridge.requestEnd(200, false);
    var captured = drain();
    var entry = captured.stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).findFirst().orElseThrow();
    assertEquals(ValueSnapshot.State.UNAVAILABLE, entry.values().get(0).state());
    assertEquals(ValueSnapshot.Reason.DEBUG_METADATA_ABSENT, entry.values().get(0).reason());
    assertNull(entry.values().get(0).preview());
    assertFalse(captured.stream().flatMap(e -> e.values() == null ? java.util.stream.Stream.empty()
        : e.values().stream()).anyMatch(v -> "unknown-name-canary".equals(v.preview())));
  }

  @Case
  void missingSourceNeverBorrowsTheHandlerOrGeneratedProxyFile() throws Exception {
    var method = demo.proxy.RepositoryContract.class.getMethod("save", String.class);
    var missing = ProxyInterfaceSources.lookup(method);
    assertNull(missing.path());
    assertEquals(0, missing.startLine());
    assertEquals(2, missing.binding());
  }

  @Case
  void throwingSinkDoesNotChangeResultsOrLeaveAParentBehind() throws Exception {
    ProxyBridge.disable(sink);
    ProxyBridge.Sink failed = new ProxyBridge.Sink() {
      @Override
      public ProxyBridge.Call resolve(Object proxy, Method method) {
        ProxyBridge.Call call = sink.resolve(proxy, method);
        if (call == null) return null;
        return new ProxyBridge.Call((recording, event, parent, kind, symbol,
            ns, declaration, args, result, thrown) -> {
          throw new IllegalStateException("sink failure");
        }, call.method(), call.symbol());
      }
    };
    assertTrue(ProxyBridge.install(failed));
    try {
      assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
      assertEquals("saved", call("save", String.class, "saved"));
      BootstrapBridge.frameEnter("Service.next");
      BootstrapBridge.frameExit("Service.next", false);
      BootstrapBridge.requestEnd(200, false);
      var captured = drain();
      var service = captured.stream().filter(e -> e.symbol().equals("Service.next")
          && e.kind() == BridgeEventKind.FRAME_ENTER).findFirst().orElseThrow();
      assertEquals(captured.get(0).eventId(), service.parentEventId());
    } finally {
      ProxyBridge.disable(failed);
    }
  }

  @Case
  void frameworkInheritedDeclarationIsNotRelabeledAndObjectMethodsAreExcluded() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("repository", proxy.toString());
    assertEquals("value", call("apply", Object.class, "value"));
    BootstrapBridge.requestEnd(200, false);
    var entries = drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).toList();
    assertEquals(1, entries.size());
    assertEquals("java.util.function.Function.apply", entries.get(0).symbol());
    assertNull(entries.get(0).sourcePath());
  }

  @Case
  void noRequestOrOutOfScopeInterfaceCreatesNoRepositoryFrames() throws Exception {
    assertEquals("value", call("save", String.class, "value"));
    assertTrue(queue.isEmpty());
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    var other = Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] {java.util.function.Function.class}, (p, m, args) -> args[0]);
    assertNull(sink.resolve(other, java.util.function.Function.class.getMethod("apply", Object.class)));
    BootstrapBridge.requestEnd(200, false);
    assertTrue(drain().stream().noneMatch(e -> e.kind() == BridgeEventKind.FRAME_ENTER));
  }

  @Case
  void hiddenLambdaHandlerStillProducesExactlyOneRepositoryFrame() throws Exception {
    InvocationHandler lambda = (p, m, arguments) -> arguments[0];
    assertTrue(lambda.getClass().isHidden());
    Object lambdaProxy = Proxy.newProxyInstance(contract.getClassLoader(),
        new Class<?>[] {contract}, lambda);
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals("saved", contract.getMethod("save", String.class).invoke(lambdaProxy, "saved"));
    BootstrapBridge.requestEnd(200, false);
    var captured = drain();
    assertEquals(1, captured.stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).count());
    assertEquals(1, captured.stream().filter(e -> e.kind() == BridgeEventKind.FRAME_EXIT).count());
  }

  @Case
  void repositoryDuringViewRenderingRemainsInsideTheDeferredRequest() throws Exception {
    dev.xtrace.agent.bootstrap.SpringMvcBridge.dispatchEnter();
    try {
      assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
      assertTrue(BootstrapBridge.deferRequestEnd(null));
      assertEquals("view-data", call("save", String.class, "view-data"));
      BootstrapBridge.requestEnd(200, false);
      assertEquals(1, drain().stream().filter(e -> e.kind() == BridgeEventKind.FRAME_ENTER).count());
    } finally {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.dispatchEnd(null, null);
    }
  }

  @Case
  void queueRejectionCountsLossAndHandlerStillReturns() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    while (queue.offer(new QueueSignal.Event("r", "e", "", 2, "fill", 1, 0, 64), false)) {}
    assertEquals("value", call("save", String.class, "value"));
    drain();
    BootstrapBridge.requestEnd(200, false);
    QueueSignal next;
    QueueSignal.Finish finish = null;
    while ((next = queue.poll(Duration.ZERO)) != null) {
      if (next instanceof QueueSignal.Finish terminal) finish = terminal;
    }
    assertNotNull(finish);
    assertTrue(finish.droppedEvents() >= 2);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Case
  void wideArgumentTupleIsExplicitlyUnavailableInsteadOfSilentlyShowingAPrefix() throws Exception {
    Class<?>[] parameters = new Class<?>[16];
    java.util.Arrays.fill(parameters, String.class);
    Object[] arguments = new Object[16];
    java.util.Arrays.fill(arguments, "x ".repeat(128));
    assertTrue(BootstrapBridge.requestStart("GET", "/repositories"));
    assertEquals(arguments[0], contract.getMethod("wide", parameters).invoke(proxy, arguments));
    BootstrapBridge.requestEnd(200, false);
    QueueSignal next;
    QueueSignal.Event entry = null;
    QueueSignal.Finish finish = null;
    while ((next = queue.poll(Duration.ZERO)) != null) {
      if (next instanceof QueueSignal.Event event && event.kind() == BridgeEventKind.FRAME_ENTER)
        entry = event;
      if (next instanceof QueueSignal.Finish terminal) finish = terminal;
    }
    assertNotNull(entry);
    assertNotNull(finish);
    assertEquals(1, entry.values().size());
    assertEquals("arguments", entry.values().get(0).name());
    assertEquals(ValueSnapshot.State.UNAVAILABLE, entry.values().get(0).state());
    assertEquals(ValueSnapshot.Reason.UNSAFE_TO_RENDER, entry.values().get(0).reason());
    assertTrue(RecordingWriter.toProto(entry, 1).getSerializedSize() < 4096);
    assertEquals(0, finish.droppedEvents());
  }

  @Case
  void overloadAndAnnotatedParameterHaveTheirOwnDeclarationLine() throws Exception {
    Method overload = contract.getMethod("save", long.class);
    var longSource = ProxyInterfaceSources.lookup(overload);
    var querySource = ProxyInterfaceSources.lookup(contract.getMethod("query", String.class));
    var genericSource = ProxyInterfaceSources.lookup(contract.getMethod("bounded", Number.class));
    var lines = Files.readAllLines(sourceBase().resolve("src/test/java/demo/proxy/RepositoryContract.java"));
    assertTrue(lines.get(longSource.startLine() - 1).contains("save(long id)"));
    assertTrue(lines.get(querySource.startLine() - 1).contains("query(@Param"));
    assertTrue(lines.get(genericSource.startLine() - 1).contains("bounded(T value)"));
  }

  private static final class Isolated extends ClassLoader {
    private final Map<String, byte[]> definitions;
    Isolated(ClassLoader parent, Map<String, byte[]> definitions) {
      super(parent);
      this.definitions = definitions;
    }
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (getClassLoadingLock(name)) {
        Class<?> type = findLoadedClass(name);
        if (type == null && definitions.containsKey(name)) {
          byte[] bytes = definitions.get(name);
          type = defineClass(name, bytes, 0, bytes.length);
        }
        if (type == null) return super.loadClass(name, resolve);
        if (resolve) resolveClass(type);
        return type;
      }
    }
  }
}
