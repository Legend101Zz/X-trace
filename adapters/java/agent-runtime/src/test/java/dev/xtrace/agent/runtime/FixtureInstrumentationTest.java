package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.adapter.ClientException;
import dev.xtrace.fixture.OrderService;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

class FixtureInstrumentationTest {
  @Test
  void defaultBootScopePreservesDependencyExclusionAndUnknownOriginsOnFailure() throws Exception {
    assertScopedFailures(ApplicationScope.defaultScope());
  }

  @Test
  void overlappingConfiguredPackagesPreserveBootDependencyExclusionOnFailure() throws Exception {
    assertScopedFailures(new ApplicationScope(List.of("demo.probe"), List.of()));
  }

  private void assertScopedFailures(ApplicationScope scope) throws Exception {
    var limitations = new FixtureInstrumentation.CaptureLimitations();
    var listener = new FixtureInstrumentation.SafeListener(
        () -> { throw new AssertionError("ordinary failures must fail open"); }, scope, limitations);
    // Deliberately equal loaders: type identity uses loader identity, never equals/hashCode.
    ClassLoader application = equalLoader();
    ClassLoader dependency = equalLoader();
    String name = "demo.probe.SharedName";
    observe(listener, application, name, bootDomain("classes/"));
    observe(listener, dependency, name, bootDomain("lib/dependency.jar"));
    listener.onError(name, dependency, null, false, new IllegalStateException("dependency"));
    listener.onComplete(name, dependency, null, false);
    assertEquals(0, limitations.count());
    listener.onError(name, application, null, false, new IllegalStateException("application"));
    listener.onComplete(name, application, null, false);
    assertEquals(1, limitations.count());
    // Completion consumes successful verdicts; an error without an observed origin cannot
    // reuse the previous application's verdict or invent application scope from a name.
    observe(listener, application, name, bootDomain("classes/"));
    listener.onComplete(name, application, null, false);
    listener.onError(name, application, null, false, new IllegalStateException("no callback"));
    observe(listener, application, "other.library.Unknown", null);
    listener.onError("other.library.Unknown", application, null, false, new IllegalStateException("unknown"));
    listener.onComplete("other.library.Unknown", application, null, false);
    assertEquals(1, limitations.count());
    listener.observeScope(application, name, bootDomain("classes/"));
    listener.onError(name, application, null, false, new IllegalStateException("discovery scan"));
    assertEquals(1, limitations.count());
    // Error is followed by completion. A nested callback for the same key must retire only
    // its own verdict, preserving the outer application's in-flight scope decision.
    observe(listener, application, name, bootDomain("classes/"));
    observe(listener, application, name, bootDomain("lib/dependency.jar"));
    listener.onError(name, application, null, false, new IllegalStateException("nested dependency"));
    listener.onComplete(name, application, null, false);
    assertEquals(1, limitations.count());
    listener.onError(name, application, null, false, new IllegalStateException("outer application"));
    listener.onComplete(name, application, null, false);
    assertEquals(2, limitations.count());
  }

  private static void observe(FixtureInstrumentation.SafeListener listener, ClassLoader loader,
      String name, ProtectionDomain domain) {
    listener.onDiscovery(name, loader, null, false);
    listener.observeScope(loader, name, domain);
  }

  private ClassLoader equalLoader() {
    return new ClassLoader(getClass().getClassLoader()) {
      @Override public boolean equals(Object other) { return other instanceof ClassLoader; }
      @Override public int hashCode() { return 0; }
    };
  }

  private static ProtectionDomain bootDomain(String suffix) throws Exception {
    return new ProtectionDomain(new CodeSource(URI.create("file:/application.jar!/BOOT-INF/" + suffix).toURL(),
        (java.security.cert.Certificate[]) null), null);
  }

  @Test
  void gapOwnerRequiresTheActualBridgeEvenWhenAShadowHasLineGap() {
    assertTrue(FixtureInstrumentation.gapOwnerAvailable(getClass().getClassLoader()));
    String name = FixtureInstrumentation.PROBE_OWNER.replace('/', '.');
    ClassWriter bytes = new ClassWriter(0);
    bytes.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, FixtureInstrumentation.PROBE_OWNER,
        null, "java/lang/Object", null);
    var gap = bytes.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "lineGap", "()V", null, null);
    gap.visitCode();
    gap.visitInsn(Opcodes.RETURN);
    gap.visitMaxs(0, 0);
    gap.visitEnd();
    bytes.visitEnd();
    byte[] shadow = bytes.toByteArray();
    ClassLoader loader = new ClassLoader(getClass().getClassLoader()) {
      @Override
      protected Class<?> loadClass(String requested, boolean resolve) throws ClassNotFoundException {
        if (!name.equals(requested)) return super.loadClass(requested, resolve);
        Class<?> owner = findLoadedClass(requested);
        if (owner == null) owner = defineClass(requested, shadow, 0, shadow.length);
        if (resolve) resolveClass(owner);
        return owner;
      }
    };
    assertFalse(FixtureInstrumentation.gapOwnerAvailable(loader));
  }

  @Test
  void matchersExcludeAgentFrameworkProxiesAndUnrelatedApplicationTypes() {
    assertTrue(
        FixtureInstrumentation.isApplicationTarget(
            "dev.xtrace.fixture.OrderController", "create"));
    assertTrue(
        FixtureInstrumentation.isApplicationTarget("dev.xtrace.fixture.OrderService", "place"));
    assertTrue(
        FixtureInstrumentation.isApplicationTarget("dev.xtrace.fixture.OrderRepository", "save"));
    assertFalse(
        FixtureInstrumentation.isApplicationTarget(
            "dev.xtrace.fixture.OrderController$$SpringCGLIB$$0", "create"));
    assertFalse(
        FixtureInstrumentation.isApplicationTarget(
            "dev.xtrace.agent.runtime.AgentRuntime", "start"));
    assertFalse(
        FixtureInstrumentation.isApplicationTarget(
            "dev.xtrace.fixture.FixtureAdminController", "count"));
    assertTrue(
        FixtureInstrumentation.isExplicitTarget(
            "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter"));
    assertTrue(FixtureInstrumentation.isExplicitTarget("org.h2.jdbc.JdbcPreparedStatement"));
  }

  @Test
  void explicitTransformationFailureStopsCaptureWithoutPropagatingCallbackFailure() {
    AtomicBoolean stopped = new AtomicBoolean();
    FixtureInstrumentation.SafeListener listener =
        new FixtureInstrumentation.SafeListener(
            () -> {
              stopped.set(true);
              throw new IllegalStateException("test-only callback failure");
            });
    listener.onError(
        FixtureInstrumentation.CONTROLLER,
        getClass().getClassLoader(),
        null,
        false,
        new IllegalStateException("test-only transformation failure"));
    assertTrue(stopped.get());

    stopped.set(false);
    listener.onError(
        "dev.xtrace.fixture.Unrelated",
        getClass().getClassLoader(),
        null,
        false,
        new IllegalStateException("test-only unrelated failure"));
    assertFalse(stopped.get());
  }

  @Test
  void attachRequiresRetransformationAndAnExplicitLoadedFixtureClass() throws Exception {
    Instrumentation supported = instrumentation(true, true, OrderService.class);
    FixtureInstrumentation.validateAttach(supported);

    ClientException unsupported =
        assertThrows(
            ClientException.class,
            () -> FixtureInstrumentation.validateAttach(instrumentation(false, true)));
    assertTrue(unsupported.code().contains("ATTACH-UNAVAILABLE"));

    ClientException noFixture =
        assertThrows(
            ClientException.class,
            () -> FixtureInstrumentation.validateAttach(instrumentation(true, true)));
    assertTrue(noFixture.code().contains("ATTACH-UNAVAILABLE"));

    Class<?>[] excessive = new Class<?>[17];
    java.util.Arrays.fill(excessive, OrderService.class);
    ClientException overLimit =
        assertThrows(
            ClientException.class,
            () -> FixtureInstrumentation.validateAttach(instrumentation(true, true, excessive)));
    assertTrue(overLimit.code().contains("ATTACH-UNAVAILABLE"));
  }

  @Test
  void attachRejectsLoadedFixtureClassThatCannotBeModified() {
    ClientException failure =
        assertThrows(
            ClientException.class,
            () ->
                FixtureInstrumentation.validateAttach(
                    instrumentation(true, false, OrderService.class)));
    assertTrue(failure.code().contains("ATTACH-UNAVAILABLE"));
  }

  private static Instrumentation instrumentation(
      boolean retransformation, boolean modifiable, Class<?>... loadedClasses) {
    return (Instrumentation)
        Proxy.newProxyInstance(
            Instrumentation.class.getClassLoader(),
            new Class<?>[] {Instrumentation.class},
            (proxy, method, arguments) -> {
              return switch (method.getName()) {
                case "isRetransformClassesSupported" -> retransformation;
                case "getAllLoadedClasses" -> loadedClasses;
                case "isModifiableClass" -> modifiable;
                case "toString" -> "test instrumentation";
                default -> {
                  Class<?> result = method.getReturnType();
                  if (result == boolean.class) yield false;
                  if (result == int.class) yield 0;
                  if (result == long.class) yield 0L;
                  yield null;
                }
              };
            });
  }
}
