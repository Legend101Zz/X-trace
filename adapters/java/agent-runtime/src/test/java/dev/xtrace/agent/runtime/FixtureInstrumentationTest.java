package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.adapter.ClientException;
import dev.xtrace.fixture.OrderService;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class FixtureInstrumentationTest {
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
