package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
