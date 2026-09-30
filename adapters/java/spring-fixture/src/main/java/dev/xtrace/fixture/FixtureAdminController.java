package dev.xtrace.fixture;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Test-only observations that are deliberately outside the instrumented controller matcher. */
@RestController
@RequestMapping("/__fixture")
public class FixtureAdminController {
  private final OrderRepository repository;

  /** Creates the acceptance-only controller. */
  public FixtureAdminController(OrderRepository repository) {
    this.repository = repository;
  }

  /** Exposes only the business-row count. */
  @GetMapping("/count")
  public Map<String, Integer> count() {
    return Map.of("count", repository.count());
  }

  /** Reports whether private agent dependencies leaked into the application classloader. */
  @GetMapping("/isolation")
  public Map<String, Boolean> isolation() {
    ClassLoader applicationLoader = FixtureAdminController.class.getClassLoader();
    return Map.of(
        "byte_buddy", visible("net.bytebuddy.ByteBuddy", applicationLoader),
        "protobuf", visible("com.google.protobuf.Message", applicationLoader),
        "conscrypt", visible("org.conscrypt.Conscrypt", applicationLoader),
        "agent_runtime", visible("dev.xtrace.agent.runtime.AgentRuntime", applicationLoader));
  }

  private static boolean visible(String name, ClassLoader loader) {
    try {
      Class.forName(name, false, loader);
      return true;
    } catch (ClassNotFoundException expected) {
      return false;
    }
  }
}
