package dev.xtrace.fixture;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Independent Spring MVC fixture used only by the launch-agent acceptance test. */
@SpringBootApplication
public class FixtureApplication {
  /** Starts the fixture application. */
  public static void main(String[] args) {
    SpringApplication.run(FixtureApplication.class, args);
  }
}
