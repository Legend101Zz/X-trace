package dev.xtrace.catalogfixture;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication(
    proxyBeanMethods = false,
    excludeName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
@RestController
public class SpringLinkFixture {
  public static void main(String[] args) {
    var context = SpringApplication.run(SpringLinkFixture.class, args);
    System.out.println("LINK_FIXTURE_READY " + context.getEnvironment().getRequiredProperty("local.server.port"));
  }

  @GetMapping("/owners/{ownerId}")
  public String owner() {
    return "ok";
  }
}
