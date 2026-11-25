package dev.xtrace.interruptfixture;

import java.util.concurrent.CountDownLatch;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication(
    proxyBeanMethods = false,
    excludeName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
@RestController
public class SpringInterruptedFixture {
  private final CountDownLatch unresolved = new CountDownLatch(1);

  public static void main(String[] args) {
    var context = SpringApplication.run(SpringInterruptedFixture.class, args);
    System.out.println("INTERRUPT_READY " + context.getEnvironment().getRequiredProperty("local.server.port")
        + " " + ProcessHandle.current().pid());
  }

  @GetMapping("/held")
  public String hold() throws InterruptedException {
    System.out.println("INTERRUPT_HELD");
    unresolved.await();
    return "released";
  }
}
