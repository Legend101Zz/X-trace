package fixture.jersey;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.ApplicationPath;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardWatchEventKinds;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.ServerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Fixture {
  public static void main(String[] args) throws Exception {
    var app = (ServletWebServerApplicationContext) SpringApplication.run(Fixture.class, args);
    // Readiness is outside HTTP, so the proof can account for every request it sends.
    Path control = Path.of(System.getProperty("fixture.control"));
    try (app; var watch = FileSystems.getDefault().newWatchService()) {
      control.register(watch, StandardWatchEventKinds.ENTRY_CREATE);
      Path pending = control.resolve("port.pending");
      Files.writeString(pending, Integer.toString(app.getWebServer().getPort()), StandardOpenOption.CREATE_NEW);
      Files.move(pending, control.resolve("port"), StandardCopyOption.ATOMIC_MOVE);
      while (!Files.exists(control.resolve("stop"))) {
        var key = watch.take();
        key.pollEvents();
        if (!key.reset()) throw new IllegalStateException("control directory disappeared");
      }
    }
  }

  @Bean
  ResourceConfig resourceConfig() {
    return new Resources();
  }

  @ApplicationPath("/declared")
  static class Resources extends ResourceConfig {
    Resources() {
      // Exercise Jersey's synchronous 404 status path during parameter conversion.
      property(ServerProperties.RESPONSE_SET_STATUS_OVER_SEND_ERROR, true);
      register(Groups.class);
    }
  }

  @Bean
  FilterRegistrationBean<Refusal> refusal() {
    var registration = new FilterRegistrationBean<>(new Refusal());
    registration.addUrlPatterns("/effective/refused");
    return registration;
  }

  static class Refusal implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
      ((HttpServletResponse) response).setStatus(403);
    }
  }
}
