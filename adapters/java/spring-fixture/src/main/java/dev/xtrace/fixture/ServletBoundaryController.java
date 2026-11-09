package dev.xtrace.fixture;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** Real committed, buffered and container-rewritten responses for the packaged-agent journey. */
@Controller
@RequestMapping("/__fixture/boundary")
public class ServletBoundaryController {
  @GetMapping("/committed")
  public void committed(HttpServletResponse response) throws IOException {
    response.setStatus(209);
    response.flushBuffer();
  }

  @GetMapping("/uncommitted")
  public void uncommitted(HttpServletResponse response) {
    response.setStatus(210);
  }

  @GetMapping("/send-error")
  public void sendError(HttpServletResponse response) throws IOException {
    response.sendError(418);
  }

  @Configuration
  static class ErrorPage {
    @Bean
    FilterRegistrationBean<Filter> boundaryErrorPage() {
      FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
      registration.setFilter((request, response, chain) -> {
        // Runs only on the later container ERROR dispatch, outside the original request seam.
        if ("/__fixture/boundary/send-error".equals(
            request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI))) {
          ((HttpServletResponse) response).setStatus(451);
          response.flushBuffer();
        } else {
          chain.doFilter(request, response);
        }
      });
      registration.addUrlPatterns("/*");
      registration.setDispatcherTypes(DispatcherType.ERROR);
      return registration;
    }
  }
}
