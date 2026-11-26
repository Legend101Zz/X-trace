package dev.xtrace.fixture;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
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

  /** A standard filter refusal. The route never reaches a controller mapping. */
  static final class RefusalFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
      String uri = ((HttpServletRequest) request).getRequestURI();
      HttpServletResponse http = (HttpServletResponse) response;
      if (uri.startsWith("/__fixture/refusal/committed/")) {
        http.setStatus(403);
        http.flushBuffer();
      } else if (uri.startsWith("/__fixture/refusal/send-error/")) {
        http.sendError(418);
      } else if (uri.startsWith("/__fixture/refusal/async/")) {
        AsyncContext async = request.startAsync();
        http.setStatus(429);
        async.complete();
      } else {
        chain.doFilter(request, response);
      }
    }
  }

  @Configuration
  static class ErrorPage {
    @Bean
    FilterRegistrationBean<Filter> boundaryRefusal() {
      FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
      registration.setFilter(new RefusalFilter());
      registration.addUrlPatterns("/__fixture/refusal/*");
      registration.setAsyncSupported(true);
      registration.setDispatcherTypes(DispatcherType.REQUEST);
      return registration;
    }

    @Bean
    ServletRegistrationBean<HttpServlet> nonMvcRefusalControl() {
      HttpServlet servlet = new HttpServlet() {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) {
          response.setStatus(409);
        }
      };
      return new ServletRegistrationBean<>(servlet, "/__fixture/service-control");
    }

    @Bean
    FilterRegistrationBean<Filter> boundaryErrorPage() {
      FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
      registration.setFilter((request, response, chain) -> {
        // Runs only on the later container ERROR dispatch, outside the original request seam.
        Object uri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        if ("/__fixture/boundary/send-error".equals(uri)
            || (uri instanceof String path && path.startsWith("/__fixture/refusal/send-error/"))) {
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
