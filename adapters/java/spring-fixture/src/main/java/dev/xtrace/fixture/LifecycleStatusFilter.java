package dev.xtrace.fixture;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;

/** Demonstrates why dispatcher-exit status does not prove final client delivery. */
@Component
public class LifecycleStatusFilter implements Filter {
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    chain.doFilter(request, response);
    if (request instanceof HttpServletRequest http
        && http.getRequestURI().equals("/__fixture/lifecycle/post-filter")) {
      ((HttpServletResponse) response).setStatus(304);
    }
  }
}
