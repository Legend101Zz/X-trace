package dev.xtrace.fixture;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.Callable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.View;

/** Real MVC seams used by the packaged-agent lifecycle journeys. */
@Controller
@RequestMapping("/__fixture/lifecycle")
public class LifecycleController {
  @GetMapping("/forward")
  public View forward() {
    return (model, request, response) -> {
      request.getRequestDispatcher("/__fixture/lifecycle/inner").forward(request, response);
      afterNested();
    };
  }

  @GetMapping("/include")
  public View include() {
    return (model, request, response) -> {
      request.getRequestDispatcher("/__fixture/lifecycle/inner").include(request, response);
      afterNested();
      response.setStatus(207);
    };
  }

  @GetMapping("/inner")
  public ResponseEntity<Void> inner() {
    return ResponseEntity.status(202).build();
  }

  /** A frame after the nested dispatch proves the outer root survived view rendering. */
  public void afterNested() {}

  @GetMapping("/mapped")
  public View mapped() {
    throw new IllegalArgumentException("fixture mapped exception");
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public View resolve() {
    // Resolution returns a view first; its response status only exists after rendering.
    return (model, request, response) -> response.setStatus(422);
  }

  @GetMapping("/async")
  public Callable<ResponseEntity<Void>> async() {
    return () -> ResponseEntity.status(206).build();
  }

  @GetMapping("/post-filter")
  public View postFilter() {
    // Leave the response uncommitted so the enclosing filter can change its status.
    return (model, request, response) -> response.setStatus(200);
  }

  @GetMapping("/send-error")
  public void sendError(HttpServletResponse response) throws IOException {
    // Tomcat handles the ERROR dispatch after doDispatch has exited.
    response.sendError(418);
  }
}
