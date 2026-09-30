package dev.xtrace.fixture;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** One deterministic observed route for the fixture-scoped premain proof. */
@RestController
@RequestMapping("/orders")
public class OrderController {
  private final OrderService service;

  /** Creates the fixture controller. */
  public OrderController(OrderService service) {
    this.service = service;
  }

  /** Inserts one order and returns the deterministic 201 fixture response. */
  @PostMapping
  public ResponseEntity<Map<String, String>> create(@RequestBody OrderRequest request) {
    try {
      service.place(request.description(), request.errorCanary());
    } catch (FixtureRequestedException ignored) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("status", "failed"));
    }
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "created"));
  }

  /** Request body intentionally crosses the application but is never captured by X-trace. */
  public record OrderRequest(String description, String bodyCanary, String errorCanary) {}
}
