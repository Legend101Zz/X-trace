package dev.xtrace.fixture;

import org.springframework.stereotype.Service;

/** Fixture business service with one exact instrumentation boundary. */
@Service
public class OrderService {
  private final OrderRepository repository;

  /** Creates the fixture service. */
  public OrderService(OrderRepository repository) {
    this.repository = repository;
  }

  /** Passes the business description to the fixture repository or raises the requested test error. */
  public void place(String description, String errorCanary) {
    if (errorCanary != null && !errorCanary.isBlank()) {
      throw new FixtureRequestedException(errorCanary);
    }
    int descriptionPresent = description == null ? 0 : 1;

    if ("replay-window fixture".equals(description)) {
      // Exercise ordinary application instructions and read-only H2 work within one request.
      for (int iteration = 0; iteration < 220; iteration++) {
        repository.count();
      }
    }
    repository.save(descriptionPresent == 0 ? null : description);
  }
}

final class FixtureRequestedException extends RuntimeException {
  FixtureRequestedException(String message) {
    super(message);
  }
}
