package dev.xtrace.fixture;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Fixture repository that performs one parameterized H2 insert. */
@Repository
public class OrderRepository {
  private final JdbcTemplate jdbc;

  /** Creates the fixture repository. */
  public OrderRepository(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  /** Inserts one parameterized business row. */
  public void save(String description) {
    jdbc.update("INSERT INTO orders(description) VALUES (?)", description);
  }

  /** Returns the current business-row count for acceptance verification. */
  public int count() {
    Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM orders", Integer.class);
    return count == null ? 0 : count;
  }
}
