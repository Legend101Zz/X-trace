package dev.xtrace.pgfixture;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Real Spring MVC application used by the focused PostgreSQL adapter journey. */
@SpringBootApplication(excludeName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
@RestController
public class PgJdbcFixture {
  private static final String SEED = System.getenv("XTRACE_PG_PROBE_SEED");

  public static void main(String[] args) throws SQLException {
    require(SEED != null && SEED.matches("[0-9a-f]{24}"), "private seed");
    // The instrumentation sees the driver load and execution, but there is no request to attach to.
    try (var connection = connect(); var statement = connection.createStatement();
         var result = statement.executeQuery("SELECT 'pgjdbc_outside_" + SEED + "'")) {
      require(result.next() && result.getString(1).equals("pgjdbc_outside_" + SEED),
          "out-of-request query");
    }
    var context = SpringApplication.run(PgJdbcFixture.class, args);
    System.out.println("PGJDBC_READY " + context.getEnvironment().getRequiredProperty("local.server.port"));
  }

  @GetMapping("/jdbc/success")
  public void success() throws SQLException {
    try (var connection = connect(); var statement = connection.createStatement()) {
      String literal = "pgjdbc_literal_" + SEED;
      try (var result = statement.executeQuery("SELECT '" + literal + "'")) {
        require(result.next() && result.getString(1).equals(literal), "plain query");
      }
      String bind = "pgjdbc_bind_" + SEED;
      try (var prepared = connection.prepareStatement("SELECT CAST(? AS text)")) {
        prepared.setString(1, bind);
        try (var result = prepared.executeQuery()) {
          require(result.next() && result.getString(1).equals(bind), "prepared query");
        }
      }
      statement.execute("CREATE TEMPORARY TABLE xtrace_probe (value text)");
      try (var prepared = connection.prepareStatement("INSERT INTO xtrace_probe VALUES (?)")) {
        prepared.setString(1, bind);
        prepared.addBatch();
        require(java.util.Arrays.equals(prepared.executeBatch(), new int[] {1}), "prepared batch");
      }
      statement.addBatch("INSERT INTO xtrace_probe VALUES ('" + literal + "')");
      require(java.util.Arrays.equals(statement.executeLargeBatch(), new long[] {1}), "plain batch");
      try (var result = statement.executeQuery("SELECT count(*) FROM xtrace_probe")) {
        require(result.next() && result.getInt(1) == 2, "batch effects");
      }
    }
  }

  @GetMapping("/jdbc/failure")
  public void failure() throws SQLException {
    try (var connection = connect(); var statement = connection.createStatement()) {
      String missing = "pgjdbc_failure_" + SEED;
      boolean rejected = false;
      try (var ignored = statement.executeQuery("SELECT " + missing)) {
        // The PostgreSQL server should throw before a result exists.
      } catch (SQLException expected) {
        rejected = "42703".equals(expected.getSQLState()) && expected.getMessage().contains(missing);
      }
      require(rejected, "database rejected missing column");
      try (var result = statement.executeQuery("SELECT 1")) {
        require(result.next() && result.getInt(1) == 1, "recovery query");
      }
    }
  }

  @GetMapping("/jdbc/empty")
  public void empty() throws SQLException {
    try (var connection = connect(); var statement = connection.createStatement()) {
      require(statement.executeBatch().length == 0, "empty batch");
    }
  }

  private static Connection connect() throws SQLException {
    return DriverManager.getConnection(
        System.getenv("XTRACE_PG_PROBE_URL") + "?ApplicationName=pgjdbc_url_" + SEED,
        "pgjdbc_user_" + SEED, "pgjdbc_password_" + SEED);
  }

  private static void require(boolean condition, String check) {
    if (!condition) throw new AssertionError(check);
  }
}
