package dev.xtrace.agent.bootstrap;

/** Fixed JDBC identities shared by the inlined probes and the recording encoder. */
public enum JdbcOperation {
  H2_UPDATE("h2", "executeUpdate"),
  PGJDBC_EXECUTE("pgjdbc", "execute"),
  PGJDBC_BATCH("pgjdbc", "executeBatch");

  private static final JdbcOperation[] KNOWN = values();

  private final String driver;
  private final String method;
  private final String symbol;
  private final String failureSymbol;

  JdbcOperation(String driver, String method) {
    this.driver = driver;
    this.method = method;
    symbol = driver + "." + method;
    failureSymbol = symbol + ".failed";
  }

  public String driver() { return driver; }

  public String method() { return method; }

  String symbol(boolean failed) { return failed ? failureSymbol : symbol; }

  public static JdbcOperation forSymbol(String symbol) {
    for (JdbcOperation operation : KNOWN) {
      if (operation.symbol.equals(symbol) || operation.failureSymbol.equals(symbol)) return operation;
    }
    return null;
  }
}
