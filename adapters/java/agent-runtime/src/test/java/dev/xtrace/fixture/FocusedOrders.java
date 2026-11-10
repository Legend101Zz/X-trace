package dev.xtrace.fixture;

public final class FocusedOrders {
  public int total(boolean discount) {
    if (discount) {
      return 7;
    }
    return 10;
  }
}
