package demo.probe;

import java.util.function.Supplier;

public class LambdaOrders {
  public String create(String description) {
    Supplier<String> normalized = () -> description.trim().toUpperCase();
    return normalized.get();
  }

  public int create(int quantity) {
    return quantity;
  }
}
