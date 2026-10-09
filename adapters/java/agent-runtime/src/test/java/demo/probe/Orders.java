package demo.probe;

public class Orders {
  public String create(String description) {
    String normalized = description.trim();
    return place(normalized);
  }

  String place(String order) {
    String saved = order.toUpperCase();
    return saved;
  }
}
