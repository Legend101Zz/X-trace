package dev.xtrace.agent.runtime.testapp;

public class SampleService {
  private final SampleRepository repository = new SampleRepository();

  public String place(String value) {
    String saved = repository.save(value);
    return saved.toUpperCase();
  }

  public String placeTolerant(String value) {
    try {
      return repository.save(value);
    } catch (IllegalStateException handled) {
      return "recovered";
    }
  }

  public java.util.function.Supplier<String> deferred(String value) {
    return () -> value + "!";
  }

  public static String shout(String value) {
    return value + "!";
  }

  public boolean isReady() {
    return true;
  }
}
