package dev.xtrace.agent.runtime.testapp;

public class SampleController {
  private final SampleService service = new SampleService();

  public String create(String value) {
    return service.place(value);
  }

  public String createTolerant(String value) {
    return service.placeTolerant(value);
  }
}
