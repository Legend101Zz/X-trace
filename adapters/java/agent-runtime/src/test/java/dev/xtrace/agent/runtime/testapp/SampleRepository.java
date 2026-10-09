package dev.xtrace.agent.runtime.testapp;

public class SampleRepository {
  private String lastSaved;

  public String save(String value) {
    if (value.equals("boom")) {
      throw new IllegalStateException("repository failure");
    }
    lastSaved = value;
    return value;
  }

  public String getLastSaved() {
    return lastSaved;
  }

  public void setLastSaved(String value) {
    lastSaved = value;
  }

  @Override
  public String toString() {
    return "SampleRepository";
  }
}
