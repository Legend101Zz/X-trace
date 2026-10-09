package demo.probe;

import org.springframework.web.bind.annotation.HandlerMarker;

public class Accessors {
  private String name = "n";

  /** A real web handler that happens to look like an accessor must still be probed. */
  @HandlerMarker
  public String getAllOwners() {
    return name;
  }

  public String getName() {
    return name;
  }

  public boolean isReady() {
    return true;
  }

  public void setName(String value) {
    name = value;
  }
}
