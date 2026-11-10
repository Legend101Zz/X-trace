package demo.probe;

import java.util.function.Supplier;

/** Methods omitted by the standard boundary policy still own their focused cursors. */
public class CursorParents {
  private String name = "initial";

  public String getName() {
    return name;
  }

  public void setName(String value) {
    name = value;
  }

  public boolean isReady() {
    return name != null;
  }

  public String readName() {
    return getName();
  }

  public String getViaLambda() {
    Supplier<String> read = () -> {
      String value = name;
      return value;
    };
    return read.get();
  }

  @Override
  public String toString() {
    return "cursor-parent";
  }

  public String getBroken() {
    throw new IllegalStateException();
  }
}
