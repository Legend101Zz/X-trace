package demo.probe;

public class BranchLoop {
  public int sum(int bound) {
    int result = 0;
    int i = 0;
    while (i < bound) {
      if ((i & 1) == 0) {
        result += i;
      } else {
        result -= i;
      }
      i++;
    }
    return result;
  }
}
