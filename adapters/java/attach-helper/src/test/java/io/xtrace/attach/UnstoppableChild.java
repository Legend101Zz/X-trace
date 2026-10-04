package io.xtrace.attach;

import java.util.concurrent.CountDownLatch;

/** Small owned child used to verify failure cleanup never signals a target implicitly. */
public final class UnstoppableChild {
  private UnstoppableChild() {}

  public static void main(String[] arguments) throws InterruptedException {
    System.out.println("READY");
    System.out.flush();
    new CountDownLatch(1).await();
  }
}
