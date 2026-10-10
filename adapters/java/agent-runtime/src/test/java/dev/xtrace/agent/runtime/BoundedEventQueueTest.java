package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.bootstrap.BridgeSink;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class BoundedEventQueueTest {
  @Test
  void reservesSlotsForStartAndFinishWhileNormalOffersSaturate() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(16, 4096);
    assertTrue(queue.offer(start("r"), false));
    for (int index = 1; index < 8; index++) {
      assertTrue(queue.offer(event("r", Integer.toString(index), 128), false));
    }
    assertFalse(queue.offer(event("r", "full", 128), false));
    for (int index = 0; index < 8; index++) {
      assertTrue(queue.offer(finish("r" + index), true));
    }
    assertFalse(queue.offer(finish("overflow"), true));
    assertEquals(16, queue.size());
    while (!queue.isEmpty()) queue.poll(Duration.ofMillis(1));
    assertEquals(0, queue.size());
    assertEquals(0, queue.bytes());
  }

  @Test
  void rejectsNormalOfferThatWouldConsumeReservedByteBudget() {
    BoundedEventQueue queue = new BoundedEventQueue(16, 4096);
    assertFalse(queue.offer(event("r", "large", 2100), false));
    assertTrue(queue.offer(finish("r"), true));
  }

  @Test
  void sinkBoundsActiveRecordingsAndReleasesCapacityOnlyWhenTheWriterClosesTheRecording() {
    RuntimeBridgeSink sink = new RuntimeBridgeSink(new BoundedEventQueue(32, 8192));
    for (int index = 0; index < 8; index++) {
      assertTrue(sink.offerStart("recording-" + index, 1, "POST", "/orders"));
    }
    assertFalse(sink.offerStart("recording-overflow", 1, "POST", "/orders"));
    assertTrue(sink.offerFinish("recording-0", 1, 2, 201, 0));
    // A queued finish does not free the slot: the writer still holds the recording.
    assertFalse(sink.offerStart("recording-next", 3, "POST", "/orders"));
    sink.recordingClosed();
    assertTrue(sink.offerStart("recording-next", 3, "POST", "/orders"));
  }

  @Test
  void shutdownFenceSeesInFlightStartAndStaleAdmissionCannotEnqueue() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(32, 8192);
    CountDownLatch admissionEntered = new CountDownLatch(1);
    CountDownLatch releaseAdmission = new CountDownLatch(1);
    CountDownLatch rejectionPublished = new CountDownLatch(1);
    CountDownLatch releaseDecrement = new CountDownLatch(1);
    RuntimeBridgeSink sink =
        new RuntimeBridgeSink(
            queue,
            () -> {
              admissionEntered.countDown();
              awaitUninterruptibly(releaseAdmission);
            },
            () -> {
              rejectionPublished.countDown();
              awaitUninterruptibly(releaseDecrement);
            });
    AtomicBoolean accepted = new AtomicBoolean(true);
    Thread producer =
        new Thread(
            () -> accepted.set(sink.offerStart("recording-race", 1, "POST", "/orders")));
    producer.start();
    assertTrue(admissionEntered.await(1, TimeUnit.SECONDS));
    assertFalse(sink.startAdmissionsDrained());

    sink.stopStarting();
    assertFalse(sink.startAdmissionsDrained());
    releaseAdmission.countDown();
    assertTrue(rejectionPublished.await(1, TimeUnit.SECONDS));

    assertFalse(sink.startAdmissionsDrained());
    assertEquals(BridgeSink.INCOMPLETE_START_REJECTED, sink.takeIncompleteKind());
    assertTrue(producer.isAlive());
    assertTrue(queue.isEmpty());
    releaseDecrement.countDown();
    producer.join(1_000);

    assertFalse(producer.isAlive());
    assertFalse(accepted.get());
    assertTrue(sink.startAdmissionsDrained());
    assertTrue(queue.isEmpty());
  }

  private static void awaitUninterruptibly(CountDownLatch latch) {
    boolean interrupted = false;
    while (true) {
      try {
        latch.await();
        break;
      } catch (InterruptedException ignored) {
        interrupted = true;
      }
    }
    if (interrupted) Thread.currentThread().interrupt();
  }

  private static QueueSignal.Start start(String id) {
    return new QueueSignal.Start(id, 1, "POST", "/orders", 128);
  }

  private static QueueSignal.Event event(String id, String event, int bytes) {
    return new QueueSignal.Event(id, event, "", 2, "symbol", 1, 0, bytes);
  }

  private static QueueSignal.Finish finish(String id) {
    return new QueueSignal.Finish(id, 1, 2, 201, 0, 128);
  }
}
