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
    RuntimeBridgeSink sink = new RuntimeBridgeSink(new BoundedEventQueue(32, 8192), 8, 0);
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
  void lifecycleAllowancePreservesOrderWhenBothEventBoundsAreFull() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(16, 4096);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    for (int i = 0; i < 8; i++) assertTrue(queue.offer(event("filler", "e" + i, 256), false));
    assertFalse(queue.offer(event("filler", "overflow", 128), false));
    for (int i = 0; i < 50; i++) {
      assertTrue(sink.offerStart("r" + i, 1, "GET", "/owners/{id}"));
      assertTrue(sink.offerFinish("r" + i, 1, 2, 200, 1));
    }
    assertEquals(50, sink.activeRecordings());
    for (int i = 0; i < 8; i++) assertTrue(queue.poll(Duration.ZERO) instanceof QueueSignal.Event);
    for (int i = 0; i < 50; i++) {
      assertEquals("r" + i, ((QueueSignal.Start) queue.poll(Duration.ZERO)).recordingId());
      assertEquals("r" + i, ((QueueSignal.Finish) queue.poll(Duration.ZERO)).recordingId());
    }
    assertTrue(queue.isEmpty());
    assertEquals(0, queue.size());
    assertEquals(0, queue.bytes());
  }

  @Test
  void pendingRecordingConfigurationHasTestedDefaultsAndAHardUpperBound() {
    assertEquals(64, RuntimeBridgeSink.pendingRecordings(null));
    assertEquals(50, RuntimeBridgeSink.pendingRecordings("50"));
    assertEquals(256, RuntimeBridgeSink.pendingRecordings("256"));
    for (String invalid : new String[] {"", "invalid", "0", "-1", "257", "2147483648"}) {
      assertEquals(64, RuntimeBridgeSink.pendingRecordings(invalid));
    }
    assertEquals(16_384, RecordingWriter.eventCap(""));
    assertEquals(131_072, RecordingWriter.eventCap("xtrace.focused.v1"));
    assertEquals(16_384, RecordingWriter.eventCap("unknown"));
  }

  @Test
  void lifecycleAllowanceAlsoHasFixedSlotAndPerSignalByteBounds() throws Exception {
    BoundedEventQueue queue = new BoundedEventQueue(16, 4096);
    assertFalse(queue.offerLifecycle(new QueueSignal.Start("large", 1, "GET", "/", 4097)));
    int slots = 2 * (BoundedEventQueue.MAX_PENDING_RECORDINGS
        + BoundedEventQueue.MAX_METADATA_RECORDINGS);
    for (int i = 0; i < slots; i++) assertTrue(queue.offerLifecycle(start("r" + i)));
    assertFalse(queue.offerLifecycle(start("overflow")));
    assertEquals(slots, queue.size());
    assertEquals(slots * 128L, queue.bytes());
    for (int i = 0; i < slots; i++) queue.poll(Duration.ZERO);
    assertEquals(0, queue.size());
    assertEquals(0, queue.bytes());
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
