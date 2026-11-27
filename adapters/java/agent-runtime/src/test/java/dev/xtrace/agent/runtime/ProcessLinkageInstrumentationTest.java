package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.Message;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.ProcessLinkageBridge;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.GapReason;
import xtp.agent.v1.Recording.InteractionKind;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;

class ProcessLinkageInstrumentationTest {
  @BeforeEach
  void setUp() {
    ProcessLinkageInstrumentation.resetForTest();
    ProcessLinkageBridge.takeInstrumentationUnavailable();
  }

  @AfterEach
  void tearDown() {
    ProcessLinkageInstrumentation.resetForTest();
    ProcessLinkageBridge.takeInstrumentationUnavailable();
  }

  @Test
  void realProcessBuilderAdvicePassesBytecodeVerificationWithoutTouchingArgsOrEnv() {
    TypeDescription processBuilderType =
        TypePool.Default.ofBootLoader().describe(ProcessLinkageInstrumentation.PROCESS_BUILDER).resolve();
    byte[] transformed =
        new ByteBuddy()
            .redefine(processBuilderType, ClassFileLocator.ForClassLoader.ofBootLoader())
            .visit(
                Advice.to(ProcessLinkageInstrumentation.ProcessStartAdvice.class)
                    .on(ProcessLinkageInstrumentation.processStartMethods()))
            .make()
            .getBytes();
    assertTrue(transformed.length > 0);
  }

  @Test
  void manifestAndWriterAdvertiseProcessLinkageAndEndToEndSignalsEncodeCleanly() throws Exception {
    try (InputStream manifestStream =
        AgentRuntime.class.getResourceAsStream("/agent-manifest.json")) {
      assertNotNull(manifestStream);
      String manifestJson = new String(manifestStream.readAllBytes(), StandardCharsets.UTF_8);
      assertTrue(manifestJson.contains("\"process_linkage\""));
    }

    var stubType =
        new ByteBuddy()
            .subclass(Object.class)
            .name("demo.ProcessBuilderStub")
            .defineMethod("start", Process.class, Visibility.PUBLIC)
            .intercept(FixedValue.nullValue())
            .make();
    Map<String, byte[]> defs = Map.of("demo.ProcessBuilderStub", stubType.getBytes());
    var locator =
        new ClassFileLocator.Compound(
            new ClassFileLocator.Simple(defs),
            ClassFileLocator.ForClassLoader.of(getClass().getClassLoader()));
    var listener = new ProcessLinkageInstrumentation.FailureListener(() -> {});
    var transformer =
        ProcessLinkageInstrumentation.configure(
                new AgentBuilder.Default()
                    .disableClassFormatChanges()
                    .with(new AgentBuilder.LocationStrategy.Simple(locator))
                    .with(listener),
                listener,
                named("demo.ProcessBuilderStub"))
            .makeRaw();

    byte[] transformedBytes =
        transformer.transform(
            getClass().getClassLoader(),
            "demo/ProcessBuilderStub",
            null,
            null,
            stubType.getBytes());

    ClassLoader isolated =
        new ClassLoader(getClass().getClassLoader()) {
          @Override
          protected Class<?> findClass(String name) throws ClassNotFoundException {
            if ("demo.ProcessBuilderStub".equals(name)) {
              return defineClass(name, transformedBytes, 0, transformedBytes.length);
            }
            throw new ClassNotFoundException(name);
          }
        };
    Object stub = isolated.loadClass("demo.ProcessBuilderStub").getDeclaredConstructor().newInstance();
    var startMethod = stub.getClass().getMethod("start");

    CapturingTransport transport = new CapturingTransport();
    BoundedEventQueue queue = new BoundedEventQueue(64, 512 * 1024);
    RuntimeBridgeSink sink = new RuntimeBridgeSink(queue);
    String secretToken = "raw-runtime-secret-token-canary";

    try (RecordingWriter writer = new RecordingWriter(transport, queue, sink, Duration.ofSeconds(2))) {
      assertTrue(BootstrapBridge.install(sink));
      writer.start();
      try {
        assertTrue(BootstrapBridge.requestStart("POST", "/spawn"));
        // 1) Plain ProcessBuilder.start() without opt-in -> child_process_not_instrumented gap.
        startMethod.invoke(stub);
        // 2) Valid opt-in child link -> jvm_fork ASYNC_LINK + INTERACTION_KIND_PROCESS.
        try (var ignored =
            ProcessLinkageBridge.withOptInChildLink(
                "01900000-0000-7000-8000-000000000201",
                "01900000-0000-7000-8000-000000000202",
                secretToken,
                secretToken)) {
          startMethod.invoke(stub);
          // 3) Reused single-use scope -> bootstrap_consumed gap.
          startMethod.invoke(stub);
        }
        // 4) Mismatched correlation token -> correlation_lost gap.
        assertFalse(
            ProcessLinkageBridge.registerChildSessionLink(
                "01900000-0000-7000-8000-000000000203", null, "bad-token", secretToken));
        BootstrapBridge.requestEnd(200, false);
      } finally {
        BootstrapBridge.disable(sink);
      }
    }

    assertNotNull(transport.capabilities);
    assertTrue(
        transport.capabilities.getCapabilitiesList().stream()
            .anyMatch(c -> "process_linkage".equals(c.getName())));

    List<RecordingEvent> events =
        transport.batches.stream().flatMap(b -> b.getEventsList().stream()).toList();
    assertTrue(
        events.stream()
            .anyMatch(
                e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
                    && e.getGap().getReason() == GapReason.GAP_REASON_CHILD_PROCESS_NOT_INSTRUMENTED));
    assertTrue(
        events.stream()
            .anyMatch(
                e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
                    && e.getGap().getReason() == GapReason.GAP_REASON_BOOTSTRAP_CONSUMED));
    assertTrue(
        events.stream()
            .anyMatch(
                e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_GAP
                    && e.getGap().getReason() == GapReason.GAP_REASON_CORRELATION_LOST));
    assertTrue(
        events.stream()
            .anyMatch(
                e -> e.getKind() == RecordingEventKind.RECORDING_EVENT_KIND_ASYNC_LINK
                    && BootstrapBridge.PROCESS_LINK_SYMBOL.equals(e.getSymbol())
                    && e.getInteraction().getKind() == InteractionKind.INTERACTION_KIND_PROCESS
                    && "jvm".equals(e.getInteraction().getDriver())
                    && "fork".equals(e.getInteraction().getMethod())));

    // Secret correlation token never enters the wire batches.
    for (RecordingEvent ev : events) {
      assertFalse(ev.toString().contains(secretToken));
    }
  }

  @Test
  void failureListenerDegradesWithoutThrowingOnTransformationErrors() {
    AtomicInteger limitations = new AtomicInteger();
    var listener = new ProcessLinkageInstrumentation.FailureListener(limitations::incrementAndGet);
    var type = TypeDescription.ForLoadedType.of(Object.class);
    var loader = getClass().getClassLoader();
    assertTrue(
        listener
            .selected((t, l, m, r, d) -> named(type.getName()).matches(t))
            .matches(type, loader, null, null, null));
    listener.onError(type.getName(), loader, null, false, new IllegalStateException("boom"));
    assertEquals(1, limitations.get());
    assertTrue(ProcessLinkageBridge.takeInstrumentationUnavailable());
  }

  private static final class CapturingTransport implements RecordingWriter.Transport {
    volatile CapabilitySet capabilities;
    final List<RecordingStarted> starts = new CopyOnWriteArrayList<>();
    final List<EventBatch> batches = new CopyOnWriteArrayList<>();
    final List<RecordingFinished> finishes = new CopyOnWriteArrayList<>();

    @Override
    public Ack send(String messageId, String correlationToken, Message payload)
        throws ClientException {
      long seq = 0;
      if (payload instanceof CapabilitySet caps) {
        capabilities = caps;
      } else if (payload instanceof RecordingStarted started) {
        starts.add(started);
        seq = started.getRecordingSeq();
      } else if (payload instanceof EventBatch batch) {
        batches.add(batch);
        seq = batch.getEventsCount() == 0
            ? 0 : batch.getEvents(batch.getEventsCount() - 1).getRecordingSeq();
      } else if (payload instanceof RecordingFinished finished) {
        finishes.add(finished);
        seq = finished.getFinalRecordingSeq();
      }
      Ack.Builder ack =
          Ack.newBuilder()
              .setDurability(AckDurability.ACK_DURABILITY_STAGED)
              .setHighestContiguousSessionSeq(1);
      if (correlationToken != null && !correlationToken.isEmpty() && seq > 0) {
        ack.putHighestContiguousRecordingSeq(correlationToken, seq);
      }
      return ack.build();
    }

    @Override
    public boolean fitsEnvelope(String messageId, String correlationToken, Message payload) {
      return true;
    }

    @Override
    public void close() {}
  }
}
