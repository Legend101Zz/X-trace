package dev.xtrace.agent.runtime;

import dev.xtrace.adapter.Bootstrap;
import dev.xtrace.adapter.BootstrapReader;
import dev.xtrace.adapter.ClientException;
import dev.xtrace.adapter.XtpSession;
import dev.xtrace.agent.bootstrap.BootstrapBridge;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/** Private fixture runtime loaded outside the target application's classloader. */
public final class AgentRuntime {
  private static final int MAX_MANIFEST_BYTES = 64 * 1024;
  private static final AtomicReference<RuntimeHandle> ACTIVE = new AtomicReference<>();

  private AgentRuntime() {}

  /** Connects the writer, installs exact fixture transformations, and returns without blocking. */
  public static void start(String bootstrapPath, Instrumentation instrumentation, boolean attach)
      throws ClientException {
    if (ACTIVE.get() != null) {
      throw new ClientException("XTR-JAVA-AGENT", "agent runtime is already active");
    }
    byte[] manifest = resource("/agent-manifest.json");
    Bootstrap bootstrap = null;
    XtpSession session = null;
    RecordingWriter writer = null;
    RuntimeBridgeSink sink = null;
    try {
      if (attach) FixtureInstrumentation.validateAttach(instrumentation);
      bootstrap = BootstrapReader.read(Path.of(bootstrapPath));
      session =
          XtpSession.open(
              bootstrap,
              manifest,
              new XtpSession.ClientIdentity(
                  attach ? "xtrace-java-attach-fixture" : "xtrace-java-premain-fixture",
                  "0.1.0",
                  "java",
                  "openjdk",
                  System.getProperty("java.version"),
                  ProcessHandle.current().pid(),
                  System.nanoTime()));
      bootstrap.close();
      bootstrap = null;
      BoundedEventQueue queue = new BoundedEventQueue(1024, 256 * 1024L);
      sink = new RuntimeBridgeSink(queue);
      writer = new RecordingWriter(session, queue, sink);
      FixtureInstrumentation.install(instrumentation, writer::stopIncomplete, attach);
      if (writer.isStopping()) {
        throw new ClientException("XTR-JAVA-INSTRUMENTATION", "fixture instrumentation failed");
      }
      if (!BootstrapBridge.install(sink)) {
        throw new ClientException("XTR-JAVA-AGENT", "bootstrap bridge is already active");
      }
      RuntimeHandle handle = new RuntimeHandle(writer, sink);
      if (!ACTIVE.compareAndSet(null, handle)) {
        BootstrapBridge.disable(sink);
        throw new ClientException("XTR-JAVA-AGENT", "agent runtime activation raced");
      }
      writer.start();
      Runtime.getRuntime().addShutdownHook(new Thread(handle::close, "xtrace-java-shutdown"));
      session = null;
      writer = null;
      sink = null;
    } finally {
      Arrays.fill(manifest, (byte) 0);
      if (sink != null) BootstrapBridge.disable(sink);
      if (writer != null) writer.close();
      else if (session != null) closeSession(session);
      if (bootstrap != null) bootstrap.close();
    }
  }

  private static byte[] resource(String name) throws ClientException {
    try (InputStream input = AgentRuntime.class.getResourceAsStream(name)) {
      if (input == null) throw new ClientException("XTR-JAVA-MANIFEST", "agent manifest is missing");
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        if (output.size() > MAX_MANIFEST_BYTES - count) {
          throw new ClientException("XTR-JAVA-MANIFEST", "agent manifest is too large");
        }
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-MANIFEST", "agent manifest could not be read", error);
    }
  }

  private static void closeSession(XtpSession session) {
    try {
      session.close();
    } catch (ClientException ignored) {
      // Startup failure remains fail-open and exposes no bootstrap details.
    }
  }

  private static final class RuntimeHandle {
    private final RecordingWriter writer;
    private final RuntimeBridgeSink sink;
    private final java.util.concurrent.atomic.AtomicBoolean closed =
        new java.util.concurrent.atomic.AtomicBoolean();

    private RuntimeHandle(RecordingWriter writer, RuntimeBridgeSink sink) {
      this.writer = writer;
      this.sink = sink;
    }

    private void close() {
      if (!closed.compareAndSet(false, true)) return;
      writer.close();
      BootstrapBridge.disable(sink);
      ACTIVE.compareAndSet(this, null);
    }
  }
}
