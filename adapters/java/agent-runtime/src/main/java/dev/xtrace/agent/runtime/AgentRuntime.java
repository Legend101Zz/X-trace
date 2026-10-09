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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/** Private fixture runtime loaded outside the target application's classloader. */
public final class AgentRuntime {
  private static final int MAX_MANIFEST_BYTES = 64 * 1024;
  private static final AtomicReference<RuntimeHandle> ACTIVE = new AtomicReference<>();

  private AgentRuntime() {}

  /** Validates the complete bootstrap and bounded attach capability before agent mutation. */
  public static byte[] prepareBootstrap(
      String bootstrapPath, Instrumentation instrumentation, boolean attach)
      throws ClientException {
    Bootstrap bootstrap = BootstrapReader.read(Path.of(bootstrapPath));
    try {
      if (attach) FixtureInstrumentation.validateAttach(instrumentation);
      return identityDigest(bootstrap);
    } finally {
      bootstrap.close();
    }
  }

  /** Returns an authenticated-session identity for idempotent agentmain duplicate checks. */
  public static byte[] bootstrapIdentity(String bootstrapPath) throws ClientException {
    Bootstrap bootstrap = BootstrapReader.read(Path.of(bootstrapPath));
    try {
      return identityDigest(bootstrap);
    } finally {
      bootstrap.close();
    }
  }

  /** Connects the writer and installs exact fixture transformations without blocking requests. */
  public static byte[] start(
      String bootstrapPath,
      Instrumentation instrumentation,
      boolean attach,
      byte[] expectedIdentity)
      throws StartFailure {
    if (ACTIVE.get() != null) {
      throw new StartFailure(true, "XTR-JAVA-AGENT", "agent runtime is already active");
    }
    byte[] manifest = null;
    byte[] identity = null;
    Bootstrap bootstrap = null;
    XtpSession session = null;
    RecordingWriter writer = null;
    RuntimeBridgeSink sink = null;
    LineProbeBridgeSink lineSink = null;
    boolean permanent = false;
    try {
      if (attach) FixtureInstrumentation.validateAttach(instrumentation);
      bootstrap = BootstrapReader.read(Path.of(bootstrapPath));
      // capture.json sits beside the bootstrap and may be removed once the session is open, so it
      // is read together with the bootstrap; absent or invalid means the default scope.
      CaptureConfig config = CaptureConfig.readBeside(Path.of(bootstrapPath));
      identity = identityDigest(bootstrap);
      if (!MessageDigest.isEqual(expectedIdentity, identity)) {
        throw new ClientException(
            "XTR-JAVA-ATTACH-BOOTSTRAP-CHANGED", "bootstrap identity changed after preflight");
      }
      manifest = resource("/agent-manifest.json");
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
      BoundedEventQueue queue = new BoundedEventQueue(8192, 2L * 1024 * 1024);
      sink = new RuntimeBridgeSink(queue);
      sink.useScope(config.scope());
      writer = new RecordingWriter(session, queue, sink);
      permanent = true;
      // Line probes and value reads exist only in effective focused mode (CONTRACTS section 4:
      // the standard line budget is 0). The daemon honours the focused claim only when armed.
      FixtureInstrumentation.LineProbes lineProbes = null;
      if (config.focused()) {
        lineProbes =
            new FixtureInstrumentation.LineProbes(
                new dev.xtrace.agent.runtime.line.SiteRegistry());
        lineSink = new LineProbeBridgeSink(sink, lineProbes.registry());
        writer.capturePolicy("xtrace.focused.v1");
        writer.untransformedCount(lineProbes::skippedCount);
      }
      FixtureInstrumentation.install(
          instrumentation, writer::stopIncomplete, attach, config.scope(), lineProbes);
      if (lineSink != null && !BootstrapBridge.installLineSink(lineSink)) {
        throw new ClientException("XTR-JAVA-AGENT", "line sink is already active");
      }
      if (writer.isStopping()) {
        throw new ClientException("XTR-JAVA-INSTRUMENTATION", "fixture instrumentation failed");
      }
      if (!BootstrapBridge.install(sink)) {
        throw new ClientException("XTR-JAVA-AGENT", "bootstrap bridge is already active");
      }
      RuntimeHandle handle = new RuntimeHandle(writer, sink, lineSink);
      if (!ACTIVE.compareAndSet(null, handle)) {
        BootstrapBridge.disable(sink);
        throw new ClientException("XTR-JAVA-AGENT", "agent runtime activation raced");
      }
      writer.start();
      Runtime.getRuntime().addShutdownHook(new Thread(handle::close, "xtrace-java-shutdown"));
      byte[] result = identity.clone();
      session = null;
      writer = null;
      sink = null;
      lineSink = null;
      return result;
    } catch (ClientException error) {
      throw new StartFailure(permanent, error.code(), error.getMessage(), error);
    } catch (RuntimeException | LinkageError error) {
      throw new StartFailure(
          permanent, "XTR-JAVA-AGENT", "agent initialization failed safely", error);
    } finally {
      if (manifest != null) Arrays.fill(manifest, (byte) 0);
      if (identity != null) Arrays.fill(identity, (byte) 0);
      if (sink != null) BootstrapBridge.disable(sink);
      if (lineSink != null) BootstrapBridge.disableLineSink(lineSink);
      if (writer != null) writer.close();
      else if (session != null) closeSession(session);
      if (bootstrap != null) bootstrap.close();
    }
  }

  private static byte[] identityDigest(Bootstrap bootstrap) throws ClientException {
    final MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException error) {
      throw new ClientException("XTR-JAVA-AGENT", "session identity hashing is unavailable", error);
    }
    updateDigest(digest, bootstrap.host());
    updateDigest(digest, Integer.toString(bootstrap.port()));
    updateDigest(digest, bootstrap.certificatePin());
    updateDigest(digest, bootstrap.runtimeSessionId().toString());
    updateDigest(digest, bootstrap.projectId().toString());
    updateDigest(digest, bootstrap.repositoryFingerprint());
    updateDigest(digest, Integer.toString(bootstrap.protocolMajor()));
    updateDigest(digest, Integer.toString(bootstrap.protocolMinor()));
    byte[] secret = bootstrap.copySessionSecret();
    try {
      digest.update(secret);
      return digest.digest();
    } finally {
      Arrays.fill(secret, (byte) 0);
    }
  }

  private static void updateDigest(MessageDigest digest, String value) {
    byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
    digest.update(encoded);
    digest.update((byte) 0);
    Arrays.fill(encoded, (byte) 0);
  }

  /** Safe failure metadata used to distinguish retryable setup from partial instrumentation. */
  public static final class StartFailure extends Exception {
    private final boolean permanent;
    private final String code;

    private StartFailure(boolean permanent, String code, String message) {
      super(message);
      this.permanent = permanent;
      this.code = code;
    }

    private StartFailure(boolean permanent, String code, String message, Throwable cause) {
      super(message, cause);
      this.permanent = permanent;
      this.code = code;
    }

    public boolean permanent() {
      return permanent;
    }

    public String code() {
      return code;
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
    private final LineProbeBridgeSink lineSink;
    private final java.util.concurrent.atomic.AtomicBoolean closed =
        new java.util.concurrent.atomic.AtomicBoolean();

    private RuntimeHandle(
        RecordingWriter writer, RuntimeBridgeSink sink, LineProbeBridgeSink lineSink) {
      this.writer = writer;
      this.sink = sink;
      this.lineSink = lineSink;
    }

    private void close() {
      if (!closed.compareAndSet(false, true)) return;
      if (lineSink != null) BootstrapBridge.disableLineSink(lineSink);
      writer.close();
      BootstrapBridge.disable(sink);
      ACTIVE.compareAndSet(this, null);
    }
  }
}
