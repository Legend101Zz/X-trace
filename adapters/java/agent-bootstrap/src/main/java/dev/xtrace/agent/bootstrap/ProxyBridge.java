package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicReference;

/** Bootstrap-visible handoff for JDK proxy boundaries; never retains call values. */
public final class ProxyBridge {
  private static final AtomicReference<Sink> SINK = new AtomicReference<>();

  private ProxyBridge() {}

  public static boolean install(Sink sink) {
    return SINK.compareAndSet(null, java.util.Objects.requireNonNull(sink));
  }

  public static void disable(Sink sink) {
    SINK.compareAndSet(sink, null);
  }

  public static Call enter(Object proxy, Method method, Object[] arguments) {
    Sink sink = SINK.get();
    if (sink == null || !BootstrapBridge.hasContext()) return null;
    try {
      Call call = sink.resolve(proxy, method);
      if (call == null) return null;
      return BootstrapBridge.proxyFrame(call, arguments, null, null, true) ? call : null;
    } catch (Throwable ignored) {
      return null; // Probe failure cannot affect the handler.
    }
  }

  public static void exit(Call call, Object result, Throwable thrown) {
    if (call == null) return;
    try {
      BootstrapBridge.proxyFrame(call, null, result, thrown, false);
    } catch (Throwable ignored) {
      // Probe failure cannot replace a result or exception.
    }
  }

  /** Reusable boundary metadata; never retains arguments, results or request identity. */
  public record Call(EventSink sink, Method method, String symbol) {}

  /** Resolves and caches boundary metadata once per proxy class/method. */
  public interface Sink {
    Call resolve(Object proxy, Method method);
  }

  /** Sanitizes authorized values synchronously before offering bounded runtime events. */
  @FunctionalInterface
  public interface EventSink {
    boolean offer(String recordingId, String eventId, String parentId, int kind, String symbol,
        long monotonicNs, Method method, Object[] arguments, Object result, Throwable thrown);
  }
}
