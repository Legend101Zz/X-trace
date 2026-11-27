package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Thread-independent reactive context token and Reactor propagation bridge.
 *
 * <p>Unlike synchronous {@link ThreadLocal} request state, a {@link Token} travels with Reactor
 * {@code Context} / subscriber pipelines across async thread hops, isolates concurrent interleaved
 * requests, cleans up on terminal signals ({@code onComplete}/{@code onError}/{@code cancel}), and
 * emits explicit {@code GAP_REASON_CORRELATION_LOST} signals when reactive context is missing or
 * detached rather than guessing parent links or borrowing unrelated thread state.
 */
public final class ReactorContextBridge {
  /** Key used inside Reactor {@code Context} / {@code ContextView} instances. */
  public static final String CONTEXT_KEY = "dev.xtrace.agent.reactor.context";

  private static final ThreadLocal<Token> ACTIVE_TOKEN = new ThreadLocal<>();
  private static final ThreadLocal<Boolean> READING_CONTEXT = new ThreadLocal<>();
  private static final AtomicInteger TOKEN_SEQ = new AtomicInteger(1);
  private static final AtomicBoolean PROPAGATION_UNAVAILABLE = new AtomicBoolean();
  private static final AtomicBoolean CORRELATION_GAP_OBSERVED = new AtomicBoolean();
  private static final AtomicLong CORRELATION_GAP_COUNT = new AtomicLong();
  private static final AtomicLong DETACHED_CONTEXT_COUNT = new AtomicLong();

  private static final ClassValue<Method[]> CONTEXT_VIEW_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "hasKey", Object.class),
            SpringMvcBridge.publicMethod(type, "get", Object.class),
            SpringMvcBridge.publicMethod(type, "put", Object.class, Object.class)
          };
        }
      };

  private static final ClassValue<Method> SUBSCRIBER_CONTEXT =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return SpringMvcBridge.publicMethod(type, "currentContext");
        }
      };

  private static final ClassValue<Method[]> MONO_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "contextWrite", Function.class),
            SpringMvcBridge.publicMethod(type, "doOnSuccess", Consumer.class),
            SpringMvcBridge.publicMethod(type, "doOnError", Consumer.class),
            SpringMvcBridge.publicMethod(type, "doOnCancel", Runnable.class)
          };
        }
      };

  private ReactorContextBridge() {}

  /** Terminal cleanup callback invoked at most once on completion, error, or cancellation. */
  @FunctionalInterface
  public interface TerminalHandler {
    void onTerminal(Token token, Throwable error, boolean cancelled);
  }

  static final class RecordingSlot {
    final AtomicReference<BootstrapBridge.RecordingState> state = new AtomicReference<>();
    final AtomicBoolean terminated = new AtomicBoolean();
    final TerminalHandler terminalHandler;

    RecordingSlot(BootstrapBridge.RecordingState initialState, TerminalHandler terminalHandler) {
      if (initialState != null) state.set(initialState);
      this.terminalHandler = terminalHandler;
    }

    BootstrapBridge.RecordingState state() {
      return state.get();
    }

    boolean bind(BootstrapBridge.RecordingState recordingState) {
      return state.compareAndSet(null, recordingState);
    }

    boolean isClosed() {
      BootstrapBridge.RecordingState current = state.get();
      return terminated.get() || (current != null && current.closed);
    }
  }

  /** Thread-independent correlation token carried across reactive operators and thread hops. */
  public static final class Token {
    final RecordingSlot slot;
    private final String parentEventId;
    private final String contextId;
    private final boolean detached;

    Token(RecordingSlot slot, String parentEventId, String contextId, boolean detached) {
      this.slot = Objects.requireNonNull(slot, "slot");
      this.parentEventId = parentEventId == null ? "" : parentEventId;
      this.contextId = contextId;
      this.detached = detached;
    }

    public String recordingId() {
      BootstrapBridge.RecordingState state = slot.state();
      return state == null ? "" : state.recordingId;
    }

    public String parentEventId() {
      return parentEventId;
    }

    public String contextId() {
      return contextId;
    }

    public boolean isBound() {
      return slot.state() != null;
    }

    public boolean isActive() {
      BootstrapBridge.RecordingState state = slot.state();
      return !detached && state != null && !state.closed && !slot.terminated.get();
    }

    public boolean isDetached() {
      return detached || slot.isClosed();
    }

    /** Creates an immutable branch-local token with a new parent frame identifier. */
    public Token derive(String childParentEventId) {
      String nextParent =
          childParentEventId == null || childParentEventId.isEmpty()
              ? this.parentEventId
              : childParentEventId;
      return new Token(
          slot, nextParent, nextContextId(recordingId()), detached || slot.isClosed());
    }

    /** Marks this token view as detached without modifying sibling tokens. */
    public Token detach() {
      return new Token(slot, parentEventId, contextId, true);
    }
  }

  /** Scoped thread-local activation that strictly restores prior state on exit. */
  public static final class Scope implements AutoCloseable {
    private final Token previousToken;
    private final BootstrapBridge.ReactiveScope bridgeScope;
    private final AtomicBoolean closed = new AtomicBoolean();

    private Scope(Token previousToken, BootstrapBridge.ReactiveScope bridgeScope) {
      this.previousToken = previousToken;
      this.bridgeScope = bridgeScope;
    }

    @Override
    public void close() {
      if (!closed.compareAndSet(false, true)) return;
      BootstrapBridge.deactivateReactiveScope(bridgeScope);
      if (previousToken == null) ACTIVE_TOKEN.remove();
      else ACTIVE_TOKEN.set(previousToken);
    }
  }

  static Token createPendingToken(TerminalHandler terminalHandler) {
    RecordingSlot slot = new RecordingSlot(null, terminalHandler);
    return new Token(slot, "", nextContextId("pending"), false);
  }

  /** Opens a reactive token bound to a freshly started WebFlux recording. */
  static Token openToken(
      BootstrapBridge.RecordingState state, String parentEventId, TerminalHandler terminalHandler) {
    Objects.requireNonNull(state, "state");
    RecordingSlot slot = new RecordingSlot(state, terminalHandler);
    String parent = parentEventId == null || parentEventId.isEmpty()
        ? state.requestEventId : parentEventId;
    return new Token(slot, parent, nextContextId(state.recordingId), false);
  }

  /** Opens an isolated reactive token for direct reactive recording roots (useful in tests/hooks). */
  public static Token startRoot(String method, String route, TerminalHandler terminalHandler) {
    BootstrapBridge.RecordingState state =
        BootstrapBridge.startReactiveRecording(method, route, System.nanoTime(), false);
    if (state == null) return null;
    return openToken(state, state.requestEventId, terminalHandler);
  }

  private static String nextContextId(String prefix) {
    return (prefix == null || prefix.isEmpty() ? "ctx" : prefix)
        + ":ctx:" + TOKEN_SEQ.getAndIncrement();
  }

  /** Returns the token temporarily active on the current thread, or null when idle. */
  public static Token currentToken() {
    return ACTIVE_TOKEN.get();
  }

  /**
   * Temporarily binds {@code token} for the current callback on this thread.
   *
   * <p>If {@code token} is {@code null}, returns {@code null} without fabricating context or
   * attaching to unrelated thread state. If {@code token} is detached/closed, suspends any
   * unrelated active request on this thread and records a detached-context gap so zombie signals
   * cannot bleed into concurrent requests.
   */
  public static Scope enterScope(Token token) {
    if (token == null) return null;
    Token previous = ACTIVE_TOKEN.get();
    if (token.isDetached()) {
      DETACHED_CONTEXT_COUNT.incrementAndGet();
      CORRELATION_GAP_OBSERVED.set(true);
      ACTIVE_TOKEN.remove();
      BootstrapBridge.ReactiveScope suspended = BootstrapBridge.suspendActiveScope();
      return new Scope(previous, suspended);
    }
    BootstrapBridge.RecordingState state = token.slot.state();
    ACTIVE_TOKEN.set(token);
    if (state == null) {
      return new Scope(previous, null);
    }
    BootstrapBridge.ReactiveScope bridgeScope =
        BootstrapBridge.activateReactiveScope(state, token.parentEventId);
    return new Scope(previous, bridgeScope);
  }

  /** Convenience entry for ByteBuddy {@code CoreSubscriber} / {@code CorePublisher} advice. */
  public static Scope subscriberEnter(Object subscriber) {
    if (subscriber == null || !BootstrapBridge.hasBridgeSink()) return null;
    Token token = fromSubscriber(subscriber);
    return enterScope(token);
  }

  public static void exitScope(Object scopeObj) {
    if (scopeObj instanceof Scope scope) scope.close();
  }

  /** Records an async hop event and returns a derived token parented to that link. */
  public static Token onAsyncLink(Token token, String symbol) {
    if (token == null) {
      reportCorrelationGap(null, symbol);
      return null;
    }
    if (token.isDetached()) {
      reportDetachedContext(token);
      return token;
    }
    BootstrapBridge.RecordingState state = token.slot.state();
    if (state == null) return token;
    String linkSymbol = symbol == null || symbol.isEmpty() ? "reactor.async_link" : symbol;
    String eventId = BootstrapBridge.emitReactiveEvent(
        state, token.parentEventId, BridgeEventKind.ASYNC_LINK, linkSymbol, 0);
    if (eventId == null) {
      reportDetachedContext(token);
      return token.detach();
    }
    if (eventId.isEmpty()) return token;
    return token.derive(eventId);
  }

  /** Captures the current thread's active reactive token for a scheduled {@link Runnable}. */
  public static Runnable wrapRunnable(Runnable task) {
    if (task == null || task instanceof ContextRunnable) return task;
    Token token = ACTIVE_TOKEN.get();
    if (token == null) return task;
    return new ContextRunnable(task, token);
  }

  private static final class ContextRunnable implements Runnable {
    private final Runnable delegate;
    private final Token token;

    ContextRunnable(Runnable delegate, Token token) {
      this.delegate = delegate;
      this.token = token;
    }

    @Override
    public void run() {
      try (Scope ignored = enterScope(token)) {
        delegate.run();
      }
    }
  }

  /** Reads a {@link Token} from a Reactor {@code ContextView} / {@code Context} via reflection. */
  public static Token fromReactorContext(Object contextView) {
    if (contextView == null) return null;
    try {
      Method[] methods = CONTEXT_VIEW_METHODS.get(contextView.getClass());
      Method hasKey = methods[0];
      Method get = methods[1];
      if (hasKey == null || get == null) return null;
      Object present = hasKey.invoke(contextView, CONTEXT_KEY);
      if (!Boolean.TRUE.equals(present)) return null;
      Object value = get.invoke(contextView, CONTEXT_KEY);
      return value instanceof Token token ? token : null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      CORRELATION_GAP_COUNT.incrementAndGet();
      CORRELATION_GAP_OBSERVED.set(true);
      return null;
    }
  }

  /** Writes {@code token} into a Reactor {@code Context} and returns the updated {@code Context}. */
  public static Object attachToReactorContext(Object context, Token token) {
    if (context == null || token == null) return context;
    try {
      Method put = CONTEXT_VIEW_METHODS.get(context.getClass())[2];
      if (put == null) {
        reportCorrelationGap(token, "context_put_unavailable");
        return context;
      }
      Object updated = put.invoke(context, CONTEXT_KEY, token);
      return updated != null ? updated : context;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      reportCorrelationGap(token, "context_put_failed");
      return context;
    }
  }

  /** Extracts {@link Token} from a {@code CoreSubscriber#currentContext()} reflectively. */
  public static Token fromSubscriber(Object subscriber) {
    if (subscriber == null || Boolean.TRUE.equals(READING_CONTEXT.get())) return null;
    READING_CONTEXT.set(Boolean.TRUE);
    try {
      Method currentContext = SUBSCRIBER_CONTEXT.get(subscriber.getClass());
      if (currentContext == null) return null;
      return fromReactorContext(currentContext.invoke(subscriber));
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      CORRELATION_GAP_COUNT.incrementAndGet();
      CORRELATION_GAP_OBSERVED.set(true);
      return null;
    } finally {
      READING_CONTEXT.remove();
    }
  }

  /**
   * Attaches {@code token} into Reactor {@code Context} and optional terminal/success hooks on a
   * Reactor {@code Mono}. Returns {@code null} if the {@code Mono} does not expose the expected
   * reactive signatures so callers fail closed without leaving unclosed recordings.
   */
  public static Object wrapMono(
      Object mono, Token token, TerminalHandler onTerminal, Consumer<Object> onNextValue) {
    if (mono == null) return null;
    try {
      Method[] methods = MONO_METHODS.get(mono.getClass());
      Method contextWrite = methods[0];
      Method doOnSuccess = methods[1];
      Method doOnError = methods[2];
      Method doOnCancel = methods[3];
      if (contextWrite == null) return null;
      Object wrapped = mono;
      if (onTerminal != null || onNextValue != null) {
        if (doOnSuccess == null || doOnError == null || doOnCancel == null) return null;
        AtomicBoolean done = new AtomicBoolean();
        Consumer<Object> successHook = value -> {
          if (onNextValue != null) {
            try {
              onNextValue.accept(value);
            } catch (RuntimeException ignored) {
              // Observation failure must never alter reactive signal values.
            }
          }
          if (onTerminal != null && done.compareAndSet(false, true)) {
            invokeTerminal(onTerminal, token, null, false);
          }
        };
        Consumer<Throwable> errorHook = error -> {
          if (onTerminal != null && done.compareAndSet(false, true)) {
            invokeTerminal(onTerminal, token, error, false);
          }
        };
        Runnable cancelHook = () -> {
          if (onTerminal != null && done.compareAndSet(false, true)) {
            invokeTerminal(onTerminal, token, null, true);
          }
        };
        wrapped = doOnSuccess.invoke(wrapped, successHook);
        wrapped = doOnError.invoke(wrapped, errorHook);
        wrapped = doOnCancel.invoke(wrapped, cancelHook);
      }
      if (token != null) {
        Function<Object, Object> modifier = ctx -> attachToReactorContext(ctx, token);
        wrapped = contextWrite.invoke(wrapped, modifier);
      }
      return wrapped;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  private static void invokeTerminal(
      TerminalHandler handler, Token token, Throwable error, boolean cancelled) {
    try {
      handler.onTerminal(token, error, cancelled);
    } catch (RuntimeException | LinkageError ignored) {
      // Terminal capture cleanup never breaks reactive signal delivery.
    }
  }

  /** Signals normal completion ({@code onComplete}) and runs cleanup at most once. */
  public static boolean signalComplete(Token token) {
    return finishTerminal(token, null, false);
  }

  /** Signals reactive error ({@code onError}) and runs cleanup at most once. */
  public static boolean signalError(Token token, Throwable error) {
    return finishTerminal(token, error, false);
  }

  /** Signals reactive cancellation ({@code cancel}) and runs cleanup at most once. */
  public static boolean signalCancel(Token token) {
    return finishTerminal(token, null, true);
  }

  private static boolean finishTerminal(Token token, Throwable error, boolean cancelled) {
    if (token == null || !token.slot.terminated.compareAndSet(false, true)) return false;
    TerminalHandler handler = token.slot.terminalHandler;
    if (handler != null) {
      invokeTerminal(handler, token, error, cancelled);
    } else {
      BootstrapBridge.RecordingState state = token.slot.state();
      if (state != null && !state.closed) {
        BootstrapBridge.finishReactiveRecording(state, 0, error, error == null, cancelled);
      }
    }
    return true;
  }

  /**
   * Signals an explicit correlation gap ({@code GAP_REASON_CORRELATION_LOST}). Emits into the
   * recording when open, and always increments bounded process diagnostics.
   */
  public static boolean reportCorrelationGap(Token token, String reason) {
    CORRELATION_GAP_COUNT.incrementAndGet();
    CORRELATION_GAP_OBSERVED.set(true);
    BootstrapBridge.RecordingState state = token != null ? token.slot.state() : null;
    String parent = token != null ? token.parentEventId : "";
    if (state == null) {
      state = BootstrapBridge.currentReactiveState();
      if (state != null && parent.isEmpty()) parent = BootstrapBridge.currentReactiveParent();
    }
    if (state == null || state.closed) return false;
    return BootstrapBridge.emitCorrelationLostGap(state, parent, 1);
  }

  /** Records a detached or post-terminal reactive signal without bleeding or reopening closed state. */
  public static boolean reportDetachedContext(Token token) {
    DETACHED_CONTEXT_COUNT.incrementAndGet();
    CORRELATION_GAP_COUNT.incrementAndGet();
    CORRELATION_GAP_OBSERVED.set(true);
    if (token == null) return false;
    BootstrapBridge.RecordingState state = token.slot.state();
    if (state == null || state.closed) return false;
    return BootstrapBridge.emitCorrelationLostGap(state, token.parentEventId, 1);
  }

  /** Marks Reactor context propagation instrumentation as unavailable in this JVM. */
  public static void reportPropagationUnavailable() {
    PROPAGATION_UNAVAILABLE.set(true);
  }

  public static boolean isPropagationUnavailable() {
    return PROPAGATION_UNAVAILABLE.get();
  }

  public static boolean takePropagationUnavailable() {
    return PROPAGATION_UNAVAILABLE.getAndSet(false);
  }

  public static boolean takeCorrelationGapObserved() {
    return CORRELATION_GAP_OBSERVED.getAndSet(false);
  }

  public static long correlationGapCount() {
    return CORRELATION_GAP_COUNT.get();
  }

  public static long detachedContextCount() {
    return DETACHED_CONTEXT_COUNT.get();
  }

  static void resetForTest() {
    ACTIVE_TOKEN.remove();
    PROPAGATION_UNAVAILABLE.set(false);
    CORRELATION_GAP_OBSERVED.set(false);
    CORRELATION_GAP_COUNT.set(0);
    DETACHED_CONTEXT_COUNT.set(0);
  }
}
