package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isBridge;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import dev.xtrace.agent.bootstrap.ProcessLinkageBridge;
import java.lang.instrument.Instrumentation;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.utility.JavaModule;

/**
 * Installs ByteBuddy advice on {@code java.lang.ProcessBuilder.start()} to emit bounded
 * process-linkage gaps or verified opt-in session links without reading raw arguments or
 * environment maps.
 */
final class ProcessLinkageInstrumentation {
  static final String PROCESS_BUILDER = "java.lang.ProcessBuilder";

  private static final AtomicBoolean DEGRADED = new AtomicBoolean();

  private ProcessLinkageInstrumentation() {}

  static ElementMatcher.Junction<MethodDescription> processStartMethods() {
    return isMethod()
        .and(isPublic())
        .and(not(isStatic()))
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(isSynthetic()))
        .and(not(isBridge()))
        .and(named("start"))
        .and(takesArguments(0));
  }

  static void install(Instrumentation instrumentation, Runnable onLimitation, boolean attach) {
    if (instrumentation == null || !instrumentation.isRetransformClassesSupported()) {
      markDegraded(onLimitation);
      return;
    }
    try {
      if (!instrumentation.isModifiableClass(ProcessBuilder.class)) {
        markDegraded(onLimitation);
        return;
      }
    } catch (RuntimeException | LinkageError ignored) {
      markDegraded(onLimitation);
      return;
    }

    FailureListener listener = new FailureListener(onLimitation);
    configure(
            new AgentBuilder.Default()
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .ignore(
                    nameStartsWith("dev.xtrace.agent.")
                        .or(nameStartsWith("net.bytebuddy."))
                        .or(not(named(PROCESS_BUILDER))))
                .assureReadEdgeFromAndTo(instrumentation, ProcessLinkageBridge.class)
                .with(listener),
            listener,
            named(PROCESS_BUILDER))
        .installOn(instrumentation);
  }

  /** Builds the ByteBuddy configuration; {@code typeMatcher} override is test-only. */
  static AgentBuilder configure(
      AgentBuilder builder,
      FailureListener listener,
      ElementMatcher<? super TypeDescription> typeMatcher) {
    AgentBuilder.RawMatcher guarded =
        listener.selected(
            (type, loader, module, redefined, domain) ->
                !type.isInterface() && !type.isEnum() && typeMatcher.matches(type));
    return builder
        .type(guarded)
        .transform(
            (target, type, loader, module, domain) ->
                target.visit(Advice.to(ProcessStartAdvice.class).on(processStartMethods())));
  }

  static void markDegraded(Runnable onLimitation) {
    DEGRADED.set(true);
    ProcessLinkageBridge.reportInstrumentationUnavailable();
    if (onLimitation != null) {
      try {
        onLimitation.run();
      } catch (Throwable ignored) {
        // Limitation reporting never propagates into agent startup.
      }
    }
  }

  static void reportCoverageAtShutdown() {
    if (DEGRADED.getAndSet(false) || ProcessLinkageBridge.takeInstrumentationUnavailable()) {
      System.err.println(
          "{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
              + "\"message\":\"ProcessBuilder linkage instrumentation degraded during JVM execution\"}");
    }
  }

  static void resetForTest() {
    DEGRADED.set(false);
  }

  static final class FailureListener extends AgentBuilder.Listener.Adapter {
    private record Candidate(String name, ClassLoader loader) {
      @Override
      public boolean equals(Object other) {
        return other instanceof Candidate c
            && name.equals(c.name)
            && loader == c.loader;
      }

      @Override
      public int hashCode() {
        return 31 * name.hashCode() + System.identityHashCode(loader);
      }
    }

    private final Runnable onLimitation;
    private final ConcurrentHashMap<Candidate, Boolean> selected = new ConcurrentHashMap<>();

    FailureListener(Runnable onLimitation) {
      this.onLimitation = onLimitation;
    }

    AgentBuilder.RawMatcher selected(AgentBuilder.RawMatcher delegate) {
      return (type, loader, module, redefined, domain) -> {
        if (!delegate.matches(type, loader, module, redefined, domain)) return false;
        selected.put(new Candidate(type.getName(), loader), Boolean.TRUE);
        return true;
      };
    }

    @Override
    public void onError(
        String name, ClassLoader loader, JavaModule module, boolean loaded, Throwable error) {
      if (selected.remove(new Candidate(name, loader)) == null) return;
      markDegraded(onLimitation);
    }

    @Override
    public void onComplete(String name, ClassLoader loader, JavaModule module, boolean loaded) {
      selected.remove(new Candidate(name, loader));
    }
  }

  /**
   * Bootstrap-safe advice inlined into {@code java.lang.ProcessBuilder.start()}.
   * References only bootstrap-visible {@link ProcessLinkageBridge}.
   */
  public static final class ProcessStartAdvice {
    private ProcessStartAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter() {
      ProcessLinkageBridge.onProcessBuilderStart();
    }
  }
}
