package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.lang.instrument.Instrumentation;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.utility.JavaModule;

/** Observes only standard servlet APIs; no container implementation seam or servlet dependency. */
final class ServletBoundaryInstrumentation {
  private ServletBoundaryInstrumentation() {}

  static ElementMatcher.Junction<MethodDescription> boundaryMethods(String api) {
    return isMethod().and(not(isAbstract()))
        .and(takesArgument(0, named(api + ".ServletRequest")))
        .and(takesArgument(1, named(api + ".ServletResponse")))
        .and(named("service").and(takesArguments(2))
            .or(named("doFilter").and(takesArguments(3))
                .and(takesArgument(2, named(api + ".FilterChain")))));
  }

  static ElementMatcher.Junction<MethodDescription> sendErrorMethods() {
    return isMethod().and(not(isAbstract())).and(named("sendError"))
        .and(takesArgument(0, int.class))
        .and(takesArguments(1).or(takesArguments(2).and(takesArgument(1, String.class))));
  }

  static void install(Instrumentation instrumentation, Runnable onFailure, boolean attach) {
    FailureListener listener = new FailureListener(onFailure);
    AgentBuilder builder = new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(attach ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
            : AgentBuilder.RedefinitionStrategy.DISABLED)
        .ignore(nameStartsWith("java.").or(nameStartsWith("jdk."))
            .or(nameStartsWith("sun.")).or(nameStartsWith("dev.xtrace.agent."))
            .or(nameStartsWith("net.bytebuddy.")))
        .with(listener);
    for (String api : new String[] {"jakarta.servlet", "javax.servlet"}) {
      builder = builder
          .type(listener.selected(not(isInterface()).and(hasSuperType(named(api + ".Filter")
              .or(named(api + ".Servlet"))))))
          .transform((target, type, loader, module, domain) ->
              target.visit(Advice.to(BoundaryAdvice.class).on(boundaryMethods(api))))
          .type(listener.selected(not(isInterface())
              .and(hasSuperType(named(api + ".http.HttpServletResponse")))))
          .transform((target, type, loader, module, domain) ->
              target.visit(Advice.to(SendErrorAdvice.class).on(sendErrorMethods())));
    }
    builder.installOn(instrumentation);
  }

  static final class FailureListener extends AgentBuilder.Listener.Adapter {
    private record Candidate(String name, ClassLoader loader) {}

    private final Runnable onFailure;
    private final Set<Candidate> selected = ConcurrentHashMap.newKeySet();

    FailureListener(Runnable onFailure) {
      this.onFailure = java.util.Objects.requireNonNull(onFailure);
    }

    AgentBuilder.RawMatcher selected(ElementMatcher<? super TypeDescription> matcher) {
      return (type, loader, module, redefined, domain) -> {
        // A failed hierarchy walk is not evidence that this is a servlet boundary.
        if (!matcher.matches(type)) return false;
        selected.add(new Candidate(type.getName(), loader));
        return true;
      };
    }

    @Override
    public void onError(String name, ClassLoader loader, JavaModule module,
        boolean loaded, Throwable failure) {
      if (!selected.remove(new Candidate(name, loader))) return;
      // A missing outer probe must never leave an inner status looking authoritative.
      try {
        onFailure.run();
      } catch (RuntimeException | LinkageError ignored) {
        // Capture failure must not escape into application class loading.
      }
    }

    @Override
    public void onComplete(String name, ClassLoader loader, JavaModule module, boolean loaded) {
      // Selection belongs to this transformation attempt, not a later load or retransformation.
      selected.remove(new Candidate(name, loader));
    }
  }

  public static final class BoundaryAdvice {
    private BoundaryAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter() {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.servletEnter();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Argument(0) Object request,
        @Advice.Argument(1) Object response, @Advice.Thrown Throwable thrown) {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.servletEnd(request, response, thrown);
    }
  }

  public static final class SendErrorAdvice {
    private SendErrorAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter() {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.servletSendError();
    }
  }
}
