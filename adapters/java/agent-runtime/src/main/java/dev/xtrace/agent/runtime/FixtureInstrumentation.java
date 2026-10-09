package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isBridge;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.nameMatches;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.adapter.ClientException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.utility.JavaModule;

/**
 * Installs the Spring MVC request root, method boundary probes on in-scope application classes,
 * and the coarse H2 execute boundary. Attach validation stays fixture-bound until generalized
 * attach lands.
 */
final class FixtureInstrumentation {
  static final String SPRING_ADAPTER =
      "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter";
  static final String DISPATCHER = "org.springframework.web.servlet.DispatcherServlet";
  static final String H2_STATEMENT = "org.h2.jdbc.JdbcPreparedStatement";
  static final String CONTROLLER = "dev.xtrace.fixture.OrderController";
  static final String SERVICE = "dev.xtrace.fixture.OrderService";
  static final String REPOSITORY = "dev.xtrace.fixture.OrderRepository";
  private static final Set<String> APPLICATION_TYPES = Set.of(CONTROLLER, SERVICE, REPOSITORY);
  private static final int MAX_ATTACH_RETRANSFORM_CLASSES = 16;
  private static final AtomicBoolean INSTALLED = new AtomicBoolean();

  private FixtureInstrumentation() {}

  static void validateAttach(Instrumentation instrumentation) throws ClientException {
    if (!instrumentation.isRetransformClassesSupported()) {
      throw new ClientException(
          "XTR-JAVA-ATTACH-UNAVAILABLE", "target JVM does not support class retransformation");
    }
    int candidateCount = 0;
    for (Class<?> candidate : instrumentation.getAllLoadedClasses()) {
      if (!isExplicitTarget(candidate.getName())) continue;
      candidateCount++;
      if (candidateCount > MAX_ATTACH_RETRANSFORM_CLASSES) {
        throw new ClientException(
            "XTR-JAVA-ATTACH-UNAVAILABLE", "loaded fixture class count exceeds the attach bound");
      }
      if (!instrumentation.isModifiableClass(candidate)) {
        throw new ClientException(
            "XTR-JAVA-ATTACH-UNAVAILABLE", "a loaded fixture class cannot be retransformed");
      }
    }
    if (candidateCount == 0) {
      throw new ClientException(
          "XTR-JAVA-ATTACH-UNAVAILABLE", "no supported Spring fixture classes are loaded");
    }
  }

  static void install(Instrumentation instrumentation, Runnable onFailure, boolean attach) {
    install(instrumentation, onFailure, attach, ApplicationScope.defaultScope());
  }

  static void install(
      Instrumentation instrumentation,
      Runnable onFailure,
      boolean attach,
      ApplicationScope scope) {
    if (!INSTALLED.compareAndSet(false, true)) {
      throw new IllegalStateException("fixture instrumentation is already installed");
    }
    AgentBuilder builder =
        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(
                attach
                    ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
                    : AgentBuilder.RedefinitionStrategy.DISABLED)
            .with(new SafeListener(onFailure))
            .ignore(
                named("dev.xtrace.agent.bootstrap.XTraceAgent")
                    .or(named("dev.xtrace.agent.bootstrap.BootstrapBridge"))
                    .or(named("dev.xtrace.agent.runtime.AgentRuntime")));

    instrumentation.addTransformer(new ClassFileTransformer() {
      @Override
      public byte[] transform(
          ClassLoader loader,
          String className,
          Class<?> classBeingRedefined,
          ProtectionDomain protectionDomain,
          byte[] classfileBuffer) {
        if (isApplicationType(className)) {
          // For retransformation the JVM supplies this transformer's input bytes again. Observe
          // this callback buffer before Byte Buddy's capable transformer adds instrumentation;
          // it is not a hash of the final transformed class bytes.
          SourceAttestation.observe(loader, className, classfileBuffer);
        }
        if (className != null
            && scope.isApplication(className.replace('/', '.'), protectionDomain)) {
          SourceIdentity.observe(
              loader,
              className,
              classfileBuffer,
              scope.sourceRoots(),
              java.nio.file.Path.of(System.getProperty("user.dir", ".")));
        }
        return null;
      }
    }, attach);

    builder =
        builder
            .type(named(SPRING_ADAPTER))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(SpringRequestAdvice.class)
                            .on(
                                isMethod()
                                    .and(named("handleInternal"))
                                    .and(takesArguments(3))
                                    .and(not(isSynthetic())))))
            .type(named(DISPATCHER))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(ExceptionResolutionAdvice.class)
                            .on(
                                isMethod()
                                    .and(named("processHandlerException"))
                                    .and(takesArguments(4))
                                    .and(not(isSynthetic())))))
            .type(
                (type, loader, module, redefined, domain) ->
                    !type.isInterface()
                        && !type.isEnum()
                        && !type.isAnnotation()
                        && !type.isRecord()
                        && scope.isApplication(type.getName(), domain))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(Advice.to(FrameAdvice.class).on(frameMethods())))
            .type(named(H2_STATEMENT))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(H2Advice.class)
                            .on(
                                isMethod()
                                    .and(named("executeUpdate"))
                                    .and(takesArguments(0))
                                    .and(not(isSynthetic())))));
    builder.installOn(instrumentation);
  }

  static final class SafeListener extends AgentBuilder.Listener.Adapter {
    private final Runnable onFailure;

    SafeListener(Runnable onFailure) {
      this.onFailure = java.util.Objects.requireNonNull(onFailure, "onFailure");
    }

    @Override
    public void onError(
        String typeName,
        ClassLoader classLoader,
        JavaModule module,
        boolean loaded,
        Throwable throwable) {
      if (isExplicitTarget(typeName)) {
        try {
          onFailure.run();
        } catch (RuntimeException | LinkageError ignored) {
          // An agent failure callback must not escape into application class loading.
        }
        System.err.println(
            "{\"code\":\"XTR-JAVA-INSTRUMENTATION\",\"message\":\"fixture boundary instrumentation failed; application continues\"}");
      }
    }
  }

  static boolean isExplicitTarget(String typeName) {
    return SPRING_ADAPTER.equals(typeName)
        || DISPATCHER.equals(typeName)
        || H2_STATEMENT.equals(typeName)
        || APPLICATION_TYPES.contains(typeName);
  }

  /** Methods that get boundary probes: real behavior, not accessors, bridges or Object plumbing. */
  static net.bytebuddy.matcher.ElementMatcher.Junction<net.bytebuddy.description.method.MethodDescription>
      frameMethods() {
    return isMethod()
        .and(not(isSynthetic()))
        .and(not(isBridge()))
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(nameStartsWith("lambda$")))
        .and(not(nameMatches("(get|is)\\p{Lu}.*").and(takesArguments(0))))
        .and(not(nameMatches("set\\p{Lu}.*").and(takesArguments(1)).and(returns(void.class))))
        .and(not(named("toString").and(takesArguments(0))))
        .and(not(named("hashCode").and(takesArguments(0))))
        .and(not(named("equals").and(takesArguments(1))))
        .and(not(named("compareTo")))
        .and(not(named("clone")))
        .and(not(named("finalize")));
  }

  /** Kept for the fixture contract: the fixture's own boundary methods are application targets. */
  static boolean isApplicationTarget(String typeName, String methodName) {
    return (CONTROLLER.equals(typeName) && "create".equals(methodName))
        || (SERVICE.equals(typeName) && "place".equals(methodName))
        || (REPOSITORY.equals(typeName) && "save".equals(methodName));
  }

  private static boolean isApplicationType(String internalName) {
    if (internalName == null) return false;
    return APPLICATION_TYPES.contains(internalName.replace('/', '.'));
  }

  /**
   * Request root advice. It reads the matched route template and method through the bootstrap
   * bridge, never the request path or query, and records only the numeric response status.
   */
  public static final class SpringRequestAdvice {
    private SpringRequestAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter(
        @Advice.Argument(0) Object request, @Advice.Argument(2) Object handlerMethod) {
      return dev.xtrace.agent.bootstrap.SpringMvcBridge.start(request, handlerMethod);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter boolean traced,
        @Advice.Argument(0) Object request,
        @Advice.Argument(1) Object response,
        @Advice.Thrown Throwable thrown) {
      if (!traced) return;
      dev.xtrace.agent.bootstrap.SpringMvcBridge.end(request, response, thrown);
    }
  }

  /**
   * Reports how the container resolved a handler exception, so a mapped exception is recorded as
   * the response it produced rather than as a propagated failure.
   */
  public static final class ExceptionResolutionAdvice {
    private ExceptionResolutionAdvice() {}

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(1) Object response,
        @Advice.Return Object resolved,
        @Advice.Thrown Throwable thrown) {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.exceptionResolved(response, resolved, thrown);
    }
  }

  /** Method boundary advice for in-scope application classes. */
  public static final class FrameAdvice {
    private FrameAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static String enter(
        @Advice.Origin Class<?> type,
        @Advice.Origin("#m") String method,
        @Advice.Origin("#d") String descriptor) {
      return BootstrapBridge.frameEnter(type, method, descriptor);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter String symbol, @Advice.Thrown Throwable thrown) {
      if (symbol != null) BootstrapBridge.frameExit(symbol, thrown);
    }
  }

  public static final class H2Advice {
    private H2Advice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter() {
      BootstrapBridge.databaseStart();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Thrown Throwable thrown) {
      BootstrapBridge.databaseEnd(thrown != null);
    }
  }
}
