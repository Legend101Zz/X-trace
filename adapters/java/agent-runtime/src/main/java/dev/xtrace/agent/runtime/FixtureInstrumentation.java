package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isAnnotatedWith;
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
    install(instrumentation, onFailure, attach, scope, null);
  }

  /** Probe owner application classes call, subject to their defining loader's visibility. */
  static final String PROBE_OWNER = "dev/xtrace/agent/bootstrap/BootstrapBridge";

  /** Method reports kept for diagnostics; bounded so a huge application cannot grow it. */
  static final int MAX_LINE_REPORTS = 4096;

  /**
   * @param lineProbes non-null only in effective focused mode: in-scope classes then also get the
   *     line-probe wrapper with LocalVariableTable-gated value reads. Standard mode passes null and
   *     pays no class-rewrite or verifier risk for evidence it may not record.
   */
  static void install(
      Instrumentation instrumentation,
      Runnable onFailure,
      boolean attach,
      ApplicationScope scope,
      LineProbes lineProbes) {
    install(instrumentation, onFailure, attach, scope, lineProbes,
        lineProbes == null ? new CaptureLimitations() : lineProbes.limitations);
  }

  static void install(
      Instrumentation instrumentation,
      Runnable onFailure,
      boolean attach,
      ApplicationScope scope,
      LineProbes lineProbes,
      CaptureLimitations limitations) {
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
            .with(new SafeListener(onFailure, scope, limitations))
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
              scope.sourceBase());
          ProxyInterfaceSources.observe(loader, className, classfileBuffer, scope);
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
                    target
                        .visit(
                            Advice.to(ExceptionResolutionAdvice.class)
                                .on(
                                    isMethod()
                                        .and(named("processHandlerException"))
                                        .and(takesArguments(4))
                                        .and(not(isSynthetic()))))
                        .visit(
                            Advice.to(DispatchAdvice.class)
                                .on(
                                    isMethod()
                                        .and(named("doDispatch"))
                                        .and(takesArguments(2))
                                        .and(not(isSynthetic())))))
            .type(
                (type, loader, module, redefined, domain) ->
                    !type.isInterface()
                        && !type.isEnum()
                        && !type.isAnnotation()
                        && !type.isRecord()
                        && scope.isApplication(type.getName(), domain))
            .transform(
                (target, type, loader, module, domain) -> {
                  if (lineProbes == null && !gapOwnerAvailable(loader)) {
                    limitations.report();
                    return target;
                  }
                  net.bytebuddy.dynamic.DynamicType.Builder<?> framed =
                      target.visit(Advice.to(FrameAdvice.class).on(frameMethods()));
                  return lineProbes == null ? framed : framed
                      .visit(lineProbes.wrapper(loader));
                })
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
    ServletBoundaryInstrumentation.install(instrumentation, onFailure, attach);
  }

  /** Focused-mode line probe wiring: one site registry and one thread-safe report sink. */
  static final class LineProbes {
    private final dev.xtrace.agent.runtime.line.SiteRegistry registry;
    private final CaptureLimitations limitations;
    private final java.util.concurrent.ConcurrentLinkedQueue<
            dev.xtrace.agent.runtime.line.MethodReport>
        reports = new java.util.concurrent.ConcurrentLinkedQueue<>();
    private final java.util.concurrent.atomic.AtomicInteger reportCount =
        new java.util.concurrent.atomic.AtomicInteger();

    LineProbes(dev.xtrace.agent.runtime.line.SiteRegistry registry) {
      this(registry, new CaptureLimitations());
    }

    LineProbes(dev.xtrace.agent.runtime.line.SiteRegistry registry, CaptureLimitations limitations) {
      this.registry = java.util.Objects.requireNonNull(registry, "registry");
      this.limitations = java.util.Objects.requireNonNull(limitations, "limitations");
    }

    dev.xtrace.agent.runtime.line.SiteRegistry registry() {
      return registry;
    }

    java.util.List<dev.xtrace.agent.runtime.line.MethodReport> reports() {
      return java.util.List.copyOf(reports);
    }

    dev.xtrace.agent.runtime.line.LineProbeAsmWrapper wrapper(ClassLoader ownerLoader) {
      boolean gapAvailable = gapOwnerAvailable(ownerLoader);
      if (!gapAvailable) limitations.report();
      return new dev.xtrace.agent.runtime.line.LineProbeAsmWrapper(
          dev.xtrace.agent.runtime.line.LineProbeConfig.focused(PROBE_OWNER),
          registry,
          ignored -> null,
          batch -> {
            for (dev.xtrace.agent.runtime.line.MethodReport report : batch) {
              if (reportCount.incrementAndGet() > MAX_LINE_REPORTS) {
                reportCount.decrementAndGet();
                return;
              }
              reports.add(report);
            }
          },
          ownerLoader) {
        @Override
        protected String probeOwnerProblem() {
          return gapAvailable ? super.probeOwnerProblem() : "bootstrap gap bridge unavailable";
        }

        @Override
        protected int skippedMethodEntryBytes() { return gapAvailable ? 3 : 0; }

        @Override
        protected void skippedMethodEntryUnavailable() { limitations.report(); }

        @Override
        protected void skippedMethodEntry(net.bytebuddy.jar.asm.MethodVisitor method) {
          // The decision travels with this method's bytecode, including lambda bodies. No loader
          // registry or diagnostic-buffer capacity can change attribution at request time.
          method.visitMethodInsn(net.bytebuddy.jar.asm.Opcodes.INVOKESTATIC,
              PROBE_OWNER, "lineGap", "()V", false);
        }
      };
    }
  }

  /** Do not trust a child loader's same-named bridge, or a bridge without the gap entry point. */
  static boolean gapOwnerAvailable(ClassLoader loader) {
    try {
      Class<?> owner = Class.forName(PROBE_OWNER.replace('/', '.'), false, loader);
      if (owner != BootstrapBridge.class) return false;
      java.lang.reflect.Method gap = owner.getDeclaredMethod("lineGap");
      return java.lang.reflect.Modifier.isPublic(gap.getModifiers())
          && java.lang.reflect.Modifier.isStatic(gap.getModifiers())
          && gap.getReturnType() == void.class;
    } catch (Throwable unavailable) {
      return false;
    }
  }

  /**
   * Sticky process coverage limitation. Without invocation probes, affected requests cannot be
   * identified, so every later recording conservatively names CLASS_NOT_TRANSFORMED. The count
   * describes failed probe installations, never an invented number of missed invocations.
   */
  static final class CaptureLimitations {
    private final java.util.concurrent.atomic.AtomicLong count =
        new java.util.concurrent.atomic.AtomicLong();

    void report() {
      long previous = count.getAndUpdate(value -> value == Long.MAX_VALUE ? value : value + 1);
      if (previous == 0) {
        System.err.println(
            "{\"code\":\"XTR-JAVA-INSTRUMENTATION\",\"message\":\"application invocation probes unavailable; recordings remain partial; application continues\"}");
      }
    }

    long count() { return count.get(); }
  }

  static final class SafeListener extends AgentBuilder.Listener.Adapter {
    private final Runnable onFailure;
    private final ApplicationScope scope;
    private final CaptureLimitations limitations;

    SafeListener(Runnable onFailure) {
      this(onFailure, ApplicationScope.defaultScope(), new CaptureLimitations());
    }

    SafeListener(Runnable onFailure, ApplicationScope scope, CaptureLimitations limitations) {
      this.onFailure = java.util.Objects.requireNonNull(onFailure, "onFailure");
      this.scope = scope;
      this.limitations = limitations;
    }

    @Override
    public void onError(
        String typeName,
        ClassLoader classLoader,
        JavaModule module,
        boolean loaded,
        Throwable throwable) {
      // The error callback has no ProtectionDomain. With default Boot scope an unknown origin
      // might be application code; conservatively disclose the failure rather than lose it.
      if (scope.verdict(typeName, null) != ApplicationScope.NOT_APPLICATION) limitations.report();
      if (isExplicitTarget(typeName)) {
        try {
          onFailure.run();
        } catch (Throwable ignored) {
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
        .and(
            not(
                nameMatches("(get|is)\\p{Lu}.*")
                    .and(takesArguments(0))
                    .and(not(isAnnotatedWith(nameStartsWith("org.springframework.web.bind.annotation."))))))
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

  /**
   * Brackets {@code DispatcherServlet#doDispatch}. The response status of a redirect or an error
   * view only exists after the view renders, which is after the handler adapter returned, so the
   * dispatch ownership stays here while the outer standard servlet frame owns root completion.
   */
  public static final class DispatchAdvice {
    private DispatchAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter() {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.dispatchEnter();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Argument(1) Object response, @Advice.Thrown Throwable thrown) {
      dev.xtrace.agent.bootstrap.SpringMvcBridge.dispatchEnd(response, thrown);
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
