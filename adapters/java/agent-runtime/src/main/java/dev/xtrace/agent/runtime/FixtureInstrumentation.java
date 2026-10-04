package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.utility.JavaModule;

/** Installs the exact fixture-only Spring MVC, application, and H2 transformations. */
final class FixtureInstrumentation {
  static final String SPRING_ADAPTER =
      "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter";
  static final String H2_STATEMENT = "org.h2.jdbc.JdbcPreparedStatement";
  static final String CONTROLLER = "dev.xtrace.fixture.OrderController";
  static final String SERVICE = "dev.xtrace.fixture.OrderService";
  static final String REPOSITORY = "dev.xtrace.fixture.OrderRepository";
  private static final Set<String> APPLICATION_TYPES = Set.of(CONTROLLER, SERVICE, REPOSITORY);
  private static final AtomicBoolean INSTALLED = new AtomicBoolean();

  private FixtureInstrumentation() {}

  static void install(Instrumentation instrumentation, Runnable onFailure) {
    if (!INSTALLED.compareAndSet(false, true)) {
      throw new IllegalStateException("fixture instrumentation is already installed");
    }
    AgentBuilder builder =
        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.DISABLED)
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
          SourceAttestation.observe(loader, className, classfileBuffer);
        }
        return null;
      }
    }, false);

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
            .type(named(CONTROLLER))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(ControllerAdvice.class)
                            .on(
                                isMethod()
                                    .and(named("create"))
                                    .and(not(isSynthetic())))))
            .type(named(SERVICE))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(ServiceAdvice.class)
                            .on(
                                isMethod()
                                    .and(named("place"))
                                    .and(not(isSynthetic())))))
            .type(named(REPOSITORY))
            .transform(
                (target, type, loader, module, domain) ->
                    target.visit(
                        Advice.to(RepositoryAdvice.class)
                            .on(
                                isMethod()
                                    .and(named("save"))
                                    .and(not(isSynthetic())))))
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
        || H2_STATEMENT.equals(typeName)
        || APPLICATION_TYPES.contains(typeName);
  }

  static boolean isApplicationTarget(String typeName, String methodName) {
    return (CONTROLLER.equals(typeName) && "create".equals(methodName))
        || (SERVICE.equals(typeName) && "place".equals(methodName))
        || (REPOSITORY.equals(typeName) && "save".equals(methodName));
  }

  private static boolean isApplicationType(String internalName) {
    if (internalName == null) return false;
    return APPLICATION_TYPES.contains(internalName.replace('/', '.'));
  }

  /** Request advice uses only fixed fixture identity and the response's numeric status. */
  public static final class SpringRequestAdvice {
    private SpringRequestAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter(@Advice.Argument(2) Object handlerMethod) {
      boolean matched = false;
      if (handlerMethod != null) {
        try {
          Method getBeanType = handlerMethod.getClass().getMethod("getBeanType");
          Method getMethod = handlerMethod.getClass().getMethod("getMethod");
          Object beanType = getBeanType.invoke(handlerMethod);
          Object method = getMethod.invoke(handlerMethod);
          matched =
              beanType instanceof Class<?> type
                  && CONTROLLER.equals(type.getName())
                  && method instanceof Method javaMethod
                  && "create".equals(javaMethod.getName());
        } catch (ReflectiveOperationException | RuntimeException ignored) {
          matched = false;
        }
      }
      if (!matched) return false;
      return BootstrapBridge.requestStart("POST", "/orders");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter boolean traced,
        @Advice.Argument(1) Object response,
        @Advice.Thrown Throwable thrown) {
      if (!traced) return;
      int responseStatus = 0;
      if (response != null) {
        try {
          Object status = response.getClass().getMethod("getStatus").invoke(response);
          responseStatus = status instanceof Integer value ? value : 0;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
          responseStatus = 0;
        }
      }
      BootstrapBridge.requestEnd(responseStatus, thrown != null);
    }
  }

  public static final class ControllerAdvice {
    private ControllerAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Origin Method method) {
      BootstrapBridge.frameEnter("OrderController.create", method);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Thrown Throwable thrown) {
      BootstrapBridge.frameExit("OrderController.create", thrown != null);
    }
  }

  public static final class ServiceAdvice {
    private ServiceAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Origin Method method) {
      BootstrapBridge.frameEnter("OrderService.place", method);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Thrown Throwable thrown) {
      BootstrapBridge.frameExit("OrderService.place", thrown != null);
    }
  }

  public static final class RepositoryAdvice {
    private RepositoryAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Origin Method method) {
      BootstrapBridge.frameEnter("OrderRepository.save", method);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Thrown Throwable thrown) {
      BootstrapBridge.frameExit("OrderRepository.save", thrown != null);
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
