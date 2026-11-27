package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isBridge;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import dev.xtrace.agent.bootstrap.WebFluxBridge;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.pool.TypePool;

/**
 * ByteBuddy instrumentation for Spring WebFlux dispatch, HTTP server boundary, routing, and
 * functional handlers with fail-closed version/contract guards and strict fault isolation.
 */
final class WebFluxInstrumentation {
  static final String HTTP_WEB_HANDLER_ADAPTER =
      "org.springframework.http.server.reactive.HttpWebHandlerAdapter";
  static final String WEB_HANDLER = "org.springframework.web.server.WebHandler";
  static final String DISPATCHER_HANDLER =
      "org.springframework.web.reactive.DispatcherHandler";
  static final String HANDLER_ADAPTER = "org.springframework.web.reactive.HandlerAdapter";
  static final String ROUTER_FUNCTION =
      "org.springframework.web.reactive.function.server.RouterFunction";
  static final String HANDLER_FUNCTION =
      "org.springframework.web.reactive.function.server.HandlerFunction";
  static final String SERVER_WEB_EXCHANGE = "org.springframework.web.server.ServerWebExchange";
  static final String SERVER_HTTP_REQUEST =
      "org.springframework.http.server.reactive.ServerHttpRequest";
  static final String SERVER_HTTP_RESPONSE =
      "org.springframework.http.server.reactive.ServerHttpResponse";
  static final String SERVER_REQUEST =
      "org.springframework.web.reactive.function.server.ServerRequest";
  static final String MONO = "reactor.core.publisher.Mono";

  private static final AtomicBoolean UNQUALIFIED = new AtomicBoolean();
  private static final AtomicBoolean PROBE_UNAVAILABLE = new AtomicBoolean();
  private static final Map<ClassLoader, Boolean> CONTRACT_CACHE =
      Collections.synchronizedMap(new WeakHashMap<>());

  private WebFluxInstrumentation() {}

  static ReactorContextInstrumentation.FailureListener failureListener(Runnable onLimitation) {
    return new ReactorContextInstrumentation.FailureListener(
        WebFluxInstrumentation::markDegraded, onLimitation);
  }

  static void install(Instrumentation instrumentation, Runnable onLimitation, boolean attach) {
    ReactorContextInstrumentation.FailureListener listener = failureListener(onLimitation);
    configure(new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(attach ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
                : AgentBuilder.RedefinitionStrategy.DISABLED)
            .ignore(nameStartsWith("java.").or(nameStartsWith("jdk."))
                .or(nameStartsWith("sun.")).or(nameStartsWith("dev.xtrace.agent."))
                .or(nameStartsWith("net.bytebuddy.")))
            .assureReadEdgeFromAndTo(instrumentation, WebFluxBridge.class)
            .with(listener),
        listener,
        null)
        .installOn(instrumentation);
  }

  /** Builds the WebFlux AgentBuilder configuration; {@code poolOverride} is test-only. */
  static AgentBuilder configure(
      AgentBuilder builder,
      ReactorContextInstrumentation.FailureListener listener,
      TypePool poolOverride) {
    AgentBuilder.RawMatcher httpAdapter = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && named(HTTP_WEB_HANDLER_ADAPTER).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher dispatcher = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && named(DISPATCHER_HANDLER).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher webHandler = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && !named(DISPATCHER_HANDLER).matches(type)
                && hasSuperType(named(WEB_HANDLER)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher handlerAdapter = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(HANDLER_ADAPTER)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher routerFunction = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(ROUTER_FUNCTION)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher handlerFunction = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(HANDLER_FUNCTION)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));

    return builder
        .type(httpAdapter)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(HttpHandlerAdapterAdvice.class).on(httpHandlerAdapterMethods())))
        .type(dispatcher)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(DispatcherAdvice.class).on(webHandlerMethods())))
        .type(webHandler)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(WebHandlerAdvice.class).on(webHandlerMethods())))
        .type(handlerAdapter)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(HandlerAdapterAdvice.class).on(handlerAdapterMethods())))
        .type(routerFunction)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(RouterFunctionAdvice.class).on(routerFunctionMethods())))
        .type(handlerFunction)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(HandlerFunctionAdvice.class).on(handlerFunctionMethods())));
  }

  static ElementMatcher.Junction<MethodDescription> httpHandlerAdapterMethods() {
    return concreteMethod("handle")
        .and(takesArguments(2))
        .and(takesArgument(0, named(SERVER_HTTP_REQUEST)))
        .and(takesArgument(1, named(SERVER_HTTP_RESPONSE)))
        .and(returns(named(MONO)));
  }

  static ElementMatcher.Junction<MethodDescription> webHandlerMethods() {
    return concreteMethod("handle")
        .and(takesArguments(1))
        .and(takesArgument(0, named(SERVER_WEB_EXCHANGE)))
        .and(returns(named(MONO)));
  }

  static ElementMatcher.Junction<MethodDescription> handlerAdapterMethods() {
    return concreteMethod("handle")
        .and(takesArguments(2))
        .and(takesArgument(0, named(SERVER_WEB_EXCHANGE)))
        .and(takesArgument(1, Object.class))
        .and(returns(named(MONO)));
  }

  static ElementMatcher.Junction<MethodDescription> routerFunctionMethods() {
    return concreteMethod("route")
        .and(takesArguments(1))
        .and(takesArgument(0, named(SERVER_REQUEST)))
        .and(returns(named(MONO)));
  }

  static ElementMatcher.Junction<MethodDescription> handlerFunctionMethods() {
    return concreteMethod("handle")
        .and(takesArguments(1))
        .and(takesArgument(0, named(SERVER_REQUEST)))
        .and(returns(named(MONO)));
  }

  private static ElementMatcher.Junction<MethodDescription> concreteMethod(String name) {
    return isMethod()
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(isBridge()))
        .and(not(isSynthetic()))
        .and(named(name));
  }

  private static boolean qualifies(
      String typeName, ClassLoader loader, ProtectionDomain domain, TypePool poolOverride) {
    if (!ReactorContextInstrumentation.bootstrapVisible(loader, WebFluxBridge.class)) {
      markDegraded();
      return false;
    }
    boolean springFrameworkClass = typeName != null && typeName.startsWith("org.springframework.");
    if (springFrameworkClass
        && ReactorContextInstrumentation.checkJarVersion(domain, 5, 3, 8)
            == ReactorContextInstrumentation.VersionStatus.UNSUPPORTED) {
      markUnqualified();
      return false;
    }
    if (ReactorContextInstrumentation.checkResourceJarVersion(
            loader, "org/springframework/web/reactive/DispatcherHandler.class", 5, 3, 8)
        == ReactorContextInstrumentation.VersionStatus.UNSUPPORTED) {
      markUnqualified();
      return false;
    }
    if (ReactorContextInstrumentation.checkResourceJarVersion(
            loader, "reactor/core/publisher/Mono.class", 3, 4, 4)
        == ReactorContextInstrumentation.VersionStatus.UNSUPPORTED) {
      markUnqualified();
      return false;
    }
    if (poolOverride != null) {
      if (!supportsWebFluxContract(poolOverride)) {
        markUnqualified();
        return false;
      }
      return true;
    }
    if (!supportsWebFluxContract(loader)) {
      markUnqualified();
      return false;
    }
    return true;
  }

  static boolean supportsWebFluxContract(ClassLoader loader) {
    if (loader == null) return false;
    Boolean cached = CONTRACT_CACHE.get(loader);
    if (cached != null) return cached;
    boolean ok = supportsWebFluxContract(TypePool.Default.of(loader));
    CONTRACT_CACHE.put(loader, ok);
    return ok;
  }

  static boolean supportsWebFluxContract(TypePool pool) {
    if (pool == null) return false;
    return ReactorContextInstrumentation.supportsReactorContract(pool)
        && ReactorContextInstrumentation.hasMethod(
            pool, WEB_HANDLER, "handle", "(L" + SERVER_WEB_EXCHANGE.replace('.', '/') + ";)"
                + "Lreactor/core/publisher/Mono;")
        && ReactorContextInstrumentation.hasMethod(
            pool, DISPATCHER_HANDLER, "handle", "(L" + SERVER_WEB_EXCHANGE.replace('.', '/') + ";)"
                + "Lreactor/core/publisher/Mono;")
        && ReactorContextInstrumentation.hasMethod(
            pool, HANDLER_ADAPTER, "handle",
            "(L" + SERVER_WEB_EXCHANGE.replace('.', '/') + ";Ljava/lang/Object;)"
                + "Lreactor/core/publisher/Mono;")
        && ReactorContextInstrumentation.hasMethod(
            pool, ROUTER_FUNCTION, "route",
            "(L" + SERVER_REQUEST.replace('.', '/') + ";)Lreactor/core/publisher/Mono;")
        && ReactorContextInstrumentation.hasMethod(
            pool, HANDLER_FUNCTION, "handle",
            "(L" + SERVER_REQUEST.replace('.', '/') + ";)Lreactor/core/publisher/Mono;")
        && ReactorContextInstrumentation.hasMethod(pool, SERVER_WEB_EXCHANGE, "getRequest", "()")
        && ReactorContextInstrumentation.hasMethod(pool, SERVER_WEB_EXCHANGE, "getResponse", "()")
        && ReactorContextInstrumentation.hasMethod(pool, SERVER_WEB_EXCHANGE, "getAttributes", "()")
        && (ReactorContextInstrumentation.hasMethod(pool, SERVER_HTTP_REQUEST, "getMethod", "()")
            || ReactorContextInstrumentation.hasMethod(
                pool, SERVER_HTTP_REQUEST, "getMethodValue", "()"))
        && (ReactorContextInstrumentation.hasMethod(pool, SERVER_HTTP_RESPONSE, "getStatusCode", "()")
            || ReactorContextInstrumentation.hasMethod(
                pool, SERVER_HTTP_RESPONSE, "getRawStatusCode", "()"))
        && ReactorContextInstrumentation.hasMethod(pool, SERVER_REQUEST, "exchange", "()");
  }

  private static void markUnqualified() {
    UNQUALIFIED.set(true);
    WebFluxBridge.markInstrumentationUnavailable();
  }

  private static void markDegraded() {
    PROBE_UNAVAILABLE.set(true);
    WebFluxBridge.markInstrumentationUnavailable();
  }

  static void reportCoverageAtShutdown() {
    if (UNQUALIFIED.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Spring WebFlux framework version or API contract did not qualify\"}");
    }
    if (PROBE_UNAVAILABLE.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Spring WebFlux probe installation unavailable\"}");
    }
  }

  static void resetForTest() {
    UNQUALIFIED.set(false);
    PROBE_UNAVAILABLE.set(false);
    CONTRACT_CACHE.clear();
  }

  public static final class HttpHandlerAdapterAdvice {
    private HttpHandlerAdapterAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(
        @Advice.Argument(0) Object request, @Advice.Argument(1) Object response) {
      return WebFluxBridge.httpBoundaryEnter(request, response);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.boundaryExit(activation, result, thrown);
      }
    }
  }

  public static final class DispatcherAdvice {
    private DispatcherAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.Argument(0) Object exchange) {
      return WebFluxBridge.boundaryEnter(exchange, true);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.boundaryExit(activation, result, thrown);
      }
    }
  }

  public static final class WebHandlerAdvice {
    private WebHandlerAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.Argument(0) Object exchange) {
      return WebFluxBridge.boundaryEnter(exchange, false);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.boundaryExit(activation, result, thrown);
      }
    }
  }

  public static final class HandlerAdapterAdvice {
    private HandlerAdapterAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(
        @Advice.Argument(0) Object exchange, @Advice.Argument(1) Object handler) {
      return WebFluxBridge.handlerEnter(exchange, handler);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.handlerExit(activation, result, thrown);
      }
    }
  }

  public static final class RouterFunctionAdvice {
    private RouterFunctionAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.Argument(0) Object serverRequest) {
      return WebFluxBridge.routeEnter(serverRequest);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.routeExit(activation, result, thrown);
      }
    }
  }

  public static final class HandlerFunctionAdvice {
    private HandlerFunctionAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(
        @Advice.This Object handlerFunction, @Advice.Argument(0) Object serverRequest) {
      return WebFluxBridge.functionalHandlerEnter(handlerFunction, serverRequest);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter Object activation,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (activation != null) {
        result = WebFluxBridge.functionalHandlerExit(activation, result, thrown);
      }
    }
  }
}
