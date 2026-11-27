package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * JDK-only request-root, route, handler, and error correlation bridge for Spring WebFlux.
 *
 * <p>All Spring WebFlux and Reactor types are reached reflectively on public interface/API methods
 * cached per runtime type in {@link ClassValue}, so one agent build serves Spring Framework 5.3+,
 * 6.x, and 7.x without framework dependencies on the bootstrap classpath.
 */
public final class WebFluxBridge {
  static final String EXCHANGE_SESSION_ATTR = "dev.xtrace.agent.webflux.session";
  static final String REQUEST_SESSION_ATTR = "dev.xtrace.agent.webflux.requestSession";
  static final String DISPATCHER_SYMBOL = "org.springframework.web.reactive.DispatcherHandler.handle";
  static final String HANDLER_ADAPTER_SYMBOL = "org.springframework.web.reactive.HandlerAdapter.handle";
  static final String HANDLER_FUNCTION_SYMBOL =
      "org.springframework.web.reactive.function.server.HandlerFunction.handle";
  static final String ROUTER_FUNCTION_SYMBOL =
      "org.springframework.web.reactive.function.server.RouterFunction.route";
  static final String BEST_MATCHING_PATTERN =
      "org.springframework.web.reactive.HandlerMapping.bestMatchingPattern";
  static final String BEST_MATCHING_HANDLER =
      "org.springframework.web.reactive.HandlerMapping.bestMatchingHandler";
  static final String ROUTER_MATCHING_PATTERN =
      "org.springframework.web.reactive.function.server.RouterFunctions.matchingPattern";

  private static final AtomicBoolean OBSERVATION_UNAVAILABLE = new AtomicBoolean();
  private static final AtomicBoolean INSTRUMENTATION_UNAVAILABLE = new AtomicBoolean();
  private static final ThreadLocal<OuterBoundary> OUTER_BOUNDARY = new ThreadLocal<>();

  private static final ClassValue<Method[]> EXCHANGE_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "getRequest"),
            SpringMvcBridge.publicMethod(type, "getResponse"),
            SpringMvcBridge.publicMethod(type, "getAttribute", String.class),
            SpringMvcBridge.publicMethod(type, "getAttributes")
          };
        }
      };

  private static final ClassValue<Method[]> REQUEST_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "getMethod"),
            SpringMvcBridge.publicMethod(type, "getMethodValue")
          };
        }
      };

  private static final ClassValue<Method[]> RESPONSE_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "getStatusCode"),
            SpringMvcBridge.publicMethod(type, "getRawStatusCode")
          };
        }
      };

  private static final ClassValue<Method[]> SERVER_REQUEST_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "method"),
            SpringMvcBridge.publicMethod(type, "methodName"),
            SpringMvcBridge.publicMethod(type, "attribute", String.class),
            SpringMvcBridge.publicMethod(type, "attributes"),
            SpringMvcBridge.publicMethod(type, "exchange")
          };
        }
      };

  private static final ClassValue<Method[]> SERVER_RESPONSE_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            SpringMvcBridge.publicMethod(type, "statusCode"),
            SpringMvcBridge.publicMethod(type, "rawStatusCode")
          };
        }
      };

  private static final ClassValue<Method> METHOD_NAME =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return SpringMvcBridge.publicMethod(type, "name");
        }
      };

  private static final ClassValue<Method> STATUS_VALUE =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return SpringMvcBridge.publicMethod(type, "value");
        }
      };

  private static final ClassValue<Method> PATTERN_STRING =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return SpringMvcBridge.publicMethod(type, "getPatternString");
        }
      };

  private static final ClassValue<Method> HANDLER_BEAN_TYPE =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return SpringMvcBridge.publicMethod(type, "getBeanType");
        }
      };

  private WebFluxBridge() {}

  private static final class OuterBoundary {
    final long startedNs;
    int depth;
    WebFluxSession session;

    OuterBoundary(long startedNs) {
      this.startedNs = startedNs;
    }
  }

  static final class WebFluxSession {
    final long startedNs;
    final String httpMethod;
    final Object exchange;
    final boolean hasOuterBoundary;
    final ReactorContextBridge.Token rootToken;
    final AtomicBoolean excludedByScope = new AtomicBoolean();
    final AtomicBoolean recorded = new AtomicBoolean();
    final AtomicBoolean handlerEntered = new AtomicBoolean();
    final AtomicBoolean finished = new AtomicBoolean();
    final AtomicBoolean correlationGap = new AtomicBoolean();
    volatile Throwable lastError;
    volatile int provisionalStatus;
    volatile ReactorContextBridge.Token activeHandlerToken;

    WebFluxSession(
        long startedNs,
        String httpMethod,
        Object exchange,
        boolean hasOuterBoundary) {
      this.startedNs = startedNs;
      this.httpMethod = httpMethod;
      this.exchange = exchange;
      this.hasOuterBoundary = hasOuterBoundary;
      this.rootToken = ReactorContextBridge.createPendingToken(
          (tok, error, cancelled) -> finishOuterSession(this, error, cancelled));
    }
  }

  private record BoundaryActivation(
      OuterBoundary boundary, boolean dispatcher, ReactorContextBridge.Scope scope) {}

  private record HandlerActivation(
      WebFluxSession session,
      String symbol,
      String frameId,
      ReactorContextBridge.Token handlerToken,
      ReactorContextBridge.Scope scope,
      boolean ownsFrame,
      boolean ownsLifecycle) {}

  private record RouteActivation(
      WebFluxSession session, ReactorContextBridge.Scope scope) {}

  /** Marks WebFlux bytecode instrumentation as unavailable/degraded. */
  public static void markInstrumentationUnavailable() {
    INSTRUMENTATION_UNAVAILABLE.set(true);
  }

  /** Consumes the observation-unavailable flag during shutdown or test checks. */
  public static boolean takeObservationUnavailable() {
    return OBSERVATION_UNAVAILABLE.getAndSet(false);
  }

  public static boolean takeInstrumentationUnavailable() {
    return INSTRUMENTATION_UNAVAILABLE.getAndSet(false);
  }

  private static boolean unavailable() {
    OBSERVATION_UNAVAILABLE.set(true);
    return false;
  }

  /**
   * Synchronous entry hook for {@code HttpWebHandlerAdapter.handle(ServerHttpRequest,
   * ServerHttpResponse)}. Captures the earliest request start timestamp and outer boundary.
   */
  public static Object httpBoundaryEnter(Object request, Object response) {
    OuterBoundary active = OUTER_BOUNDARY.get();
    if (active == null) {
      active = new OuterBoundary(System.nanoTime());
      OUTER_BOUNDARY.set(active);
    }
    active.depth++;
    return new BoundaryActivation(active, false, null);
  }

  /**
   * Synchronous entry hook for {@code WebHandler.handle(ServerWebExchange)} and {@code
   * DispatcherHandler.handle(ServerWebExchange)}. Never leaves a sticky {@code ThreadLocal} after
   * method exit.
   */
  public static Object boundaryEnter(Object exchange, boolean dispatcher) {
    OuterBoundary active = OUTER_BOUNDARY.get();
    if (active == null) {
      active = new OuterBoundary(System.nanoTime());
      OUTER_BOUNDARY.set(active);
    }
    active.depth++;
    if (exchange != null && active.session == null) {
      Object existing = exchangeAttribute(exchange, EXCHANGE_SESSION_ATTR);
      if (existing instanceof WebFluxSession session && !session.finished.get()) {
        active.session = session;
      } else {
        String verb = httpMethodFromExchange(exchange);
        WebFluxSession session = new WebFluxSession(active.startedNs, verb, exchange, true);
        active.session = session;
        putExchangeAttribute(exchange, EXCHANGE_SESSION_ATTR, session);
      }
    }
    ReactorContextBridge.Scope scope = active.session != null
        ? ReactorContextBridge.enterScope(active.session.rootToken) : null;
    return new BoundaryActivation(active, dispatcher, scope);
  }

  /**
   * Synchronous exit hook for {@code HttpWebHandlerAdapter.handle}, {@code WebHandler.handle}, and
   * {@code DispatcherHandler.handle}. Wraps the returned {@code Mono} so async context and terminal
   * outcome survive thread hops, or fails closed if wrapping is unavailable.
   */
  public static Object boundaryExit(Object activationObj, Object returnValue, Throwable thrown) {
    if (!(activationObj instanceof BoundaryActivation activation)) return returnValue;
    OuterBoundary boundary = activation.boundary;
    ReactorContextBridge.exitScope(activation.scope);
    WebFluxSession session = boundary.session;
    if (activation.dispatcher && thrown != null && session != null) {
      session.lastError = thrown;
    }
    boolean outermost = --boundary.depth <= 0;
    if (outermost) OUTER_BOUNDARY.remove();
    if (!outermost) {
      if (thrown == null && returnValue != null && session != null) {
        Object propagated = ReactorContextBridge.wrapMono(returnValue, session.rootToken, null, null);
        return propagated != null ? propagated : returnValue;
      }
      return returnValue;
    }
    if (session == null) return returnValue;
    if (session.excludedByScope.get()) {
      cleanupExchangeAttribute(session.exchange);
      return returnValue;
    }
    if (thrown != null) {
      if (session.recorded.get()) {
        ReactorContextBridge.signalError(session.rootToken, thrown);
      } else {
        cleanupExchangeAttribute(session.exchange);
      }
      return returnValue;
    }
    if (returnValue == null) {
      if (session.recorded.get()) {
        session.correlationGap.set(true);
        ReactorContextBridge.reportCorrelationGap(session.rootToken, "webflux_null_publisher");
        finishOuterSession(session, null, false);
      } else {
        cleanupExchangeAttribute(session.exchange);
      }
      return null;
    }
    Object wrapped = ReactorContextBridge.wrapMono(
        returnValue,
        session.rootToken,
        (tok, error, cancelled) -> finishOuterSession(session, error, cancelled),
        null);
    if (wrapped != null) return wrapped;
    // Fail closed: Mono wrapping is unavailable, so close any active recording immediately rather
    // than leaving an unclosed recording open until shutdown.
    ReactorContextBridge.reportPropagationUnavailable();
    if (session.recorded.get()) {
      session.correlationGap.set(true);
      ReactorContextBridge.reportCorrelationGap(session.rootToken, "webflux_mono_wrap_unavailable");
      finishOuterSession(session, null, false);
    } else {
      cleanupExchangeAttribute(session.exchange);
    }
    return returnValue;
  }

  /**
   * Entry hook for {@code HandlerAdapter.handle(ServerWebExchange, Object)}. Opens the request root
   * once route template and in-scope handler identity are known, and emits a handler frame.
   */
  public static Object handlerEnter(Object exchange, Object handler) {
    if (exchange == null || handler == null) return null;
    WebFluxSession session = resolveExchangeSession(exchange);
    boolean ownsLifecycle = false;
    if (session == null) {
      session = new WebFluxSession(
          System.nanoTime(), httpMethodFromExchange(exchange), exchange, false);
      ownsLifecycle = true;
    }
    if (session.excludedByScope.get() || session.finished.get()) return null;
    if (!ensureRecordingStarted(session, exchange, null, handler)) return null;
    if (!session.handlerEntered.compareAndSet(false, true)) return null;
    String symbol = isHandlerFunction(handler) ? HANDLER_FUNCTION_SYMBOL : HANDLER_ADAPTER_SYMBOL;
    String frameId = BootstrapBridge.emitReactiveEvent(
        session.rootToken.slot.state(),
        session.rootToken.parentEventId(),
        BridgeEventKind.FRAME_ENTER,
        symbol,
        0);
    ReactorContextBridge.Token handlerToken = session.rootToken.derive(frameId);
    session.activeHandlerToken = handlerToken;
    ReactorContextBridge.Scope scope = ReactorContextBridge.enterScope(handlerToken);
    return new HandlerActivation(
        session, symbol, frameId, handlerToken, scope, true, ownsLifecycle);
  }

  /** Exit hook for {@code HandlerAdapter.handle(ServerWebExchange, Object)}. */
  public static Object handlerExit(Object activationObj, Object returnValue, Throwable thrown) {
    if (!(activationObj instanceof HandlerActivation act)) return returnValue;
    ReactorContextBridge.exitScope(act.scope);
    BootstrapBridge.RecordingState state = act.session.rootToken.slot.state();
    if (thrown != null) {
      act.session.lastError = thrown;
      if (state != null) {
        BootstrapBridge.emitReactiveThrow(state, act.frameId, act.symbol, thrown);
      }
      if (act.ownsLifecycle) {
        finishOuterSession(act.session, thrown, false);
      }
      return returnValue;
    }
    if (returnValue == null) {
      if (state != null) {
        BootstrapBridge.emitReactiveEvent(state, act.frameId, BridgeEventKind.FRAME_EXIT, act.symbol, 0);
      }
      if (act.ownsLifecycle) {
        finishOuterSession(act.session, null, false);
      }
      return null;
    }
    Object wrapped = ReactorContextBridge.wrapMono(
        returnValue,
        act.handlerToken,
        (tok, error, cancelled) -> closeHandlerFrame(act, error, cancelled),
        null);
    if (wrapped != null) return wrapped;
    // Fail closed if returned publisher cannot be wrapped.
    if (state != null) {
      BootstrapBridge.emitReactiveEvent(state, act.frameId, BridgeEventKind.FRAME_EXIT, act.symbol, 0);
      act.session.correlationGap.set(true);
      ReactorContextBridge.reportCorrelationGap(act.handlerToken, "handler_mono_wrap_unavailable");
    }
    if (act.ownsLifecycle) {
      finishOuterSession(act.session, null, false);
    }
    return returnValue;
  }

  /** Entry hook for {@code RouterFunction.route(ServerRequest)}. */
  public static Object routeEnter(Object serverRequest) {
    if (serverRequest == null) return null;
    WebFluxSession session = resolveServerRequestSession(serverRequest);
    if (session == null || session.finished.get()) return null;
    ReactorContextBridge.Scope scope = ReactorContextBridge.enterScope(session.rootToken);
    return new RouteActivation(session, scope);
  }

  /** Exit hook for {@code RouterFunction.route(ServerRequest)}. */
  public static Object routeExit(Object activationObj, Object returnValue, Throwable thrown) {
    if (!(activationObj instanceof RouteActivation act)) return returnValue;
    ReactorContextBridge.exitScope(act.scope);
    if (thrown != null) {
      act.session.lastError = thrown;
      BootstrapBridge.RecordingState state = act.session.rootToken.slot.state();
      if (state != null) {
        BootstrapBridge.emitReactiveThrow(
            state, act.session.rootToken.parentEventId(), ROUTER_FUNCTION_SYMBOL, thrown);
      }
      return returnValue;
    }
    if (returnValue != null) {
      Object propagated = ReactorContextBridge.wrapMono(
          returnValue, act.session.rootToken, null, null);
      if (propagated != null) return propagated;
    }
    return returnValue;
  }

  /**
   * Entry hook for {@code HandlerFunction.handle(ServerRequest)}. Avoids duplicate roots when
   * invoked inside an instrumented {@code HandlerAdapter}, and supports standalone functional
   * routing when invoked directly without {@code DispatcherHandler}.
   */
  public static Object functionalHandlerEnter(Object handlerFunction, Object serverRequest) {
    if (handlerFunction == null || serverRequest == null) return null;
    WebFluxSession session = resolveServerRequestSession(serverRequest);
    boolean ownsLifecycle = false;
    if (session == null) {
      Object exchange = serverRequestExchange(serverRequest);
      session = new WebFluxSession(
          System.nanoTime(), httpMethodFromServerRequest(serverRequest), exchange, false);
      ownsLifecycle = true;
    }
    if (session.excludedByScope.get() || session.finished.get()) return null;
    if (session.handlerEntered.get()) {
      // HandlerAdapter already opened the handler frame; reuse its handler token cleanly.
      ReactorContextBridge.Token activeTok = session.activeHandlerToken;
      ReactorContextBridge.Token tok = activeTok != null ? activeTok : session.rootToken;
      ReactorContextBridge.Scope scope = ReactorContextBridge.enterScope(tok);
      return new HandlerActivation(
          session, HANDLER_FUNCTION_SYMBOL, tok.parentEventId(), tok, scope, false, false);
    }
    if (!ensureRecordingStarted(session, session.exchange, serverRequest, handlerFunction)) {
      return null;
    }
    if (!session.handlerEntered.compareAndSet(false, true)) return null;
    String frameId = BootstrapBridge.emitReactiveEvent(
        session.rootToken.slot.state(),
        session.rootToken.parentEventId(),
        BridgeEventKind.FRAME_ENTER,
        HANDLER_FUNCTION_SYMBOL,
        0);
    ReactorContextBridge.Token handlerToken = session.rootToken.derive(frameId);
    session.activeHandlerToken = handlerToken;
    ReactorContextBridge.Scope scope = ReactorContextBridge.enterScope(handlerToken);
    return new HandlerActivation(
        session, HANDLER_FUNCTION_SYMBOL, frameId, handlerToken, scope, true, ownsLifecycle);
  }

  /** Exit hook for {@code HandlerFunction.handle(ServerRequest)}. */
  public static Object functionalHandlerExit(
      Object activationObj, Object returnValue, Throwable thrown) {
    if (!(activationObj instanceof HandlerActivation act)) return returnValue;
    ReactorContextBridge.exitScope(act.scope);
    if (!act.ownsFrame) {
      if (!act.ownsLifecycle && thrown == null && returnValue != null) {
        Object propagated =
            ReactorContextBridge.wrapMono(returnValue, act.handlerToken, null, null);
        return propagated != null ? propagated : returnValue;
      }
      return returnValue;
    }
    if (!act.session.handlerEntered.get() || act.frameId == null || act.frameId.isEmpty()) {
      return returnValue;
    }
    BootstrapBridge.RecordingState state = act.session.rootToken.slot.state();
    if (thrown != null) {
      act.session.lastError = thrown;
      if (state != null) {
        BootstrapBridge.emitReactiveThrow(state, act.frameId, act.symbol, thrown);
      }
      if (act.ownsLifecycle) finishOuterSession(act.session, thrown, false);
      return returnValue;
    }
    if (returnValue == null) {
      if (state != null) {
        BootstrapBridge.emitReactiveEvent(
            state, act.frameId, BridgeEventKind.FRAME_EXIT, act.symbol, 0);
      }
      if (act.ownsLifecycle) finishOuterSession(act.session, null, false);
      return null;
    }
    Object wrapped = ReactorContextBridge.wrapMono(
        returnValue,
        act.handlerToken,
        (tok, error, cancelled) -> {
          closeHandlerFrame(act, error, cancelled);
        },
        value -> {
          int status = statusFromServerResponse(value);
          if (status != 0) act.session.provisionalStatus = status;
        });
    if (wrapped != null) return wrapped;
    if (state != null) {
      BootstrapBridge.emitReactiveEvent(
          state, act.frameId, BridgeEventKind.FRAME_EXIT, act.symbol, 0);
      act.session.correlationGap.set(true);
      ReactorContextBridge.reportCorrelationGap(act.handlerToken, "functional_mono_wrap_unavailable");
    }
    if (act.ownsLifecycle) finishOuterSession(act.session, null, false);
    return returnValue;
  }

  private static void closeHandlerFrame(
      HandlerActivation act, Throwable error, boolean cancelled) {
    BootstrapBridge.RecordingState state = act.session.rootToken.slot.state();
    if (state != null && !state.closed) {
      if (error != null) {
        act.session.lastError = error;
        BootstrapBridge.emitReactiveThrow(state, act.frameId, act.symbol, error);
      } else {
        BootstrapBridge.emitReactiveEvent(
            state, act.frameId, BridgeEventKind.FRAME_EXIT, act.symbol, cancelled ? 1 : 0);
      }
    }
    if (act.ownsLifecycle) {
      finishOuterSession(act.session, error, cancelled);
    }
  }

  private static boolean ensureRecordingStarted(
      WebFluxSession session, Object exchange, Object serverRequest, Object handler) {
    if (session.recorded.get()) return session.rootToken.slot.state() != null;
    if (BootstrapBridge.inRequest()) return false;
    Class<?> handlerType = resolveHandlerType(handler);
    int scope = BootstrapBridge.scopeOf(handlerType);
    if (scope == 0) {
      session.excludedByScope.set(true);
      return false;
    }
    String verb = session.httpMethod != null ? session.httpMethod
        : (exchange != null ? httpMethodFromExchange(exchange)
            : httpMethodFromServerRequest(serverRequest));
    if (!BootstrapBridge.validMethod(verb)) return false;
    String template = exchange != null ? routeTemplateFromExchange(exchange)
        : routeTemplateFromServerRequest(serverRequest);
    if (!BootstrapBridge.validRoute(template)) return false;
    if (!session.recorded.compareAndSet(false, true)) {
      return session.rootToken.slot.state() != null;
    }
    BootstrapBridge.RecordingState state =
        BootstrapBridge.startReactiveRecording(verb, template, session.startedNs, scope < 0);
    if (state == null) {
      session.recorded.set(false);
      return false;
    }
    session.rootToken.slot.bind(state);
    if (session.hasOuterBoundary
        && ReactorContextBridge.currentToken() == null
        && ReactorContextBridge.isPropagationUnavailable()) {
      session.correlationGap.set(true);
      ReactorContextBridge.reportCorrelationGap(
          session.rootToken, "reactor_context_propagation_unavailable");
    }
    return true;
  }

  private static void finishOuterSession(
      WebFluxSession session, Throwable error, boolean cancelled) {
    if (session == null || !session.finished.compareAndSet(false, true)) return;
    session.rootToken.slot.terminated.set(true);
    try {
      BootstrapBridge.RecordingState state = session.rootToken.slot.state();
      if (state == null) return;
      boolean provisional = session.exchange == null || !session.hasOuterBoundary;
      int status = (!provisional && session.exchange != null)
          ? statusFromExchange(session.exchange)
          : session.provisionalStatus;
      Throwable actualError = error != null ? error : null;
      String[] unsupported = ReactorContextBridge.isPropagationUnavailable()
          ? new String[] {"async_correlation"} : null;
      BootstrapBridge.finishReactiveRecording(
          state, status, actualError, provisional, cancelled, unsupported);
    } finally {
      cleanupExchangeAttribute(session.exchange);
    }
  }

  private static WebFluxSession resolveExchangeSession(Object exchange) {
    Object attr = exchangeAttribute(exchange, EXCHANGE_SESSION_ATTR);
    if (attr instanceof WebFluxSession session) return session;
    ReactorContextBridge.Token token = ReactorContextBridge.currentToken();
    if (token != null && token.slot.state() != null) {
      // Find via OuterBoundary if still on assembly thread.
      OuterBoundary boundary = OUTER_BOUNDARY.get();
      if (boundary != null && boundary.session != null) return boundary.session;
    }
    return null;
  }

  private static WebFluxSession resolveServerRequestSession(Object serverRequest) {
    Object attr = serverRequestAttribute(serverRequest, REQUEST_SESSION_ATTR);
    if (attr instanceof WebFluxSession session) return session;
    Object exchange = serverRequestExchange(serverRequest);
    if (exchange != null) {
      Object exAttr = exchangeAttribute(exchange, EXCHANGE_SESSION_ATTR);
      if (exAttr instanceof WebFluxSession session) return session;
    }
    OuterBoundary boundary = OUTER_BOUNDARY.get();
    return boundary != null ? boundary.session : null;
  }

  static Class<?> resolveHandlerType(Object handler) {
    if (handler == null) return null;
    try {
      Method getBeanType = HANDLER_BEAN_TYPE.get(handler.getClass());
      if (getBeanType != null) {
        Object beanType = getBeanType.invoke(handler);
        if (beanType instanceof Class<?> cls) return cls;
      }
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
    }
    Class<?> type = handler.getClass();
    String name = type.getName();
    int lambdaMarker = name.indexOf("$$Lambda");
    if (lambdaMarker < 0) lambdaMarker = name.indexOf("$Lambda");
    if (lambdaMarker > 0 && type.getClassLoader() != null) {
      String hostName = name.substring(0, lambdaMarker);
      try {
        return Class.forName(hostName, false, type.getClassLoader());
      } catch (ClassNotFoundException | LinkageError ignored) {
        return type;
      }
    }
    return type;
  }

  private static boolean isHandlerFunction(Object handler) {
    if (handler == null) return false;
    for (Class<?> iface : handler.getClass().getInterfaces()) {
      if ("org.springframework.web.reactive.function.server.HandlerFunction".equals(iface.getName())) {
        return true;
      }
    }
    return HANDLER_BEAN_TYPE.get(handler.getClass()) == null
        && handler.getClass().getName().contains("Lambda");
  }

  static String httpMethodFromExchange(Object exchange) {
    if (exchange == null) return null;
    try {
      Method getRequest = EXCHANGE_METHODS.get(exchange.getClass())[0];
      Object request = getRequest == null ? null : getRequest.invoke(exchange);
      return httpMethodFromRequest(request);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return null;
    }
  }

  static String httpMethodFromRequest(Object request) {
    if (request == null) return null;
    try {
      Method[] methods = REQUEST_METHODS.get(request.getClass());
      Object methodObj = methods[0] != null ? methods[0].invoke(request) : null;
      if (methodObj == null && methods[1] != null) {
        methodObj = methods[1].invoke(request);
      }
      return extractMethodName(methodObj);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return null;
    }
  }

  static String httpMethodFromServerRequest(Object serverRequest) {
    if (serverRequest == null) return null;
    try {
      Method[] methods = SERVER_REQUEST_METHODS.get(serverRequest.getClass());
      Object methodObj = methods[0] != null ? methods[0].invoke(serverRequest) : null;
      if (methodObj == null && methods[1] != null) {
        methodObj = methods[1].invoke(serverRequest);
      }
      return extractMethodName(methodObj);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return null;
    }
  }

  private static String extractMethodName(Object methodObj) throws ReflectiveOperationException {
    if (methodObj == null) return null;
    if (methodObj instanceof String text) return text;
    if (methodObj instanceof Enum<?> enumVal) return enumVal.name();
    Method nameMethod = METHOD_NAME.get(methodObj.getClass());
    Object value = nameMethod == null ? null : nameMethod.invoke(methodObj);
    return value instanceof String text ? text : null;
  }

  static String routeTemplateFromExchange(Object exchange) {
    if (exchange == null) return null;
    Object pattern = exchangeAttribute(exchange, BEST_MATCHING_PATTERN);
    if (pattern == null) pattern = exchangeAttribute(exchange, ROUTER_MATCHING_PATTERN);
    return extractPatternString(pattern);
  }

  static String routeTemplateFromServerRequest(Object serverRequest) {
    if (serverRequest == null) return null;
    Object pattern = serverRequestAttribute(serverRequest, ROUTER_MATCHING_PATTERN);
    if (pattern == null) pattern = serverRequestAttribute(serverRequest, BEST_MATCHING_PATTERN);
    return extractPatternString(pattern);
  }

  private static String extractPatternString(Object pattern) {
    if (pattern == null) return null;
    if (pattern instanceof String text) return text;
    try {
      Method getPattern = PATTERN_STRING.get(pattern.getClass());
      if (getPattern == null) {
        unavailable();
        return null;
      }
      Object value = getPattern.invoke(pattern);
      return value instanceof String text ? text : null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return null;
    }
  }

  static int statusFromExchange(Object exchange) {
    if (exchange == null) return 0;
    try {
      Method getResponse = EXCHANGE_METHODS.get(exchange.getClass())[1];
      Object response = getResponse == null ? null : getResponse.invoke(exchange);
      return statusFromResponse(response);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return 0;
    }
  }

  static int statusFromResponse(Object response) {
    if (response == null) return 0;
    try {
      Method[] methods = RESPONSE_METHODS.get(response.getClass());
      Object statusObj = methods[0] != null ? methods[0].invoke(response) : null;
      int code = extractStatusValue(statusObj);
      if (code != 0) return code;
      if (methods[1] != null) {
        Object raw = methods[1].invoke(response);
        if (raw instanceof Integer val) return val;
      }
      return 0;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return 0;
    }
  }

  static int statusFromServerResponse(Object serverResponse) {
    if (serverResponse == null) return 0;
    try {
      Method[] methods = SERVER_RESPONSE_METHODS.get(serverResponse.getClass());
      Object statusObj = methods[0] != null ? methods[0].invoke(serverResponse) : null;
      int code = extractStatusValue(statusObj);
      if (code != 0) return code;
      if (methods[1] != null) {
        Object raw = methods[1].invoke(serverResponse);
        if (raw instanceof Integer val) return val;
      }
      return 0;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
      return 0;
    }
  }

  private static int extractStatusValue(Object statusObj) throws ReflectiveOperationException {
    if (statusObj == null) return 0;
    if (statusObj instanceof Integer code) return code;
    Method valueMethod = STATUS_VALUE.get(statusObj.getClass());
    Object value = valueMethod == null ? null : valueMethod.invoke(statusObj);
    return value instanceof Integer code ? code : 0;
  }

  private static Object exchangeAttribute(Object exchange, String key) {
    if (exchange == null || key == null) return null;
    try {
      Method[] methods = EXCHANGE_METHODS.get(exchange.getClass());
      if (methods[2] != null) return methods[2].invoke(exchange, key);
      if (methods[3] != null && methods[3].invoke(exchange) instanceof Map<?, ?> map) {
        return map.get(key);
      }
      return null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  @SuppressWarnings("unchecked")
  private static void putExchangeAttribute(Object exchange, String key, Object value) {
    if (exchange == null) return;
    try {
      Method getAttributes = EXCHANGE_METHODS.get(exchange.getClass())[3];
      if (getAttributes != null && getAttributes.invoke(exchange) instanceof Map<?, ?> rawMap) {
        ((Map<String, Object>) rawMap).put(key, value);
      }
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      unavailable();
    }
  }

  private static void cleanupExchangeAttribute(Object exchange) {
    if (exchange == null) return;
    try {
      Method getAttributes = EXCHANGE_METHODS.get(exchange.getClass())[3];
      if (getAttributes != null && getAttributes.invoke(exchange) instanceof Map<?, ?> rawMap) {
        rawMap.remove(EXCHANGE_SESSION_ATTR);
      }
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      // Cleanup never throws.
    }
  }

  private static Object serverRequestAttribute(Object serverRequest, String key) {
    if (serverRequest == null || key == null) return null;
    try {
      Method[] methods = SERVER_REQUEST_METHODS.get(serverRequest.getClass());
      if (methods[2] != null) {
        Object result = methods[2].invoke(serverRequest, key);
        if (result instanceof Optional<?> opt) return opt.orElse(null);
        return result;
      }
      if (methods[3] != null && methods[3].invoke(serverRequest) instanceof Map<?, ?> map) {
        return map.get(key);
      }
      return null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  private static Object serverRequestExchange(Object serverRequest) {
    if (serverRequest == null) return null;
    try {
      Method exchange = SERVER_REQUEST_METHODS.get(serverRequest.getClass())[4];
      return exchange == null ? null : exchange.invoke(serverRequest);
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  static void resetForTest() {
    OUTER_BOUNDARY.remove();
    OBSERVATION_UNAVAILABLE.set(false);
    INSTRUMENTATION_UNAVAILABLE.set(false);
  }
}
