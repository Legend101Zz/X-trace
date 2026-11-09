package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * JDK-only request-root helper for Spring MVC. Spring and servlet types are reached only through
 * reflection on public API methods, so one agent build serves javax and jakarta containers and
 * every Spring version that has {@code RequestMappingHandlerAdapter#handleInternal}.
 *
 * <p>It records nothing itself: it derives a sanitized method and route template (never a path,
 * query or header) and delegates to {@link BootstrapBridge}.
 */
public final class SpringMvcBridge {
  /** Request attribute set by Spring's handler mapping with the matched pattern. */
  static final String BEST_MATCHING_PATTERN =
      "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern";

  private static final ClassValue<Method[]> REQUEST_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {
            publicMethod(type, "getMethod"),
            publicMethod(type, "getAttribute", String.class),
            publicMethod(type, "isAsyncStarted"),
            publicMethod(type, "getDispatcherType")
          };
        }
      };
  private static final ClassValue<Method[]> RESPONSE_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {publicMethod(type, "getStatus")};
        }
      };
  private static final ClassValue<Method[]> HANDLER_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {publicMethod(type, "getBeanType")};
        }
      };

  /**
   * Set once {@code DispatcherServlet#doDispatch} has been observed running. From then on the
   * response status is read when the dispatch ends, not when the handler returns: a redirect,
   * an error view or a mapped exception only sets its real status while the view is rendered,
   * after the handler adapter has returned.
   */
  private static volatile boolean dispatchObserved;

  private SpringMvcBridge() {}

  /** Called as {@code DispatcherServlet#doDispatch} begins; marks the dispatch hook as live. */
  public static void dispatchEnter() {
    dispatchObserved = true;
  }

  /**
   * Closes a request root that was kept open past the handler adapter. A dispatch that threw
   * propagates the exception (the container decides the status later, so none is claimed);
   * otherwise the response status after view rendering is the observed outcome.
   */
  public static void dispatchEnd(Object response, Throwable thrown) {
    if (!BootstrapBridge.awaitingResolution()) return;
    if (thrown != null) {
      BootstrapBridge.requestEnd(0, thrown);
    } else {
      BootstrapBridge.requestEnd(status(response), (Throwable) null);
    }
  }

  static void resetForTest() {
    dispatchObserved = false;
  }

  /**
   * Opens the request root for a handler dispatch. Returns false (no recording) when the handler is
   * not application code, the request shape is not a clean method plus route template, or a root
   * is already open on this thread (nested or forwarded dispatch).
   */
  public static boolean start(Object request, Object handlerMethod) {
    if (request == null || handlerMethod == null || BootstrapBridge.inRequest()) return false;
    // The ASYNC re-dispatch of a request already opened (and closed UNOBSERVED) is not a new root.
    if (isAsyncDispatch(request)) return false;
    Class<?> beanType = beanType(handlerMethod);
    int scope = BootstrapBridge.scopeOf(beanType);
    if (scope == 0) return false;
    String httpMethod = httpMethod(request);
    if (httpMethod == null) return false;
    String template = bestMatchingPattern(request);
    // Without a matched pattern the template is unknown; a raw path is never substituted.
    if (template == null) return false;
    if (!BootstrapBridge.requestStart(httpMethod, template)) return false;
    if (scope < 0) BootstrapBridge.handlerUnresolved();
    return true;
  }

  /**
   * Closes the request root with the response status, or 0 when the status is not observable.
   *
   * <p>When the handler threw, the container decides the final status later (an exception
   * resolver may map it to a 4xx), and the response object still carries its pre-error default.
   * The root therefore stays open until {@link #exceptionResolved} reports the outcome.
   */
  public static void end(Object response, Throwable thrown) {
    end(null, response, thrown);
  }

  /**
   * Closes the request root. RESPONDED means the status the response carried when the handler
   * returned. If the handler started asynchronous processing (Callable, DeferredResult, reactive
   * types) the real status is not known at return, so the root closes UNOBSERVED with no status.
   */
  public static void end(Object request, Object response, Throwable thrown) {
    if (thrown == null && request != null && asyncStarted(request)) {
      BootstrapBridge.requestEnd(0, (Throwable) null);
      return;
    }
    if (thrown != null) {
      if (!BootstrapBridge.deferRequestEnd(thrown)) BootstrapBridge.requestEnd(0, thrown);
      return;
    }
    // The handler returned. The status may still change while the view renders (redirects), so
    // once the dispatch hook is live the root stays open until the dispatch ends.
    if (dispatchObserved && BootstrapBridge.deferRequestEnd(null)) return;
    BootstrapBridge.requestEnd(status(response), (Throwable) null);
  }

  /**
   * Reports the end of {@code DispatcherServlet#processHandlerException}. A resolver that returned
   * a result mapped the exception to a response, so the observed status is reported as RESPONDED;
   * an unresolved exception (the method threw) is propagated with no status observed.
   */
  public static void exceptionResolved(Object response, Object resolved, Throwable thrown) {
    if (!BootstrapBridge.awaitingResolution()) return;
    if (thrown != null) {
      BootstrapBridge.requestEnd(0, thrown);
    } else if (resolved != null) {
      // A resolver produced a view or a status; a view renders after this call returns.
      if (dispatchObserved) return;
      BootstrapBridge.requestEnd(status(response), (Throwable) null);
    } else {
      BootstrapBridge.requestEnd(0, (Throwable) null);
    }
  }

  static boolean asyncStarted(Object request) {
    try {
      Method method = REQUEST_METHODS.get(request.getClass())[2];
      return method != null && Boolean.TRUE.equals(method.invoke(request));
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return false;
    }
  }

  static boolean isAsyncDispatch(Object request) {
    try {
      Method method = REQUEST_METHODS.get(request.getClass())[3];
      Object value = method == null ? null : method.invoke(request);
      return value instanceof Enum<?> kind && kind.name().equals("ASYNC");
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return false;
    }
  }

  static Class<?> beanType(Object handlerMethod) {
    try {
      Method method = HANDLER_METHODS.get(handlerMethod.getClass())[0];
      Object value = method == null ? null : method.invoke(handlerMethod);
      return value instanceof Class<?> type ? type : null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  static String httpMethod(Object request) {
    try {
      Method method = REQUEST_METHODS.get(request.getClass())[0];
      Object value = method == null ? null : method.invoke(request);
      return value instanceof String text ? text : null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  static String bestMatchingPattern(Object request) {
    try {
      Method method = REQUEST_METHODS.get(request.getClass())[1];
      Object value = method == null ? null : method.invoke(request, BEST_MATCHING_PATTERN);
      return value instanceof String text ? text : null;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return null;
    }
  }

  static int status(Object response) {
    if (response == null) return 0;
    try {
      Method method = RESPONSE_METHODS.get(response.getClass())[0];
      Object value = method == null ? null : method.invoke(response);
      return value instanceof Integer status ? status : 0;
    } catch (ReflectiveOperationException | RuntimeException ignored) {
      return 0;
    }
  }

  /** Finds a public method callable through a public declaring type, or null. */
  static Method publicMethod(Class<?> type, String name, Class<?>... parameters) {
    for (Class<?> current = type; current != null; current = current.getSuperclass()) {
      Method found = declaredPublic(current, name, parameters);
      if (found != null) return found;
      Method viaInterface = viaInterfaces(current, name, parameters);
      if (viaInterface != null) return viaInterface;
    }
    return null;
  }

  private static Method viaInterfaces(Class<?> type, String name, Class<?>[] parameters) {
    for (Class<?> candidate : type.getInterfaces()) {
      Method found = declaredPublic(candidate, name, parameters);
      if (found != null) return found;
      found = viaInterfaces(candidate, name, parameters);
      if (found != null) return found;
    }
    return null;
  }

  private static Method declaredPublic(Class<?> type, String name, Class<?>[] parameters) {
    if (!Modifier.isPublic(type.getModifiers())) return null;
    try {
      Method method = type.getMethod(name, parameters);
      return Modifier.isPublic(method.getDeclaringClass().getModifiers()) ? method : null;
    } catch (NoSuchMethodException | SecurityException ignored) {
      return null;
    }
  }
}
