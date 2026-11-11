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
  private static final ClassValue<Method> RESPONSE_STATUS =
      new ClassValue<>() {
        @Override
        protected Method computeValue(Class<?> type) {
          return publicMethod(type, "getStatus");
        }
      };
  private static final ClassValue<Method[]> HANDLER_METHODS =
      new ClassValue<>() {
        @Override
        protected Method[] computeValue(Class<?> type) {
          return new Method[] {publicMethod(type, "getBeanType")};
        }
      };

  // A nested forward/include can run after the outer handler deferred its root. Ownership is
  // assigned at root creation, not at deferral, and remains until that dispatch exits. A tree
  // with an already closed nested root must not record subsequent includes as new requests.
  private static final ThreadLocal<DispatchState> DISPATCH = new ThreadLocal<>();
  private static final ThreadLocal<ServletState> SERVLET = new ThreadLocal<>();

  private static final class ServletState {
    private int depth;
    private boolean recorded;
    private boolean errorPending;
    private boolean asyncStarted;
  }

  private static final class DispatchState {
    private int depth;
    private int ownerDepth;
    private boolean recorded;
  }

  private SpringMvcBridge() {}

  // Identity, rather than thread reuse, ties a deferral to the frame that observed it. Prefer
  // the outer servlet so post-dispatch filter work remains attributable until that frame exits.
  static Object captureBoundary() {
    ServletState servlet = SERVLET.get();
    return servlet != null ? servlet : DISPATCH.get();
  }

  static boolean boundaryActive(Object boundary) {
    return boundary != null && (boundary == SERVLET.get() || boundary == DISPATCH.get());
  }

  /** Brackets resolver work even when dispatch instrumentation is unavailable. */
  public static Object exceptionResolutionEnter() {
    return BootstrapBridge.exceptionResolutionEnter();
  }

  /** Enters a standard Filter.doFilter or Servlet.service frame on this thread. */
  public static void servletEnter() {
    ServletState state = SERVLET.get();
    if (state == null) {
      state = new ServletState();
      SERVLET.set(state);
    }
    state.depth++;
  }

  /** sendError may report committed before the container has rendered its error page. */
  public static void servletSendError() {
    ServletState state = SERVLET.get();
    if (state != null) state.errorPending = true;
  }

  /**
   * Closes after all post-chain filter work at the outermost standard servlet frame. A buffered
   * status is final on normal return unless sendError is pending. Escaping exceptions and
   * asynchronous processing leave only provisional evidence, regardless of commit state.
   */
  public static void servletEnd(Object request, Object response, Throwable thrown) {
    ServletState state = SERVLET.get();
    if (state == null) return;
    if (--state.depth != 0) return;
    try {
      if (state.recorded && BootstrapBridge.hasContext()) {
        if (state.asyncStarted || (request != null && asyncStarted(request))) {
          BootstrapBridge.provisionalRequestEnd(status(response), null);
        } else {
          finish(response, thrown, !state.errorPending && thrown == null);
        }
      }
    } finally {
      SERVLET.remove();
    }
  }

  private static void finish(Object response, Throwable thrown, boolean finalStatus) {
    if (finalStatus) BootstrapBridge.requestEnd(status(response), thrown);
    else BootstrapBridge.provisionalRequestEnd(status(response), thrown);
  }

  /** Called on entry to each {@code DispatcherServlet#doDispatch} on this thread. */
  public static void dispatchEnter() {
    DispatchState state = DISPATCH.get();
    if (state == null) {
      state = new DispatchState();
      DISPATCH.set(state);
    }
    state.depth++;
  }

  /**
   * Keeps dispatch ownership for nested rendering. An enclosing standard servlet frame owns
   * completion; without one, this seam can only report a provisional status.
   */
  public static void dispatchEnd(Object response, Throwable thrown) {
    DispatchState state = DISPATCH.get();
    if (state == null) return;
    try {
      if (SERVLET.get() == null && state.ownerDepth == state.depth
          && BootstrapBridge.awaitingResolution()) {
        finish(response, thrown, false);
      }
    } finally {
      if (state.ownerDepth == state.depth) state.ownerDepth = 0;
      if (--state.depth == 0) DISPATCH.remove();
    }
  }

  static void resetForTest() {
    DISPATCH.remove();
    SERVLET.remove();
  }

  /**
   * Opens the request root for a handler dispatch. Returns false (no recording) when the handler is
   * not application code, the request shape is not a clean method plus route template, or a root
   * is already open on this thread (nested or forwarded dispatch).
   */
  public static boolean start(Object request, Object handlerMethod) {
    DispatchState state = DISPATCH.get();
    ServletState servlet = SERVLET.get();
    if (request == null || handlerMethod == null || BootstrapBridge.inRequest()
        || (state != null && state.recorded) || (servlet != null && servlet.recorded)) return false;
    // ASYNC and container ERROR redispatches continue an existing HTTP request, not a new root.
    if (isContinuationDispatch(request)) return false;
    Class<?> beanType = beanType(handlerMethod);
    int scope = BootstrapBridge.scopeOf(beanType);
    if (scope == 0) return false;
    String httpMethod = httpMethod(request);
    if (httpMethod == null) return false;
    String template = bestMatchingPattern(request);
    // Without a matched pattern the template is unknown; a raw path is never substituted.
    if (template == null) return false;
    if (!BootstrapBridge.requestStart(httpMethod, template)) return false;
    if (servlet != null) servlet.recorded = true;
    if (state != null) {
      state.ownerDepth = state.depth;
      state.recorded = true;
    }
    if (scope < 0) BootstrapBridge.handlerUnresolved();
    return true;
  }

  /**
   * Defers completion to the enclosing servlet or dispatch frame when present.
   *
   * <p>When the handler threw, the container decides the final status later (an exception
   * resolver may map it to a 4xx), and the response object still carries its pre-error default.
   * The root therefore stays open through exception resolution and view rendering.
   */
  public static void end(Object response, Throwable thrown) {
    end(null, response, thrown);
  }

  /**
   * Defers to the outer servlet boundary, or the owning dispatcher when no servlet probe exists.
   * With neither probe, handler-return status is provisional.
   * If the handler started asynchronous processing (Callable, DeferredResult, reactive types),
   * the later status is not observed, so the root closes UNOBSERVED with no status.
   */
  public static void end(Object request, Object response, Throwable thrown) {
    if (thrown == null && request != null && asyncStarted(request)) {
      ServletState servlet = SERVLET.get();
      if (servlet != null) {
        servlet.asyncStarted = true;
        BootstrapBridge.deferRequestEnd(null);
        return;
      }
      BootstrapBridge.requestEnd(0, (Throwable) null);
      return;
    }
    if (thrown != null) {
      if (!BootstrapBridge.deferRequestEnd(thrown)) BootstrapBridge.requestEnd(0, thrown);
      return;
    }
    // A normal handler return proves earlier frame throws were handled. Keep the root until
    // the outer servlet exits; another thread's boundary must never cause deferral here.
    DispatchState state = DISPATCH.get();
    if ((SERVLET.get() != null || (state != null && state.ownerDepth == state.depth))
        && BootstrapBridge.deferRequestEnd(null)) return;
    finish(response, null, false);
  }

  /**
   * Observes exception resolution at {@code DispatcherServlet#processHandlerException}. With
   * dispatch advice, even a failing resolver must wait for its owning dispatch to exit. Without
   * it, this seam observes the resolver's status, not a later rendered view or filter response.
   */
  public static void exceptionResolved(Object response, Object resolved, Throwable thrown) {
    finishExceptionResolution(response, resolved, thrown);
  }

  /** Completes only the context observed on entry, then retires that resolver's attribution. */
  public static void exceptionResolved(Object response, Object resolved, Throwable thrown, Object boundary) {
    try {
      if (BootstrapBridge.resolving(boundary)) finishExceptionResolution(response, resolved, thrown);
    } finally {
      BootstrapBridge.exceptionResolutionEnd(boundary);
    }
  }

  private static void finishExceptionResolution(Object response, Object resolved, Throwable thrown) {
    if (!BootstrapBridge.awaitingResolution()) return;
    DispatchState state = DISPATCH.get();
    if (state != null) {
      if (state.ownerDepth == state.depth && thrown == null && resolved != null) {
        BootstrapBridge.deferRequestEnd(null);
      }
      return;
    }
    if (SERVLET.get() != null) {
      if (thrown == null && resolved != null) BootstrapBridge.deferRequestEnd(null);
      return;
    }
    if (thrown != null) {
      finish(response, thrown, false);
    } else if (resolved != null) {
      finish(response, null, false);
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

  static boolean isContinuationDispatch(Object request) {
    try {
      Method method = REQUEST_METHODS.get(request.getClass())[3];
      Object value = method == null ? null : method.invoke(request);
      return value instanceof Enum<?> kind
          && (kind.name().equals("ASYNC") || kind.name().equals("ERROR"));
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
      Method method = RESPONSE_STATUS.get(response.getClass());
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
