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
            publicMethod(type, "getMethod"), publicMethod(type, "getAttribute", String.class)
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

  private SpringMvcBridge() {}

  /**
   * Opens the request root for a handler dispatch. Returns false (no recording) when the handler is
   * not application code, the request shape is not a clean method plus route template, or a root
   * is already open on this thread (nested or forwarded dispatch).
   */
  public static boolean start(Object request, Object handlerMethod) {
    if (request == null || handlerMethod == null || BootstrapBridge.inRequest()) return false;
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

  /** Closes the request root with the response status, or 0 when the status is not observable. */
  public static void end(Object response, Throwable thrown) {
    // A handler exception means the container, not this method, decides the final status; the
    // response object still carries its pre-error default, so it must not be reported.
    int status = thrown != null ? 0 : status(response);
    BootstrapBridge.requestEnd(status, thrown != null);
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
