package dev.xtrace.agent.bootstrap;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** Observes class-image-qualified Jersey 3.1.11 entry points on the launch path. */
public final class JerseyBridge {
  static final String SERVICE = "org.glassfish.jersey.servlet.ServletContainer.service";
  private static final String APPLY = "org.glassfish.jersey.server.model.ResourceMethodInvoker.apply";
  private static final AtomicBoolean OBSERVATION_UNAVAILABLE = new AtomicBoolean();
  private static final ThreadLocal<Service> ACTIVE = new ThreadLocal<>();

  private static final class Service {
    final ClassLoader loader;
    final Object request;
    final long started;
    int depth = 1;
    Object jerseyRequest;
    boolean excluded;
    boolean recorded;

    Service(ClassLoader loader, Object request, long started) {
      this.loader = loader;
      this.request = request;
      this.started = started;
    }
  }

  private JerseyBridge() {}

  /** Consume a fixed process-level coverage notice during shutdown, outside the request path. */
  public static boolean takeObservationUnavailable() {
    return OBSERVATION_UNAVAILABLE.getAndSet(false);
  }

  private static boolean unavailable() {
    OBSERVATION_UNAVAILABLE.set(true);
    return false;
  }

  /** The public generic ServletContainer.service body, not its parent or its HTTP overload. */
  public static Object serviceEnter(Class<?> type, Object request) {
    long started = System.nanoTime();
    ServletFilterBridge.downstreamEnter();
    Service active = ACTIVE.get();
    if (active != null) {
      active.depth++;
      active.excluded = true;
      if (active.recorded) SpringMvcBridge.jerseyOutcomeUncertain();
      return active;
    }
    Service owner = new Service(type.getClassLoader(), request, started);
    // Hold even an unqualified outer activation so a nested call cannot take it over.
    owner.excluded = !SpringMvcBridge.jerseyMayStart();
    if (!owner.excluded) {
      String dispatcher = request == null ? null : SpringMvcBridge.dispatchType(request);
      if (dispatcher == null) {
        owner.excluded = true;
        unavailable();
      } else if (!"REQUEST".equals(dispatcher)) {
        owner.excluded = true;
      } else {
        Boolean async = SpringMvcBridge.asyncState(request);
        owner.excluded = !Boolean.FALSE.equals(async);
        if (async == null) unavailable();
      }
    }
    ACTIVE.set(owner);
    return owner;
  }

  public static void serviceExit(Object token, Throwable thrown) {
    Service owner = ACTIVE.get();
    if (owner == null || owner != token || --owner.depth != 0) return;
    try {
      if (owner.recorded) {
        if (thrown != null) SpringMvcBridge.jerseyOutcomeUncertain();
        BootstrapBridge.frameExit(SERVICE, thrown);
      }
    } finally {
      ACTIVE.remove();
    }
  }

  /** Bind identities only while the pinned implementation initializes this servlet invocation's request. */
  public static void bindRequest(Class<?> type, Object jerseyRequest, Object servletRequest) {
    Service owner = ACTIVE.get();
    if (owner == null || owner.excluded) return;
    if (owner.request != servletRequest || owner.loader != type.getClassLoader()
        || jerseyRequest == null || owner.jerseyRequest != null) {
      owner.excluded = true;
      unavailable();
      if (owner.recorded) SpringMvcBridge.jerseyOutcomeUncertain();
      return;
    }
    owner.jerseyRequest = jerseyRequest;
  }

  /** A matched resource model is used only for scope admission. App probes own app entry. */
  public static boolean dispatchEnter(Object invoker, Object context) {
    Service owner = ACTIVE.get();
    if (owner == null || owner.excluded) return false;
    if (owner.jerseyRequest == null) return unavailable();
    if (owner.recorded) {
      SpringMvcBridge.jerseyOutcomeUncertain();
      return false;
    }
    if (!SpringMvcBridge.jerseyMayStart() || invoker.getClass().getClassLoader() != owner.loader) return false;
    try {
      ClassLoader loader = owner.loader;
      Object request = call(loader, "org.glassfish.jersey.server.internal.process.RequestProcessingContext",
          "request", context);
      if (request != owner.jerseyRequest) return unavailable();
      String model = "org.glassfish.jersey.server.model.ResourceMethodInvoker";
      Object resource = call(loader, model, "getResourceClass", invoker);
      Object selectedMethod = call(loader, model, "getResourceMethod", invoker);
      if (!(resource instanceof Class<?> type) || !(selectedMethod instanceof Method method)
          || !method.getDeclaringClass().isAssignableFrom(type)) return unavailable();
      if (BootstrapBridge.scopeOf(type) <= 0 || BootstrapBridge.scopeOf(method.getDeclaringClass()) <= 0) {
        return false;
      }
      String container = "org.glassfish.jersey.server.ContainerRequest";
      Object httpMethod = call(loader, container, "getMethod", request);
      if (!(httpMethod instanceof String verb) || !BootstrapBridge.validMethod(verb)
          || !verb.equals(SpringMvcBridge.httpMethod(owner.request))) return unavailable();
      Object info = call(loader, container, "getUriInfo", request);
      Object values = call(loader, "org.glassfish.jersey.server.ExtendedUriInfo", "getMatchedTemplates", info);
      if (!(values instanceof List<?> templates) || templates.isEmpty() || templates.size() > 16) return unavailable();
      String template = route(owner, templates);
      if (template == null) return unavailable();
      if (!BootstrapBridge.jerseyStart(verb, template, owner.started)) return false;
      owner.recorded = true;
      SpringMvcBridge.jerseyStarted();
      BootstrapBridge.frameEnter(APPLY);
      return true;
    } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
      return unavailable();
    }
  }

  public static void dispatchExit(Object response, Throwable thrown) {
    // Null on Jersey async/SSE dispatch. An escaped failure has no observed final response here.
    if (response == null || thrown != null) SpringMvcBridge.jerseyOutcomeUncertain();
    BootstrapBridge.frameExit(APPLY, thrown);
  }

  private static String route(Service owner, List<?> templates) throws ReflectiveOperationException {
    ClassLoader loader = owner.loader;
    Object context = call(loader, "jakarta.servlet.ServletRequest", "getServletContext", owner.request);
    Object deployed = call(loader, "jakarta.servlet.ServletContext", "getContextPath", context);
    String servletRequest = "jakarta.servlet.http.HttpServletRequest";
    Object effective = call(loader, servletRequest, "getContextPath", owner.request);
    // A context may have aliases. Only the deployed template supplies route text;
    // the request's context path is used exclusively as an equality check.
    if (!(deployed instanceof String prefix) || !prefix.equals(effective)) return null;
    Object mapping = call(loader, servletRequest, "getHttpServletMapping", owner.request);
    String api = "jakarta.servlet.http.HttpServletMapping";
    Object category = call(loader, api, "getMappingMatch", mapping);
    Object pattern = call(loader, api, "getPattern", mapping);
    if (!(category instanceof Enum<?> kind)
        || !kind.name().equals("PATH") || !(pattern instanceof String path) || !path.endsWith("/*")) return null;
    StringBuilder result = new StringBuilder();
    if (!append(result, prefix, false) || !append(result, path.substring(0, path.length() - 2), false)) return null;
    for (int index = templates.size() - 1; index >= 0; index--) {
      Object matched = call(loader, "org.glassfish.jersey.uri.UriTemplate", "getTemplate", templates.get(index));
      if (!(matched instanceof String part) || !append(result, part, true)) return null;
    }
    return result.isEmpty() ? "/" : result.toString();
  }

  private static boolean append(StringBuilder route, String part, boolean variables) {
    if (part.isEmpty() || part.equals("/")) return true;
    if (part.length() > 200 || part.contains("//")) return false;
    String pieces = part.startsWith("/") ? part.substring(1) : part;
    for (String piece : pieces.split("/", -1)) {
      if (!(piece.matches("[A-Za-z0-9_-]+") || (variables && piece.matches("\\{[A-Za-z_][A-Za-z0-9_]*}")))) return false;
      if (route.length() + piece.length() + 1 > 200) return false;
      route.append('/').append(piece);
    }
    return true;
  }

  private static Object call(ClassLoader loader, String api, String method, Object receiver)
      throws ReflectiveOperationException {
    Class<?> type = Class.forName(api, false, loader);
    Method getter = type.getMethod(method);
    return getter.invoke(type.cast(receiver));
  }
}
