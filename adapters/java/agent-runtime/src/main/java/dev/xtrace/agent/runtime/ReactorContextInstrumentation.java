package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isBridge;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import dev.xtrace.agent.bootstrap.ReactorContextBridge;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.Manifest;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.JavaModule;

/**
 * Installs Reactor subscriber, publisher, and scheduler context-propagation hooks with fail-closed
 * version/signature guards and strict fault isolation.
 */
final class ReactorContextInstrumentation {
  static final String CONTEXT_VIEW = "reactor.util.context.ContextView";
  static final String CONTEXT = "reactor.util.context.Context";
  static final String CORE_SUBSCRIBER = "reactor.core.CoreSubscriber";
  static final String CORE_PUBLISHER = "reactor.core.CorePublisher";
  static final String MONO = "reactor.core.publisher.Mono";
  static final String SCHEDULER = "reactor.core.scheduler.Scheduler";
  static final String SCHEDULER_WORKER = "reactor.core.scheduler.Scheduler$Worker";
  static final String RS_SUBSCRIPTION = "org.reactivestreams.Subscription";

  enum VersionStatus {
    NO_JAR,
    SUPPORTED,
    UNSUPPORTED
  }

  private static final AtomicBoolean UNQUALIFIED = new AtomicBoolean();
  private static final AtomicBoolean PROBE_UNAVAILABLE = new AtomicBoolean();
  private static final Map<ClassLoader, Boolean> CONTRACT_CACHE =
      Collections.synchronizedMap(new WeakHashMap<>());

  private ReactorContextInstrumentation() {}

  static void install(Instrumentation instrumentation, Runnable onLimitation, boolean attach) {
    FailureListener listener = new FailureListener(onLimitation);
    configure(new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(attach ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
                : AgentBuilder.RedefinitionStrategy.DISABLED)
            .ignore(nameStartsWith("java.").or(nameStartsWith("jdk."))
                .or(nameStartsWith("sun.")).or(nameStartsWith("dev.xtrace.agent."))
                .or(nameStartsWith("net.bytebuddy.")))
            .assureReadEdgeFromAndTo(instrumentation, ReactorContextBridge.class)
            .with(listener),
        listener,
        null)
        .installOn(instrumentation);
  }

  /** Builds the Reactor AgentBuilder configuration; {@code poolOverride} is test-only. */
  static AgentBuilder configure(
      AgentBuilder builder, FailureListener listener, TypePool poolOverride) {
    AgentBuilder.RawMatcher guardedSubscriber = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(CORE_SUBSCRIBER)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher guardedPublisher = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(CORE_PUBLISHER)).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    AgentBuilder.RawMatcher guardedScheduler = listener.selected(
        (type, loader, module, redefined, domain) ->
            !type.isInterface()
                && !type.isEnum()
                && hasSuperType(named(SCHEDULER).or(named(SCHEDULER_WORKER))).matches(type)
                && qualifies(type.getName(), loader, domain, poolOverride));
    return builder
        .type(guardedSubscriber)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(SubscriberAdvice.class).on(subscriberMethods())))
        .type(guardedPublisher)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(PublisherAdvice.class).on(publisherSubscribeMethods())))
        .type(guardedScheduler)
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(SchedulerAdvice.class).on(schedulerScheduleMethods())));
  }

  static ElementMatcher.Junction<MethodDescription> subscriberMethods() {
    return isMethod()
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(isBridge()))
        .and(not(isSynthetic()))
        .and(
            named("onSubscribe").and(takesArguments(1)).and(takesArgument(0, named(RS_SUBSCRIPTION)))
                .or(named("onNext").and(takesArguments(1)))
                .or(named("onError").and(takesArguments(1)).and(takesArgument(0, Throwable.class)))
                .or(named("onComplete").and(takesArguments(0)))
                .or(named("request").and(takesArguments(1)).and(takesArgument(0, long.class)))
                .or(named("cancel").and(takesArguments(0))));
  }

  static ElementMatcher.Junction<MethodDescription> publisherSubscribeMethods() {
    return isMethod()
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(isBridge()))
        .and(not(isSynthetic()))
        .and(named("subscribe").and(takesArguments(1)).and(takesArgument(0, named(CORE_SUBSCRIBER))));
  }

  static ElementMatcher.Junction<MethodDescription> schedulerScheduleMethods() {
    return isMethod()
        .and(not(isAbstract()))
        .and(not(isNative()))
        .and(not(isBridge()))
        .and(not(isSynthetic()))
        .and(named("schedule").or(named("schedulePeriodically")))
        .and(takesArgument(0, Runnable.class));
  }

  private static boolean qualifies(
      String typeName, ClassLoader loader, ProtectionDomain domain, TypePool poolOverride) {
    if (!bootstrapVisible(loader, ReactorContextBridge.class)) {
      markDegraded(true);
      return false;
    }
    boolean reactorFrameworkClass = typeName != null && typeName.startsWith("reactor.");
    if (reactorFrameworkClass && checkJarVersion(domain, 3, 4, 4) == VersionStatus.UNSUPPORTED) {
      markUnqualified();
      return false;
    }
    if (checkResourceJarVersion(loader, "reactor/core/publisher/Mono.class", 3, 4, 4)
        == VersionStatus.UNSUPPORTED) {
      markUnqualified();
      return false;
    }
    if (poolOverride != null) {
      if (!supportsReactorContract(poolOverride)) {
        markUnqualified();
        return false;
      }
      return true;
    }
    if (!supportsReactorContract(loader)) {
      markUnqualified();
      return false;
    }
    return true;
  }

  static VersionStatus checkResourceJarVersion(
      ClassLoader loader,
      String classResource,
      int minMajor,
      int minMinor,
      int maxMajorExclusive) {
    if (loader == null || classResource == null) return VersionStatus.NO_JAR;
    URL resource = loader.getResource(classResource);
    if (resource == null || !"jar".equals(resource.getProtocol())) return VersionStatus.NO_JAR;
    String spec = resource.toExternalForm();
    int sep = spec.lastIndexOf("!/");
    if (sep <= 0) return VersionStatus.UNSUPPORTED;
    try {
      URL manifestUrl = new URL(spec.substring(0, sep + 2) + "META-INF/MANIFEST.MF");
      return readManifestVersionStatus(manifestUrl, minMajor, minMinor, maxMajorExclusive);
    } catch (IOException | RuntimeException ignored) {
      return VersionStatus.UNSUPPORTED;
    }
  }

  static void markUnqualified() {
    UNQUALIFIED.set(true);
    ReactorContextBridge.reportPropagationUnavailable();
  }

  static void markDegraded(boolean unavailable) {
    if (unavailable) PROBE_UNAVAILABLE.set(true);
    ReactorContextBridge.reportPropagationUnavailable();
  }

  static boolean bootstrapVisible(ClassLoader loader, Class<?> bridgeClass) {
    if (loader == null) return false;
    try {
      return Class.forName(bridgeClass.getName(), false, loader) == bridgeClass;
    } catch (ClassNotFoundException | LinkageError unavailable) {
      return false;
    }
  }

  static boolean supportsReactorContract(ClassLoader loader) {
    if (loader == null) return false;
    Boolean cached = CONTRACT_CACHE.get(loader);
    if (cached != null) return cached;
    TypePool pool = TypePool.Default.of(loader);
    boolean ok = supportsReactorContract(pool);
    CONTRACT_CACHE.put(loader, ok);
    return ok;
  }

  static boolean supportsReactorContract(TypePool pool) {
    if (pool == null) return false;
    return hasMethod(pool, CONTEXT_VIEW, "hasKey", "(Ljava/lang/Object;)Z")
        && hasMethod(pool, CONTEXT_VIEW, "get", "(Ljava/lang/Object;)Ljava/lang/Object;")
        && hasMethod(pool, CONTEXT, "put",
            "(Ljava/lang/Object;Ljava/lang/Object;)Lreactor/util/context/Context;")
        && hasMethod(pool, CORE_SUBSCRIBER, "currentContext",
            "()Lreactor/util/context/Context;")
        && hasMethod(pool, CORE_PUBLISHER, "subscribe",
            "(Lreactor/core/CoreSubscriber;)V")
        && hasMethod(pool, MONO, "contextWrite",
            "(Ljava/util/function/Function;)Lreactor/core/publisher/Mono;")
        && hasMethod(pool, MONO, "doOnSuccess",
            "(Ljava/util/function/Consumer;)Lreactor/core/publisher/Mono;")
        && hasMethod(pool, MONO, "doOnError",
            "(Ljava/util/function/Consumer;)Lreactor/core/publisher/Mono;")
        && hasMethod(pool, MONO, "doOnCancel",
            "(Ljava/lang/Runnable;)Lreactor/core/publisher/Mono;");
  }

  static boolean hasMethod(
      TypePool pool, String typeName, String methodName, String descriptorPrefix) {
    TypePool.Resolution res = pool.describe(typeName);
    if (!res.isResolved()) return false;
    TypeDescription type = res.resolve();
    for (MethodDescription.InDefinedShape method : type.getDeclaredMethods()) {
      if (method.getInternalName().equals(methodName)
          && method.getDescriptor().startsWith(descriptorPrefix)) {
        return true;
      }
    }
    return false;
  }

  static VersionStatus checkJarVersion(
      ProtectionDomain domain, int minMajor, int minMinor, int maxMajorExclusive) {
    if (domain == null || domain.getCodeSource() == null) return VersionStatus.NO_JAR;
    URL source = domain.getCodeSource().getLocation();
    if (source == null || !source.getHost().isEmpty()) return VersionStatus.NO_JAR;
    String location = source.toExternalForm();
    URL manifestUrl;
    try {
      if ("file".equals(source.getProtocol()) && location.endsWith(".jar")) {
        manifestUrl = new URL("jar:" + location + "!/META-INF/MANIFEST.MF");
      } else if ("jar".equals(source.getProtocol())
          && location.startsWith("jar:nested:/")
          && !location.startsWith("jar:nested://")
          && location.endsWith(".jar!/")) {
        manifestUrl = new URL(source, "META-INF/MANIFEST.MF");
      } else {
        return VersionStatus.NO_JAR;
      }
      return readManifestVersionStatus(manifestUrl, minMajor, minMinor, maxMajorExclusive);
    } catch (IOException | RuntimeException ignored) {
      return VersionStatus.UNSUPPORTED;
    }
  }

  private static VersionStatus readManifestVersionStatus(
      URL manifestUrl, int minMajor, int minMinor, int maxMajorExclusive) throws IOException {
    if (manifestUrl == null) return VersionStatus.UNSUPPORTED;
    try (InputStream stream = manifestUrl.openStream()) {
      byte[] data = stream.readNBytes(128 * 1024 + 1);
      if (data.length > 128 * 1024) return VersionStatus.UNSUPPORTED;
      var attrs = new Manifest(new ByteArrayInputStream(data)).getMainAttributes();
      String version = attrs.getValue("Implementation-Version");
      if (version == null || version.isBlank()) version = attrs.getValue("Bundle-Version");
      return isSupportedVersion(version, minMajor, minMinor, maxMajorExclusive)
          ? VersionStatus.SUPPORTED : VersionStatus.UNSUPPORTED;
    }
  }

  /**
   * Parses major.minor version prefix and rejects missing, malformed, or out-of-range versions fail
   * closed.
   */
  static boolean isSupportedVersion(
      String version, int minMajor, int minMinor, int maxMajorExclusive) {
    if (version == null || version.isBlank()) return false;
    String trimmed = version.trim();
    int firstDot = trimmed.indexOf('.');
    if (firstDot <= 0) return false;
    int major = parseLeadingInt(trimmed.substring(0, firstDot));
    if (major < 0) return false;
    String rest = trimmed.substring(firstDot + 1);
    int secondSep = -1;
    for (int i = 0; i < rest.length(); i++) {
      char c = rest.charAt(i);
      if (c < '0' || c > '9') {
        secondSep = i;
        break;
      }
    }
    String minorPart = secondSep < 0 ? rest : rest.substring(0, secondSep);
    int minor = parseLeadingInt(minorPart);
    if (minor < 0) return false;
    if (major >= maxMajorExclusive) return false;
    if (major > minMajor) return true;
    return major == minMajor && minor >= minMinor;
  }

  private static int parseLeadingInt(String digits) {
    if (digits == null || digits.isEmpty() || digits.length() > 6) return -1;
    for (int i = 0; i < digits.length(); i++) {
      char c = digits.charAt(i);
      if (c < '0' || c > '9') return -1;
    }
    try {
      return Integer.parseInt(digits);
    } catch (NumberFormatException ignored) {
      return -1;
    }
  }

  static void reportCoverageAtShutdown() {
    if (UNQUALIFIED.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Reactor library version or contract did not qualify for async propagation\"}");
    }
    if (PROBE_UNAVAILABLE.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Reactor context propagation probe installation unavailable\"}");
    }
  }

  static void resetForTest() {
    UNQUALIFIED.set(false);
    PROBE_UNAVAILABLE.set(false);
    CONTRACT_CACHE.clear();
  }

  static final class FailureListener extends AgentBuilder.Listener.Adapter {
    private record Candidate(String name, ClassLoader loader) {
      @Override
      public boolean equals(Object other) {
        return other instanceof Candidate c && name.equals(c.name) && loader == c.loader;
      }

      @Override
      public int hashCode() {
        return 31 * name.hashCode() + System.identityHashCode(loader);
      }
    }

    private final Runnable onDegraded;
    private final Runnable onLimitation;
    private final ConcurrentHashMap<Candidate, Boolean> selected = new ConcurrentHashMap<>();

    FailureListener(Runnable onLimitation) {
      this(() -> markDegraded(true), onLimitation);
    }

    FailureListener(Runnable onDegraded, Runnable onLimitation) {
      this.onDegraded = onDegraded == null ? () -> {} : onDegraded;
      this.onLimitation = onLimitation == null ? () -> {} : onLimitation;
    }

    AgentBuilder.RawMatcher selected(AgentBuilder.RawMatcher delegate) {
      return (type, loader, module, redefined, domain) -> {
        if (!delegate.matches(type, loader, module, redefined, domain)) return false;
        selected.put(new Candidate(type.getName(), loader), Boolean.TRUE);
        return true;
      };
    }

    @Override
    public void onError(
        String name, ClassLoader loader, JavaModule module, boolean loaded, Throwable error) {
      if (selected.remove(new Candidate(name, loader)) == null) return;
      onDegraded.run();
      try {
        onLimitation.run();
      } catch (Throwable ignored) {
        // Limitation reporting must never escape classloading.
      }
    }

    @Override
    public void onComplete(String name, ClassLoader loader, JavaModule module, boolean loaded) {
      selected.remove(new Candidate(name, loader));
    }
  }

  public static final class SubscriberAdvice {
    private SubscriberAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.This Object subscriber) {
      return ReactorContextBridge.subscriberEnter(subscriber);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Object scope) {
      ReactorContextBridge.exitScope(scope);
    }
  }

  public static final class PublisherAdvice {
    private PublisherAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.Argument(0) Object subscriber) {
      return ReactorContextBridge.subscriberEnter(subscriber);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Object scope) {
      ReactorContextBridge.exitScope(scope);
    }
  }

  public static final class SchedulerAdvice {
    private SchedulerAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(value = 0, readOnly = false) Runnable task) {
      task = ReactorContextBridge.wrapRunnable(task);
    }
  }
}
