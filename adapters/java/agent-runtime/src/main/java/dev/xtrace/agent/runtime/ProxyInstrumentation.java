package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.*;

import dev.xtrace.agent.bootstrap.ProxyBridge;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.utility.JavaModule;

/** Instruments each generated JDK proxy class once, including proxies backed by hidden handlers. */
final class ProxyInstrumentation {
  private static final Pattern PROXY_NAME = Pattern.compile("(?:.*\\.)?\\$Proxy[0-9]+");

  private ProxyInstrumentation() {}

  static ElementMatcher.Junction<TypeDescription> proxies() {
    // JDK proxies always have this generated simple name, including package-private contracts.
    // Reject other classes before resolving hierarchies that may exist only in memory.
    return nameMatches(PROXY_NAME.pattern()).and(hasSuperType(named("java.lang.reflect.Proxy")))
        .and(not(isInterface()));
  }

  static ElementMatcher.Junction<MethodDescription> invocations() {
    return isMethod().and(not(isStatic())).and(not(isAbstract())).and(not(isNative()));
  }

  static void install(Instrumentation instrumentation, Runnable onFailure, boolean attach) {
    install(instrumentation, error -> onFailure.run(), attach);
  }

  static void install(Instrumentation instrumentation, Consumer<Throwable> onFailure, boolean attach) {
    // A JDK proxy implements erased JVM descriptors, including covariant bridge variants.
    // A Java generic method graph can hide one of those concrete proxy methods.
    new AgentBuilder.Default(new net.bytebuddy.ByteBuddy().with(
        net.bytebuddy.dynamic.scaffold.MethodGraph.Compiler.ForDeclaredMethods.INSTANCE))
        .disableClassFormatChanges()
        .with(attach ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
            : AgentBuilder.RedefinitionStrategy.DISABLED)
        .ignore(nameStartsWith("dev.xtrace.agent.").or(nameStartsWith("net.bytebuddy.")))
        .assureReadEdgeFromAndTo(instrumentation, ProxyBridge.class)
        .with(new FailureListener(onFailure))
        .type(proxies())
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(ProxyAdvice.class).on(invocations())))
        .installOn(instrumentation);
  }

  static final class FailureListener extends AgentBuilder.Listener.Adapter {
    private final Consumer<Throwable> onFailure;

    FailureListener(Consumer<Throwable> onFailure) {
      this.onFailure = java.util.Objects.requireNonNull(onFailure);
    }

    @Override
    public void onTransformation(TypeDescription type, ClassLoader loader, JavaModule module,
        boolean loaded, net.bytebuddy.dynamic.DynamicType dynamicType) {
      ProxyDiagnostics.report(type.getName(), null, null, "transformed");
    }

    @Override
    public void onError(String name, ClassLoader loader, JavaModule module,
        boolean loaded, Throwable error) {
      if (!PROXY_NAME.matcher(name).matches()) return;
      ProxyDiagnostics.report(name, null, null, "transform_failed");
      try {
        onFailure.accept(error);
      } catch (RuntimeException | LinkageError ignored) {
        // The application must still be able to load the class after capture has failed.
      }
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"proxy boundary instrumentation failed; application continues\"}");
    }
  }

  public static final class ProxyAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ProxyBridge.Call enter(@Advice.This Object proxy,
        @Advice.Origin Method method, @Advice.AllArguments Object[] arguments) {
      // Advice resolves these arguments at their load sites, after this idle fast path.
      if (!dev.xtrace.agent.bootstrap.BootstrapBridge.hasContext()) return null;
      return ProxyBridge.enter(proxy, method, arguments);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter ProxyBridge.Call call,
        @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable thrown) {
      if (call != null) ProxyBridge.exit(call, result, thrown);
    }
  }
}
