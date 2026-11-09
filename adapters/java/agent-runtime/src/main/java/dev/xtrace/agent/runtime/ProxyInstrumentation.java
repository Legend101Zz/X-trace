package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.*;

import dev.xtrace.agent.bootstrap.ProxyBridge;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.utility.JavaModule;

/** Instruments each generated JDK proxy class once, including proxies backed by hidden handlers. */
final class ProxyInstrumentation {
  private ProxyInstrumentation() {}

  static ElementMatcher.Junction<TypeDescription> proxies() {
    return hasSuperType(named("java.lang.reflect.Proxy"))
        .and(not(named("java.lang.reflect.Proxy"))).and(not(isInterface()));
  }

  static ElementMatcher.Junction<MethodDescription> invocations() {
    return isMethod().and(not(isStatic())).and(not(isAbstract())).and(not(isNative()));
  }

  static void install(Instrumentation instrumentation, Runnable onFailure, boolean attach) {
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .with(attach ? AgentBuilder.RedefinitionStrategy.RETRANSFORMATION
            : AgentBuilder.RedefinitionStrategy.DISABLED)
        .ignore(nameStartsWith("dev.xtrace.agent.").or(nameStartsWith("net.bytebuddy.")))
        .assureReadEdgeFromAndTo(instrumentation, ProxyBridge.class)
        .with(new AgentBuilder.Listener.Adapter() {
          @Override
          public void onError(String name, ClassLoader loader, JavaModule module,
              boolean loaded, Throwable error) {
            onFailure.run();
          }
        })
        .type(proxies())
        .transform((target, type, loader, module, domain) ->
            target.visit(Advice.to(ProxyAdvice.class).on(invocations())))
        .installOn(instrumentation);
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
