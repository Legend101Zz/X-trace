package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.named;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.StubMethod;
import org.junit.jupiter.api.Test;

class ServletBoundaryInstrumentationTest {
  @Test
  void unrelatedUnresolvableHierarchyDoesNotStopCapture() throws Exception {
    var parent = new ByteBuddy().subclass(Object.class).name("demo.MissingParent").make();
    var child = new ByteBuddy().subclass(parent.getTypeDescription())
        .name("demo.Unrelated").make();
    AtomicInteger failures = new AtomicInteger();
    AtomicInteger analysisErrors = new AtomicInteger();
    var listener = new ServletBoundaryInstrumentation.FailureListener(failures::incrementAndGet);
    var locator = new ClassFileLocator.Compound(
        ClassFileLocator.Simple.of("demo.Unrelated", child.getBytes()),
        ClassFileLocator.ForClassLoader.ofPlatformLoader());
    var transformer = new AgentBuilder.Default()
        .with(new AgentBuilder.LocationStrategy.Simple(locator))
        .with(listener)
        .with(new AgentBuilder.Listener.Adapter() {
          @Override
          public void onError(String name, ClassLoader loader,
              net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable error) {
            analysisErrors.incrementAndGet();
          }
        })
        .type(listener.selected(hasSuperType(named("jakarta.servlet.Filter"))))
        .transform((target, type, loader, module, domain) -> target)
        .makeRaw();
    transformer.transform(getClass().getClassLoader(), "demo/Unrelated", null, null,
        child.getBytes());
    assertEquals(1, analysisErrors.get(), "the missing parent must actually fail analysis");
    assertEquals(0, failures.get());
  }

  @Test
  void selectedBoundaryTransformationFailuresStillStopCapture() throws Exception {
    for (String api : List.of("jakarta.servlet", "javax.servlet")) {
      for (String boundary : List.of("Filter", "Servlet", "http.HttpServletResponse")) {
        var contract = new ByteBuddy().makeInterface().name(api + "." + boundary).make();
        var implementation = new ByteBuddy().subclass(Object.class)
            .name("demo.Boundary").implement(contract.getTypeDescription()).make();
        AtomicInteger failures = new AtomicInteger();
        var listener = new ServletBoundaryInstrumentation.FailureListener(failures::incrementAndGet);
        var locator = new ClassFileLocator.Compound(new ClassFileLocator.Simple(Map.of(
            contract.getTypeDescription().getName(), contract.getBytes(),
            "demo.Boundary", implementation.getBytes())),
            ClassFileLocator.ForClassLoader.ofPlatformLoader());
        var transformer = new AgentBuilder.Default()
            .with(new AgentBuilder.LocationStrategy.Simple(locator))
            .with(listener)
            .type(listener.selected(hasSuperType(named(contract.getTypeDescription().getName()))))
            .transform((target, type, loader, module, domain) -> {
              throw new IllegalStateException("boundary transformation failed");
            })
            .makeRaw();
        assertDoesNotThrow(() -> transformer.transform(getClass().getClassLoader(),
            "demo/Boundary", null, null, implementation.getBytes()));
        assertEquals(1, failures.get(), api + "." + boundary);
        listener.onError("demo.Boundary", getClass().getClassLoader(), null, false,
            new IllegalStateException("later unrelated analysis"));
        assertEquals(1, failures.get(), "a completed attempt must not retain selection");
      }
    }
  }

  @Test
  void selectionIsScopedToLoaderAndAttemptAndContainsCallbackFailures() {
    ClassLoader loader = getClass().getClassLoader();
    ClassLoader otherLoader = new ClassLoader(loader) {};
    TypeDescription type = TypeDescription.ForLoadedType.of(Object.class);
    AtomicInteger failures = new AtomicInteger();
    var listener = new ServletBoundaryInstrumentation.FailureListener(failures::incrementAndGet);
    var matcher = listener.selected(named("java.lang.Object"));
    var error = new IllegalStateException("transformation failed");
    assertTrue(matcher.matches(type, loader, null, null, null));
    listener.onError(type.getName(), otherLoader, null, false, error);
    assertEquals(0, failures.get());
    listener.onComplete(type.getName(), loader, null, false);
    listener.onError(type.getName(), loader, null, false, error);
    assertEquals(0, failures.get());
    for (boolean linkage : List.of(false, true)) {
      var throwing = new ServletBoundaryInstrumentation.FailureListener(() -> {
        if (linkage) throw new LinkageError("callback failed");
        throw new IllegalStateException("callback failed");
      });
      assertTrue(throwing.selected(named(type.getName())).matches(type, loader, null, null, null));
      assertDoesNotThrow(() -> throwing.onError(type.getName(), loader, null, false, error));
    }
  }

  @Test
  void bothServletNamespacesMatchOnlyTheStandardBoundarySignatures() {
    for (String api : List.of("jakarta.servlet", "javax.servlet")) {
      TypeDescription request = new ByteBuddy().makeInterface()
          .name(api + ".ServletRequest").make().getTypeDescription();
      TypeDescription response = new ByteBuddy().makeInterface()
          .name(api + ".ServletResponse").make().getTypeDescription();
      TypeDescription chain = new ByteBuddy().makeInterface()
          .name(api + ".FilterChain").make().getTypeDescription();
      TypeDescription type = new ByteBuddy().subclass(Object.class)
          .defineMethod("service", void.class, Visibility.PUBLIC)
          .withParameters(request, response).intercept(StubMethod.INSTANCE)
          .defineMethod("doFilter", void.class, Visibility.PUBLIC)
          .withParameters(request, response, chain).intercept(StubMethod.INSTANCE)
          .defineMethod("doFilterInternal", void.class, Visibility.PUBLIC)
          .withParameters(request, response, chain).intercept(StubMethod.INSTANCE)
          .defineMethod("service", void.class, Visibility.PUBLIC)
          .withParameters(Object.class, Object.class).intercept(StubMethod.INSTANCE)
          .defineMethod("doFilter", void.class, Visibility.PUBLIC)
          .withParameters(request, response).intercept(StubMethod.INSTANCE)
          .make().getTypeDescription();
      assertEquals(List.of("service", "doFilter"), type.getDeclaredMethods().stream()
          .filter(ServletBoundaryInstrumentation.boundaryMethods(api)::matches)
          .map(method -> method.getName()).toList());
      String other = api.startsWith("jakarta") ? "javax.servlet" : "jakarta.servlet";
      assertEquals(0, type.getDeclaredMethods().stream()
          .filter(ServletBoundaryInstrumentation.boundaryMethods(other)::matches).count());
    }
  }

  @Test
  void bothSendErrorOverloadsAreTrackedButStatusSettersAreNot() {
    TypeDescription type = new ByteBuddy().subclass(Object.class)
        .defineMethod("sendError", void.class, Visibility.PUBLIC)
        .withParameters(int.class).intercept(StubMethod.INSTANCE)
        .defineMethod("sendError", void.class, Visibility.PUBLIC)
        .withParameters(int.class, String.class).intercept(StubMethod.INSTANCE)
        .defineMethod("sendError", void.class, Visibility.PUBLIC)
        .withParameters(String.class).intercept(StubMethod.INSTANCE)
        .defineMethod("setStatus", void.class, Visibility.PUBLIC)
        .withParameters(int.class).intercept(StubMethod.INSTANCE)
        .make().getTypeDescription();
    assertEquals(List.of(1, 2), type.getDeclaredMethods().stream()
        .filter(ServletBoundaryInstrumentation.sendErrorMethods()::matches)
        .map(method -> method.getParameters().size()).toList());
  }
}
