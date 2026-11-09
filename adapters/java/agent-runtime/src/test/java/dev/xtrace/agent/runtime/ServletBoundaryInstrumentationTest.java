package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.StubMethod;
import org.junit.jupiter.api.Test;

class ServletBoundaryInstrumentationTest {
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
