package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;

class ApplicationScopeTest {
  private static ProtectionDomain domain(String location) throws Exception {
    // Spring Boot registers handlers for its nested jar schemes; the test needs only the text.
    URL url =
        new URL(
            null,
            location,
            new java.net.URLStreamHandler() {
              @Override
              protected java.net.URLConnection openConnection(URL ignored) {
                throw new UnsupportedOperationException();
              }
            });
    return new ProtectionDomain(new CodeSource(url, (Certificate[]) null), null);
  }

  @Test
  void fatJarBootInfClassesIsApplicationByDefault() throws Exception {
    ApplicationScope scope = ApplicationScope.defaultScope();
    ProtectionDomain classes = domain("jar:nested:/work/petclinic.jar/!BOOT-INF/classes/!/");
    assertEquals(
        ApplicationScope.APPLICATION,
        scope.verdict("org.springframework.samples.petclinic.owner.OwnerController", classes));
  }

  @Test
  void dependencyJarsAreNeverApplicationRoots() throws Exception {
    ProtectionDomain lib =
        domain("jar:nested:/work/petclinic.jar/!BOOT-INF/lib/spring-web-7.0.0.jar!/");
    assertEquals(
        ApplicationScope.NOT_APPLICATION,
        ApplicationScope.defaultScope().verdict("org.springframework.web.Anything", lib));
    // Even an explicitly configured prefix cannot make a dependency jar class an application class.
    ApplicationScope configured =
        new ApplicationScope(List.of("org.springframework.web"), List.of("src/main/java"));
    assertEquals(
        ApplicationScope.NOT_APPLICATION,
        configured.verdict("org.springframework.web.Anything", lib));
  }

  @Test
  void denySetCannotBeOverriddenByConfiguration() throws Exception {
    ApplicationScope scope =
        new ApplicationScope(
            List.of("java.lang", "dev.xtrace.agent", "net.bytebuddy", "com.acme"),
            List.of("src/main/java"));
    assertEquals(List.of("com.acme"), scope.packages());
    ProtectionDomain any = domain("file:/work/classes/");
    assertFalse(scope.isApplication("java.lang.String", any));
    assertFalse(scope.isApplication("dev.xtrace.agent.runtime.AgentRuntime", any));
    assertTrue(scope.isApplication("com.acme.Thing", any));
  }

  @Test
  void packagePrefixMatchesWholeSegmentsOnly() throws Exception {
    ApplicationScope scope = new ApplicationScope(List.of("com.acme"), List.of("src/main/java"));
    ProtectionDomain any = domain("file:/work/classes/");
    assertTrue(scope.isApplication("com.acme.web.Controller", any));
    assertFalse(scope.isApplication("com.acmeevil.Controller", any));
    assertFalse(scope.isApplication("org.other.Controller", any));
  }

  @Test
  void proxiesAndGeneratedClassesAreNotApplicationCode() throws Exception {
    ApplicationScope scope = new ApplicationScope(List.of("com.acme"), List.of("src/main/java"));
    ProtectionDomain any = domain("file:/work/classes/");
    assertFalse(scope.isApplication("com.acme.Thing$$SpringCGLIB$$0", any));
    assertFalse(scope.isApplication("com.acme.$Proxy12", any));
    assertFalse(scope.isApplication("com.acme.Thing$$Lambda/0x1234", any));
    assertFalse(scope.isApplication("com.acme.Thing$ByteBuddy$abc", any));
  }

  @Test
  void unconfiguredScopeOutsideBootInfIsUnknownNotApplication() throws Exception {
    ApplicationScope scope = ApplicationScope.defaultScope();
    assertEquals(
        ApplicationScope.UNKNOWN,
        scope.verdict("com.acme.Thing", domain("file:/work/classes/")));
    assertEquals(ApplicationScope.UNKNOWN, scope.verdict("com.acme.Thing", null));
    assertFalse(scope.isApplication("com.acme.Thing", null));
  }

  @Test
  void packageNamesAreValidatedAndBounded() {
    assertTrue(ApplicationScope.validPackage("com.acme.web"));
    assertFalse(ApplicationScope.validPackage(""));
    assertFalse(ApplicationScope.validPackage("com..acme"));
    assertFalse(ApplicationScope.validPackage("com.acme."));
    assertFalse(ApplicationScope.validPackage("com.acme/web"));
    assertFalse(ApplicationScope.validPackage("a".repeat(300)));
  }
}
