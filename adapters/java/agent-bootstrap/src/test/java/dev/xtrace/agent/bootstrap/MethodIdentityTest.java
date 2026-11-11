package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class MethodIdentityTest {
  @Test
  void identitiesDistinguishOverloadsAndDeclaringClassesWithoutPublishingDescriptors() {
    String first = MethodIdentity.symbol("demo.A", "run", "(Lprivateapp/SecretType;)V");
    assertTrue(first.matches("A\\.run#m1:[0-9a-f]{64}"));
    assertEquals(first, MethodIdentity.symbol("demo.A", "run", "(Lprivateapp/SecretType;)V"));
    assertNotEquals(first, MethodIdentity.symbol("demo.A", "run", "(I)V"));
    assertNotEquals(first, MethodIdentity.symbol("other.A", "run", "(Lprivateapp/SecretType;)V"));
    assertNotEquals(first, MethodIdentity.symbol("demo.A", "other", "(Lprivateapp/SecretType;)V"));
    assertFalse(first.contains("privateapp"));
    assertFalse(first.contains("SecretType"));
    assertNull(MethodIdentity.symbol("demo.A", "run", null));
    assertNull(MethodIdentity.symbol("demo.A", "run", ""));
    String bounded = MethodIdentity.symbol("demo." + "A".repeat(300), "run", "()V");
    assertTrue(BootstrapBridge.validSymbol(bounded));
    assertTrue(bounded.matches(".+#m1:[0-9a-f]{64}"));
  }
}
