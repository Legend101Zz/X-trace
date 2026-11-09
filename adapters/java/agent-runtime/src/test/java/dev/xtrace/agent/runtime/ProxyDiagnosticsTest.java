package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class ProxyDiagnosticsTest {
  @Test
  void startupCannotExhaustRequestResolutionDiagnosticsAndBothRemainBounded() {
    var budget = new ProxyDiagnostics.Budget();
    for (int i = 0; i < 64; i++) assertTrue(budget.admit("transformed"));
    assertFalse(budget.admit("transformed"));
    for (int i = 0; i < 64; i++) assertTrue(budget.admit("resolved"));
    assertFalse(budget.admit("no_declaration"));
    assertFalse(budget.admit("resolution_failed"));
    assertFalse(budget.admit("transform_failed"));
  }

  @Test
  void onlyHashesAndFixedResultsLeaveTheRuntime() throws Exception {
    String declaration = "org.springframework.samples.petclinic.owner.OwnerRepository.findById";
    String expected = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
        .digest(declaration.getBytes(StandardCharsets.UTF_8)));
    String row = ProxyDiagnostics.row("private.proxy.$Proxy17", "findById(I)Lprivate/Owner;", declaration, "resolved");
    assertTrue(row.contains("\"declarationHash\":\"" + expected + "\""));
    assertTrue(row.contains("\"result\":\"resolved\""));
    assertFalse(row.contains("private"));
    assertFalse(row.contains("OwnerRepository"));
    assertFalse(row.contains("findById"));
    assertEquals(3, row.split("sha256:", -1).length - 1);
    assertThrows(IllegalArgumentException.class,
        () -> ProxyDiagnostics.row("proxy", null, null, "private exception text"));
  }

  @Test
  void absentDeclarationIsNeverInvented() {
    String row = ProxyDiagnostics.row("proxy", "findById()V", null, "no_declaration");
    assertTrue(row.contains("\"declarationHash\":null"));
    assertTrue(row.contains("\"result\":\"no_declaration\""));
  }
}
