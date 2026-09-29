package dev.xtrace.adapter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class TranscriptProofTest {
  @Test
  void sharedRustNodeJavaGoldenVectorMatches() throws Exception {
    Path fixture = Path.of("../../schema/fixtures/xtp-agent/handshake-vector.json");
    Map<String, String> values = new HashMap<>();
    try (JsonParser parser = new JsonFactory().createParser(Files.readAllBytes(fixture))) {
      assertEquals(JsonToken.START_OBJECT, parser.nextToken());
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        String name = parser.currentName();
        parser.nextToken();
        values.put(name, parser.getText());
      }
    }
    byte[] actual =
        TranscriptProof.compute(
            hex(values.get("session_secret_hex")),
            hex(values.get("tls_exporter_hex")),
            hex(values.get("runtime_session_id_hex")),
            hex(values.get("client_nonce_hex")),
            hex(values.get("server_nonce_hex")),
            values.get("manifest_digest").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    assertArrayEquals(hex(values.get("expected_hmac_hex")), actual);
  }

  @Test
  void rejectsWrongOrTruncatedDaemonProof() throws Exception {
    byte[] expected = new byte[32];
    byte[] wrong = new byte[32];
    wrong[0] = 1;
    assertThrows(ClientException.class, () -> TranscriptProof.verify(expected, wrong));
    assertThrows(ClientException.class, () -> TranscriptProof.verify(expected, new byte[31]));
  }

  private static byte[] hex(String value) {
    return HexFormat.of().parseHex(value);
  }
}
