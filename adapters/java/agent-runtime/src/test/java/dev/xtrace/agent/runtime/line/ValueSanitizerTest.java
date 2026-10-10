package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.line.ValueSanitizer.Limits;
import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Reason;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import dev.xtrace.agent.runtime.line.ValueSnapshot.State;
import dev.xtrace.agent.runtime.line.ValueSnapshot.ValueShape;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ValueSanitizerTest {
  static ValueSnapshot ref(String name, Object v, Limits l) {
    return ValueSanitizer.ofRef(name, NameOrigin.DECLARED, v, Role.LOCAL, l);
  }

  static SiteRegistry.Name n(String name, String desc) {
    return new SiteRegistry.Name(1, name, desc, 1);
  }

  enum Mode {
    FAST
  }

  /** Counts calls: proves nothing of the value is invoked. */
  static final class Tripwire {
    static int calls;

    @Override
    public String toString() {
      calls++;
      return "tripped";
    }

    @Override
    public int hashCode() {
      calls++;
      return 1;
    }
  }

  @Test
  void neverInvokesToStringOrHashCodeOfUnknownObjects() {
    Tripwire.calls = 0;
    ValueSnapshot s = ref("thing", new Tripwire(), Limits.FOCUSED);
    assertEquals(State.UNAVAILABLE, s.state());
    assertEquals(Reason.UNSAFE_TO_RENDER, s.reason());
    assertTrue(s.typeName().endsWith("ValueSanitizerTest$Tripwire"));
    assertNull(s.preview());
    assertEquals(0, Tripwire.calls);
  }

  @Test
  void primitivesStringsBoxedAndEnums() {
    assertEquals("true", ValueSanitizer.ofInt(n("z", "Z"), 1, Role.LOCAL, Limits.FOCUSED).preview());
    assertEquals("q", ValueSanitizer.ofInt(n("c", "C"), 'q', Role.LOCAL, Limits.FOCUSED).preview());
    assertEquals("-3", ValueSanitizer.ofInt(n("b", "B"), 253, Role.LOCAL, Limits.FOCUSED).preview());
    assertEquals("12", ValueSanitizer.ofLong(n("l", "J"), 12L, Role.LOCAL, Limits.FOCUSED).preview());
    assertEquals("1.5", ValueSanitizer.ofDouble(n("d", "D"), 1.5, Role.LOCAL, Limits.FOCUSED).preview());
    assertEquals("hello", ref("greeting", "hello", Limits.FOCUSED).preview());
    assertEquals("42", ref("count", Integer.valueOf(42), Limits.FOCUSED).preview());
    assertEquals("FAST", ref("mode", Mode.FAST, Limits.FOCUSED).preview());
    assertEquals("null", ref("nothing", null, Limits.FOCUSED).preview());
    ValueSnapshot s = ref("greeting", "hello", Limits.FOCUSED);
    assertEquals(State.CAPTURED, s.state());
    assertEquals(NameOrigin.DECLARED, s.nameOrigin());
  }

  @Test
  void secretNamesAreRedactedBeforeTheValueIsRendered() {
    for (String name : new String[] {"password", "PASSWD", "dbPwd", "clientSecret", "authToken",
        "Authorization", "cookieJar", "api_key", "apiKey", "api-key", "credentials", "privateKey",
        "private-key", "sessionId", "bearerValue"}) {
      ValueSnapshot s = ref(name, "xtrace-canary-1234", Limits.FOCUSED);
      assertEquals(State.REDACTED, s.state(), name);
      assertEquals(Redaction.RULE_NAME, s.ruleId(), name);
      assertNull(s.preview(), name);
      assertNull(s.contentHash(), name);
    }
    assertEquals(State.REDACTED, ValueSanitizer.ofInt(n("pwd", "I"), 7, Role.LOCAL, Limits.FOCUSED).state());
    assertEquals(State.CAPTURED, ref("count", "x", Limits.FOCUSED).state());
  }

  @Test
  void contentPatternsAreRedactedEvenUnderInnocentNames() {
    String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl";
    String aws = "AKIA" + "ABCDEFGHIJKLMNOP";
    String pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----";
    String bearer = "Authorization: Bearer abcdef123456";
    for (String v : new String[] {jwt, aws, pem, bearer, "prefix " + jwt + " suffix"}) {
      ValueSnapshot s = ref("note", v, Limits.FOCUSED);
      assertEquals(State.REDACTED, s.state(), v);
      assertEquals(Redaction.RULE_CONTENT, s.ruleId());
      assertNull(s.preview());
    }
    // secret hidden after the preview cut is still detected (scan precedes truncation)
    String late = "x ".repeat(300) + aws; // spaces: the 512-char preview alone matches no rule
    assertEquals(State.REDACTED, ref("note", late, Limits.FOCUSED).state());
  }

  @Test
  void sensitiveTypesAreRedactedByType() {
    assertEquals(Redaction.RULE_TYPE, ref("in", new ByteArrayInputStream(new byte[0]), Limits.FOCUSED).ruleId());
    assertEquals(Redaction.RULE_TYPE, ref("cl", String.class, Limits.FOCUSED).ruleId());
    assertEquals(Redaction.RULE_TYPE, ref("t", Thread.currentThread(), Limits.FOCUSED).ruleId());
    assertEquals(
        Redaction.RULE_TYPE,
        ref("k", new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"), Limits.FOCUSED).ruleId());
  }

  @Test
  void previewsAreBoundedByBytesNotChars() {
    ValueSnapshot s = ref("text", "\u00e9".repeat(400), Limits.STANDARD); // 800 bytes
    assertEquals(State.TRUNCATED, s.state());
    byte[] bytes = s.preview().getBytes(StandardCharsets.UTF_8);
    assertTrue(bytes.length <= 256 && bytes.length >= 254, "len " + bytes.length);
    assertEquals(512, ref("text", "ab ".repeat(2000), Limits.FOCUSED).preview().length());
    ValueSnapshot ok = ref("text", "ab ".repeat(85) + "a", Limits.STANDARD);
    assertEquals(State.CAPTURED, ok.state());
    ValueSnapshot emoji = ref("text", "\uD83D\uDE00".repeat(100), Limits.STANDARD);
    assertTrue(emoji.preview().getBytes(StandardCharsets.UTF_8).length <= 256);
    assertFalse(emoji.preview().endsWith("\uD83D"), "never split a surrogate pair");
  }

  @Test
  void contentHashIsBlake3OfEmittedBytesAndAbsentWhenRedacted() {
    ValueSnapshot s = ref("text", "hello", Limits.FOCUSED);
    assertArrayEquals(LineProbeInstrumenter.blake3("hello".getBytes(StandardCharsets.UTF_8)), s.contentHash());
    ValueSnapshot t = ref("text", "\u00e9".repeat(400), Limits.STANDARD);
    assertArrayEquals(LineProbeInstrumenter.blake3(t.preview().getBytes(StandardCharsets.UTF_8)), t.contentHash());
    assertNull(ref("password", "x", Limits.FOCUSED).contentHash());
  }

  @Test
  void controlCharactersAndLongNamesAreNormalised() {
    ValueSnapshot s = ref("a\u0000b", "line1\u0007line2", Limits.FOCUSED);
    assertEquals("a\uFFFDb", s.name());
    assertEquals("line1\uFFFDline2", s.preview());
    ValueSnapshot long1 = ref("n".repeat(300), "v", Limits.FOCUSED);
    assertEquals(128, long1.name().length());
  }

  @Test
  void missingDebugMetadataIsAnExplicitSynthesizedUnavailable() {
    ValueSnapshot s = ValueSanitizer.noDebugMetadata(2, Role.ARGUMENT);
    assertEquals("arg2", s.name());
    assertEquals(NameOrigin.SYNTHESIZED, s.nameOrigin());
    assertEquals(Reason.DEBUG_METADATA_ABSENT, s.reason());
  }

  @Test
  void registryDedupesNamesAndBoundsSites() {
    SiteRegistry r = new SiteRegistry(2);
    assertEquals(r.addName("x", "I", 1), r.addName("x", "I", 1));
    assertTrue(r.addName("x", "I", 2) != r.addName("x", "I", 1));
    assertEquals(1, r.addSite("C", null, "m", "()V", 10));
    assertEquals(2, r.addSite("C", null, "m", "()V", 11));
    assertEquals(-1, r.addSite("C", null, "m", "()V", 12));
    assertEquals(11, r.site(2).line());
    assertEquals(2, r.siteCount());
  }

  @Test
  void dispatchIsFailOpenAndNoopByDefault() {
    LineProbeDispatch.install(
        new LineProbeSink() {
          @Override
          public void line(int siteId) {
            throw new IllegalStateException("sink bug");
          }
        });
    try {
      LineProbeDispatch.line(1); // must not throw into application code
      LineProbeDispatch.valueRef(1, 3, "x");
    } finally {
      LineProbeDispatch.install(null);
    }
    assertEquals(LineProbeSink.NOOP, LineProbeDispatch.current());
  }

  // ---- round 2: wire mapping fields ----

  @Test
  void shapesFollowTheWireEnumForEveryPrimitiveAndReference() {
    assertEquals(ValueShape.BOOLEAN, ValueSanitizer.ofInt(n("z", "Z"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.STRING, ValueSanitizer.ofInt(n("c", "C"), 'q', Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.INTEGER_8, ValueSanitizer.ofInt(n("b", "B"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.INTEGER_16, ValueSanitizer.ofInt(n("s", "S"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.INTEGER_32, ValueSanitizer.ofInt(n("i", "I"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.INTEGER_64, ValueSanitizer.ofLong(n("l", "J"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.FLOAT_32, ValueSanitizer.ofFloat(n("f", "F"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.FLOAT_64, ValueSanitizer.ofDouble(n("d", "D"), 1, Role.LOCAL, Limits.FOCUSED).shape());
    assertEquals(ValueShape.STRING, ref("v", "x", Limits.FOCUSED).shape());
    assertEquals(ValueShape.NULL, ref("v", null, Limits.FOCUSED).shape());
    assertEquals(ValueShape.INTEGER_64, ref("v", 5L, Limits.FOCUSED).shape());
    assertEquals(ValueShape.STRING, ref("v", Thread.State.NEW, Limits.FOCUSED).shape());
    assertEquals(ValueShape.UNKNOWN, ref("v", new Object(), Limits.FOCUSED).shape());
  }

  @Test
  void redactedValuesCarryAShapeHint() {
    ValueSnapshot s = ref("password", "x", Limits.FOCUSED);
    assertEquals(State.REDACTED, s.state());
    assertEquals(ValueShape.STRING, s.shape());
    assertEquals(ValueShape.INTEGER_32, ValueSanitizer.ofInt(n("pwd", "I"), 7, Role.LOCAL, Limits.FOCUSED).shape());
  }

  @Test
  void truncatedCarriesOriginalSizeLowerBoundAndLimit() {
    ValueSnapshot s = ref("text", "\u00e9".repeat(400), Limits.STANDARD); // 800 bytes
    assertEquals(State.TRUNCATED, s.state());
    assertEquals(256, s.limit());
    assertTrue(s.originalSizeLowerBound() >= 256 && s.originalSizeLowerBound() <= 800, "" + s.originalSizeLowerBound());
    ValueSnapshot big = ref("text", "ab ".repeat(2000), Limits.FOCUSED); // 6000 bytes
    assertEquals(512, big.limit());
    assertTrue(big.originalSizeLowerBound() > 512 && big.originalSizeLowerBound() <= 6000);
    ValueSnapshot ok = ref("text", "short", Limits.FOCUSED);
    assertEquals(0, ok.originalSizeLowerBound());
    assertEquals(0, ok.limit());
  }

  @Test
  void rolesAndShapesEqualTheGeneratedWireEnums() {
    // ROLE_* numbers are the wire BindingRole numbers
    assertEquals(xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_ARGUMENT_VALUE, LineProbeSink.ROLE_ARGUMENT);
    assertEquals(xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_RETURN_VALUE, LineProbeSink.ROLE_RETURN);
    assertEquals(xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_LOCAL_VALUE, LineProbeSink.ROLE_LOCAL);
    assertEquals(xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_EXCEPTION_VALUE, LineProbeSink.ROLE_EXCEPTION);
    assertEquals(xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_RECEIVER_VALUE, LineProbeSink.ROLE_RECEIVER);
    // every Role maps to a wire role by name, and nothing is left over
    for (Role r : Role.values()) {
      assertEquals(r.name(), xtp.agent.v1.Recording.BindingRole.valueOf("BINDING_ROLE_" + r.name()).name().substring("BINDING_ROLE_".length()));
    }
    int wireRoles = 0;
    for (var w : xtp.agent.v1.Recording.BindingRole.values()) {
      if (w != xtp.agent.v1.Recording.BindingRole.UNRECOGNIZED && w != xtp.agent.v1.Recording.BindingRole.BINDING_ROLE_UNSPECIFIED) wireRoles++;
    }
    assertEquals(wireRoles, Role.values().length);
    // ValueShape: same names in the same order as the wire enum (UNSPECIFIED and UNRECOGNIZED aside)
    java.util.List<String> wire = new java.util.ArrayList<>();
    for (var w : xtp.agent.v1.Recording.ValueShape.values()) {
      if (w == xtp.agent.v1.Recording.ValueShape.UNRECOGNIZED || w == xtp.agent.v1.Recording.ValueShape.VALUE_SHAPE_UNSPECIFIED) continue;
      wire.add(w.name().substring("VALUE_SHAPE_".length()));
      assertEquals(w.getNumber(), java.util.Arrays.asList(ValueShape.values()).indexOf(ValueShape.valueOf(wire.get(wire.size() - 1))) + 1);
    }
    java.util.List<String> ours = new java.util.ArrayList<>();
    for (ValueShape v : ValueShape.values()) ours.add(v.name());
    assertEquals(wire, ours);
    // roles flow through the sanitizer unchanged
    assertEquals(Role.EXCEPTION, ValueSanitizer.ofRef("ex", NameOrigin.DECLARED, "boom", Role.EXCEPTION, Limits.STANDARD).role());
    assertEquals(Role.RECEIVER, ValueSanitizer.ofRef("this", NameOrigin.DECLARED, "r", Role.RECEIVER, Limits.STANDARD).role());
  }

  @Test
  void cutBetweenSurrogatePairNeverLeavesALoneSurrogate() {
    // 255 'a' puts the pair across the 256 limit: char 255 is the high surrogate, 256 the low one.
    String text = "ab ".repeat(85) + "\uD83D\uDE00" + "b";
    ValueSnapshot s = ref("text", text, Limits.STANDARD);
    assertFalse(Character.isHighSurrogate(s.preview().charAt(s.preview().length() - 1)));
    assertTrue(s.preview().getBytes(StandardCharsets.UTF_8).length <= 256);
    // the hash is of bytes that decode back to exactly the preview
    byte[] bytes = s.preview().getBytes(StandardCharsets.UTF_8);
    assertEquals(s.preview(), new String(bytes, StandardCharsets.UTF_8));
    assertArrayEquals(LineProbeInstrumenter.blake3(bytes), s.contentHash());
    assertFalse(s.preview().contains("?"));
  }

  @Test
  void loneSurrogatesInTheInputAreReplacedNotQuestionMarked() {
    ValueSnapshot s = ref("text", "a\uD83Db\uDE00c", Limits.FOCUSED);
    assertEquals("a\uFFFDb\uFFFDc", s.preview());
    byte[] bytes = s.preview().getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(LineProbeInstrumenter.blake3(bytes), s.contentHash());
  }

  // ---- round 2: one redaction policy ----

  @Test
  void sharedVectorsAreRedactedUnderInnocentNames() throws Exception {
    java.util.List<String> lines =
        java.nio.file.Files.readAllLines(
            java.nio.file.Path.of(
                getClass().getResource("/line/redaction-vectors.tsv").toURI()),
            StandardCharsets.UTF_8);
    int checked = 0;
    for (String line : lines) {
      if (line.isBlank() || line.startsWith("#")) continue;
      String[] f = line.split("\t", 2);
      boolean secret = f[0].equals("secret");
      String text = f[1].replace("\\n", "\n");
      assertEquals(secret, Redaction.contentIsSecret(text), line);
      ValueSnapshot s = ref("note", text, Limits.FOCUSED);
      assertEquals(secret ? State.REDACTED : State.CAPTURED, s.state(), line);
      if (secret) {
        assertFalse(Redaction.replaceSecrets(text).equals(text), line);
      } else {
        assertEquals(text, Redaction.replaceSecrets(text), line);
      }
      checked++;
    }
    assertTrue(checked >= 12, "vectors read: " + checked);
  }

  // ---- final stage: review2 fixes ----

  @Test
  void regexCostIsBoundedOnDottedAndHyphenatedRuns() {
    for (String unit : new String[] {"a.", "a-", "a.b-", "a:"}) {
      String text = unit.repeat(4096);
      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
          java.time.Duration.ofMillis(500), () -> Redaction.contentIsSecret(text), unit);
      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
          java.time.Duration.ofMillis(500), () -> ref("note", text, Limits.FOCUSED), unit);
    }
  }

  @Test
  void aSecretStartingInsideThePreviewAndRunningPastTheScanCutIsStillSeen() {
    String text = "x ".repeat(100) + "Bearer " + "A".repeat(3000);
    assertEquals(State.REDACTED, ref("note", text, Limits.FOCUSED).state());
    String url = "see " + "scheme://user:pw@host/";
    assertEquals(State.REDACTED, ref("note", url, Limits.FOCUSED).state());
  }

  @Test
  void originalSizeLowerBoundNeverExceedsTheTrueUtf8Size() {
    String bel = "\u0007".repeat(600); // 600 bytes in UTF-8, 1800 once cleaned to U+FFFD
    ValueSnapshot s = ref("text", bel, Limits.FOCUSED);
    assertEquals(State.TRUNCATED, s.state());
    long trueSize = bel.getBytes(StandardCharsets.UTF_8).length;
    assertTrue(s.originalSizeLowerBound() <= trueSize, "bound " + s.originalSizeLowerBound());
    assertTrue(s.originalSizeLowerBound() > s.limit(), "bound " + s.originalSizeLowerBound());
    String mixed = "\u0007".repeat(100) + "x".repeat(2000);
    long mixedSize = mixed.getBytes(StandardCharsets.UTF_8).length;
    assertTrue(ref("text", mixed, Limits.FOCUSED).originalSizeLowerBound() <= mixedSize);
  }

  @Test
  void bindingNamesCarryNoControlCharactersAtAll() {
    ValueSnapshot s = ref("a\nb\tc\u0000d", "v", Limits.FOCUSED);
    for (char c : s.name().toCharArray()) assertFalse(Character.isISOControl(c), s.name());
    assertEquals("a\uFFFDb\uFFFDc\uFFFDd", s.name());
    // previews keep newline and tab
    assertEquals("l1\nl2\tz", ref("text", "l1\nl2\tz", Limits.FOCUSED).preview());
  }

  @Test
  void registryReusesSiteIdsForTheSameDigestMethodLineAndOrdinal() {
    SiteRegistry r = new SiteRegistry();
    byte[] d1 = new byte[32];
    byte[] d2 = new byte[32];
    d2[0] = 1;
    int a = r.addSite("C", d1, "m", "()V", 10, 0);
    assertEquals(a, r.addSite("C", d1.clone(), "m", "()V", 10, 0));
    assertTrue(a != r.addSite("C", d1, "m", "()V", 10, 1), "second site on the same line");
    assertTrue(a != r.addSite("C", d2, "m", "()V", 10, 0), "different class bytes");
    assertTrue(a != r.addSite("C", d1, "m2", "()V", 10, 0));
    assertEquals(4, r.siteCount());
    // no digest: no dedupe (cannot prove it is the same class)
    int n1 = r.addSite("C", null, "m", "()V", 10);
    assertTrue(n1 != r.addSite("C", null, "m", "()V", 10));
    assertEquals(250_000, SiteRegistry.DEFAULT_MAX_SITES);
  }
}
