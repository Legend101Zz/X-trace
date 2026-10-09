package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.line.CorpusHarness.Run;
import dev.xtrace.agent.runtime.line.MethodReport.Reasons;
import dev.xtrace.agent.runtime.line.MethodReport.Status;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Honest fallbacks: every method the visitor cannot instrument says so and still verifies. */
class LineProbeFallbackTest {
  static final String OWNER = LineProbeDispatch.INTERNAL_NAME;

  @TempDir Path tmp;

  /** Class with straight-line statements, one per line, numbered 0..n-1. */
  static String bigSource(String cls, int statements) {
    StringBuilder b = new StringBuilder("package linecorpus;\npublic final class " + cls + " {\n");
    b.append("  public static String s_run() {\n    int sum = 0;\n    int i = 3;\n");
    for (int k = 0; k < statements; k++) b.append("    sum += i;\n");
    b.append("    return \"sum\" + sum;\n  }\n}\n");
    return b.toString();
  }

  private CorpusPipeline build(
      String name, Map<String, String> extra, String[] flags, LineProbeConfig cfg) throws Exception {
    return CorpusPipeline.build(
        tmp.resolve(name), new SiteRegistry(), extra, flags, CorpusPipeline.byteApi(cfg));
  }

  private static MethodReport report(CorpusPipeline p, String internal, String method) {
    for (MethodReport m : p.results.get(internal).methods()) if (m.name().equals(method)) return m;
    throw new AssertionError(internal + "." + method + " not reported: " + p.results.get(internal).methods());
  }

  @Test
  void classWithoutLineNumberTableIsLeftAloneAndReported() throws Exception {
    CorpusPipeline p =
        build("nog", CorpusPipeline.noExtra(), new String[] {"-g:none"}, LineProbeConfig.focused(OWNER));
    for (var e : p.results.entrySet()) {
      assertFalse(e.getValue().changed(), e.getKey());
      for (MethodReport m : e.getValue().methods()) {
        assertEquals(Status.SKIPPED, m.status());
        assertTrue(
            m.reason().equals(Reasons.NO_LINE_TABLE) || m.reason().equals(Reasons.SYNTHETIC)
                || m.reason().equals(Reasons.BRIDGE),
            m.toString());
      }
    }
    assertEquals(0, p.registry.siteCount());
    CorpusPipeline.Child c = p.runChild();
    assertEquals(0, c.exit(), c.stderr());
    assertTrue(c.loadFailed().isEmpty());
  }

  @Test
  void linesOnlyDebugInfoGivesLineProbesAndHonestNoLocalsReason() throws Exception {
    CorpusPipeline p =
        build("lines", CorpusPipeline.noExtra(), new String[] {"-g:lines,source"}, LineProbeConfig.focused(OWNER));
    MethodReport m = report(p, "linecorpus/LineCorpus", "s_straight");
    assertEquals(Status.INSTRUMENTED, m.status());
    assertTrue(m.sites() > 0);
    assertEquals(0, m.valueCalls());
    assertEquals(Reasons.NO_LVT, m.valuesReason());
    CorpusPipeline.Child c = p.runChild();
    assertEquals(0, c.exit(), c.stderr());
    assertTrue(c.loadFailed().isEmpty(), c.loadFailed().toString());
    List<Run> plain = p.runPlain();
    assertEquals(plain.size(), c.runs().size());
    for (int i = 0; i < plain.size(); i++) assertEquals(plain.get(i).result(), c.runs().get(i).result());
    for (Run r : c.runs()) for (String t : r.tokens()) assertFalse(t.startsWith("V"), t);
  }

  @Test
  void largeMethodsAreInstrumentedUpToTheBudgetThenSkippedWithReasons() throws Exception {
    Map<String, String> extra = new LinkedHashMap<>();
    extra.put("BigOk", bigSource("BigOk", 700)); // under the 1024-site budget
    extra.put("BigSites", bigSource("BigSites", 1500)); // over the site budget
    extra.put("BigBytes", bigSource("BigBytes", 3000)); // fits sites if raised, not the byte budget
    LineProbeConfig cfg =
        new LineProbeConfig(OWNER, false, 1024, 0, 0, LineProbeConfig.DEFAULT_MAX_CODE_BYTES);
    CorpusPipeline p = build("big", extra, new String[] {"-g"}, cfg);
    assertEquals(Status.INSTRUMENTED, report(p, "linecorpus/BigOk", "s_run").status());
    MethodReport sites = report(p, "linecorpus/BigSites", "s_run");
    assertEquals(Status.SKIPPED, sites.status());
    assertEquals(Reasons.SITE_BUDGET, sites.reason());

    LineProbeConfig raised =
        new LineProbeConfig(OWNER, false, 100_000, 0, 0, LineProbeConfig.DEFAULT_MAX_CODE_BYTES);
    CorpusPipeline q = build("big2", extra, new String[] {"-g"}, raised);
    MethodReport bytes = report(q, "linecorpus/BigBytes", "s_run");
    assertEquals(Status.SKIPPED, bytes.status());
    assertEquals(Reasons.TOO_LARGE, bytes.reason());
    assertEquals(Status.INSTRUMENTED, report(q, "linecorpus/BigSites", "s_run").status());

    for (CorpusPipeline pipeline : List.of(p, q)) {
      CorpusPipeline.Child c = pipeline.runChild();
      assertEquals(0, c.exit(), c.stderr());
      assertTrue(c.loadFailed().isEmpty(), c.loadFailed().toString());
      List<Run> plain = pipeline.runPlain();
      for (int i = 0; i < plain.size(); i++) {
        assertEquals(plain.get(i).name(), c.runs().get(i).name());
        assertEquals(plain.get(i).result(), c.runs().get(i).result(), plain.get(i).name());
      }
    }
  }

  @Test
  void valueBudgetFallsBackToLinesOnlyWithReason() throws Exception {
    LineProbeConfig cfg = new LineProbeConfig(OWNER, true, 1024, 16, 3, LineProbeConfig.DEFAULT_MAX_CODE_BYTES);
    CorpusPipeline p = build("vb", CorpusPipeline.noExtra(), new String[] {"-g"}, cfg);
    MethodReport m = report(p, "linecorpus/LineCorpus", "s_widePrims");
    assertEquals(Status.INSTRUMENTED, m.status());
    assertEquals(0, m.valueCalls());
    assertEquals(Reasons.VALUE_BUDGET, m.valuesReason());
    CorpusPipeline.Child c = p.runChild();
    assertEquals(0, c.exit(), c.stderr());
    assertTrue(c.loadFailed().isEmpty());
  }

  @Test
  void fullSiteRegistrySkipsMethodsInsteadOfFailing() throws Exception {
    SiteRegistry tiny = new SiteRegistry(5);
    CorpusPipeline p =
        CorpusPipeline.build(
            tmp.resolve("reg"), tiny, CorpusPipeline.noExtra(), new String[] {"-g"},
            CorpusPipeline.byteApi(LineProbeConfig.lineOnly(OWNER)));
    assertTrue(tiny.siteCount() <= 5);
    boolean sawFull = false;
    for (var e : p.results.values()) {
      for (MethodReport m : e.methods()) if (Reasons.REGISTRY_FULL.equals(m.reason())) sawFull = true;
    }
    assertTrue(sawFull);
    CorpusPipeline.Child c = p.runChild();
    assertEquals(0, c.exit(), c.stderr());
    assertTrue(c.loadFailed().isEmpty());
  }

  @Test
  void garbageAndUnsupportedBytesFailOpen() {
    LineProbeInstrumenter inst = new LineProbeInstrumenter(LineProbeConfig.lineOnly(OWNER), new SiteRegistry());
    byte[] junk = {1, 2, 3, 4, 5};
    LineProbeInstrumenter.Result r = inst.instrument(junk);
    assertFalse(r.changed());
    assertEquals(junk, r.bytes());
    assertFalse(r.classReason().isEmpty());
  }
}
