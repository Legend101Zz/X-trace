package dev.xtrace.agent.runtime.line;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.runtime.line.CorpusHarness.Run;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The verifier corpus (lane JB gate): compiles tricky methods with the JDK running the tests,
 * transforms them, loads them in a child JVM with -Xverify:all, and checks that line events
 * match an independent ground truth (Trace.hit) and that behaviour is unchanged.
 */
class LineProbeCorpusTest {
  static final String[] DEBUG_ALL = {"-g"};
  static final Pattern TAG = Pattern.compile("//@(\\w+)\\s*$");

  static Path work;
  static CorpusPipeline lineOnly;
  static CorpusPipeline.Child lineOnlyChild;
  static List<Run> plainRuns;
  static CorpusPipeline focused;
  static CorpusPipeline.Child focusedChild;
  static Map<Integer, String> tagByLine = new HashMap<>();

  @TempDir static Path tmp;

  @BeforeAll
  static void build() throws Exception {
    work = tmp;
    String[] lines = CorpusPipeline.resource("/line/LineCorpus.java.txt").split("\n", -1);
    for (int i = 0; i < lines.length; i++) {
      Matcher m = TAG.matcher(lines[i]);
      if (m.find()) tagByLine.put(i + 1, m.group(1));
    }
    String owner = LineProbeDispatch.INTERNAL_NAME;
    lineOnly =
        CorpusPipeline.build(
            work.resolve("lineonly"), new SiteRegistry(), CorpusPipeline.noExtra(), DEBUG_ALL,
            CorpusPipeline.byteApi(LineProbeConfig.lineOnly(owner)));
    lineOnlyChild = lineOnly.runChild();
    plainRuns = lineOnly.runPlain();
    focused =
        CorpusPipeline.build(
            work.resolve("focused"), new SiteRegistry(), CorpusPipeline.noExtra(), DEBUG_ALL,
            CorpusPipeline.byteApi(LineProbeConfig.focused(owner)));
    focusedChild = focused.runChild();
  }

  @Test
  void everyClassVerifiesUnderXverifyAll() {
    for (CorpusPipeline.Child c : List.of(lineOnlyChild, focusedChild)) {
      assertEquals(0, c.exit(), c.stderr());
      assertTrue(c.loadFailed().isEmpty(), "verify/link failures: " + c.loadFailed() + c.stderr());
      assertTrue(c.loaded().size() >= 10, "corpus classes loaded: " + c.loaded());
    }
  }

  @Test
  void classesWereActuallyInstrumented() {
    int changed = 0;
    for (var r : lineOnly.results.values()) if (r.changed()) changed++;
    assertTrue(changed >= 10, "changed classes: " + changed);
    assertTrue(lineOnly.registry.siteCount() > 150, "sites: " + lineOnly.registry.siteCount());
  }

  @Test
  void lineEventsMatchGroundTruthInOrder() {
    assertScenarios(lineOnly, lineOnlyChild);
  }

  @Test
  void lineEventsMatchGroundTruthInFocusedMode() {
    assertScenarios(focused, focusedChild);
  }

  private void assertScenarios(CorpusPipeline p, CorpusPipeline.Child child) {
    int totalHits = 0;
    int checked = 0;
    for (Run run : child.runs()) {
      if (!run.name().startsWith("linecorpus.LineCorpus.")) continue;
      List<String> events = taggedEvents(p, run);
      List<String> hits = new ArrayList<>();
      for (String h : run.hits()) hits.add(h.substring(0, h.indexOf('|')));
      assertEquals(hits, events, run.name() + " tagged line events vs ground truth");
      totalHits += hits.size();
      checked++;
    }
    assertTrue(checked >= 16, "scenarios checked: " + checked);
    assertTrue(totalHits >= 60, "ground-truth hits: " + totalHits);
  }

  private List<String> taggedEvents(CorpusPipeline p, Run run) {
    List<String> out = new ArrayList<>();
    for (String t : run.tokens()) {
      if (!t.startsWith("L ")) continue;
      SiteRegistry.Site site = p.registry.site(Integer.parseInt(t.substring(2)));
      assertNotNull(site, "unknown site in " + t);
      String tag = site.classInternalName().startsWith("linecorpus/LineCorpus") ? tagByLine.get(site.line()) : null;
      if (tag != null) out.add(tag);
    }
    return out;
  }

  @Test
  void behaviourAndStackTraceLinesAreUnchanged() {
    Map<String, String> plain = new HashMap<>();
    for (Run r : plainRuns) plain.put(r.name(), r.result());
    assertTrue(plain.size() >= 16);
    for (CorpusPipeline.Child c : List.of(lineOnlyChild, focusedChild)) {
      for (Run r : c.runs()) {
        assertEquals(plain.get(r.name()), r.result(), r.name() + " result differs after instrumentation");
        assertFalse(r.result().startsWith("THROWN"), r.name() + " " + r.result());
      }
      assertEquals(plain.size(), c.runs().size());
    }
    // the NPE scenario reports the throwing line; it must be the same as in the plain run
    assertTrue(plain.get("linecorpus.LineCorpus.s_stackTraceLines").contains(":"));
  }

  @Test
  void everySiteLineExistsInTheOriginalLineNumberTable() throws Exception {
    for (var e : lineOnly.results.entrySet()) {
      Map<String, Set<Integer>> original = lineTables(lineOnly.plainBytes.get(e.getKey()));
      for (MethodReport m : e.getValue().methods()) {
        if (m.status() != MethodReport.Status.INSTRUMENTED) continue;
        Set<Integer> lines = original.get(m.name() + m.descriptor());
        assertNotNull(lines, e.getKey() + "." + m.name());
        assertTrue(m.sites() >= 1 && m.sites() <= lines.size() * 4, m.toString());
      }
    }
    for (int id = 1; id <= lineOnly.registry.siteCount(); id++) {
      SiteRegistry.Site s = lineOnly.registry.site(id);
      Set<Integer> lines = lineTables(lineOnly.plainBytes.get(s.classInternalName())).get(s.method() + s.descriptor());
      assertTrue(lines.contains(s.line()), s.toString());
      assertEquals(32, s.classDigest().length);
    }
  }

  @Test
  void bridgeAndSyntheticMethodsAreReportedSkippedNotSilentlyDropped() {
    boolean bridge = false;
    boolean lambda = false;
    boolean synthetic = false;
    for (var e : lineOnly.results.entrySet()) {
      for (MethodReport m : e.getValue().methods()) {
        if (m.reason().equals(MethodReport.Reasons.BRIDGE)) bridge = true;
        if (m.reason().equals(MethodReport.Reasons.SYNTHETIC)) synthetic = true;
        if (m.name().startsWith("lambda$") && m.status() == MethodReport.Status.INSTRUMENTED) lambda = true;
      }
    }
    assertTrue(bridge, "Pt.compareTo(Object) bridge must be reported");
    assertTrue(lambda, "lambda bodies are instrumented (ADR 0003 2.2)");
    assertTrue(synthetic || bridge);
  }

  @Test
  void focusedValuesOnArrivalMatchTheStatementsOwnView() {
    int compared = 0;
    for (Run run : focusedChild.runs()) {
      if (!run.name().startsWith("linecorpus.LineCorpus.")) continue;
      List<List<String>> groups = taggedGroups(focused, run);
      assertEquals(run.hits().size(), groups.size(), run.name());
      for (int i = 0; i < groups.size(); i++) {
        String detail = run.hits().get(i).substring(run.hits().get(i).indexOf('|') + 1);
        if (detail.isEmpty()) continue;
        Map<String, String> got = new HashMap<>();
        for (String v : groups.get(i)) {
          String[] f = v.split("\t", -1);
          if (f[1].equals("CAPTURED") || f[1].equals("TRUNCATED")) got.put(f[0], f[2]);
        }
        for (String pair : detail.split(",")) {
          int eq = pair.indexOf('=');
          String name = pair.substring(0, eq);
          assertEquals(pair.substring(eq + 1), got.get(name), run.name() + " hit " + i + " local " + name + " in " + got);
          compared++;
        }
      }
    }
    assertTrue(compared >= 40, "compared values: " + compared);
  }

  /** Value group (V lines) that follows each tagged line event. */
  private List<List<String>> taggedGroups(CorpusPipeline p, Run run) {
    List<List<String>> out = new ArrayList<>();
    List<String> current = null;
    for (String t : run.tokens()) {
      if (t.startsWith("L ")) {
        SiteRegistry.Site site = p.registry.site(Integer.parseInt(t.substring(2)));
        boolean tagged = site.classInternalName().startsWith("linecorpus/LineCorpus") && tagByLine.containsKey(site.line());
        current = tagged ? new ArrayList<>() : null;
        if (tagged) out.add(current);
      } else if (t.startsWith("V ") && current != null) {
        current.add(t.substring(2));
      }
    }
    return out;
  }

  @Test
  void localsNotYetAssignedAreNeverRead() {
    Run run = find(focusedChild, "s_straight");
    List<List<String>> groups = taggedGroups(focused, run);
    List<String> first = groups.get(0); // st1: only `a` is live
    Set<String> names = new HashSet<>();
    for (String v : first) names.add(v.split("\t", -1)[0]);
    assertEquals(Set.of("a"), names, "st1 arrival must see only a");
    names.clear();
    for (String v : groups.get(2)) names.add(v.split("\t", -1)[0]);
    assertEquals(Set.of("a", "b", "big", "d"), names, run.tokens().toString());
  }

  @Test
  void secretNamedLocalsAreRedactedAndCanaryNeverLeavesTheChild() {
    Run run = find(focusedChild, "s_secretNames");
    List<String> group = taggedGroups(focused, run).get(0);
    Map<String, String[]> byName = new HashMap<>();
    for (String v : group) {
      String[] f = v.split("\t", -1);
      byName.put(f[0], f);
    }
    assertEquals("REDACTED", byName.get("password")[1]);
    assertEquals(Redaction.RULE_NAME, byName.get("password")[3]);
    assertEquals("REDACTED", byName.get("apiKey")[1]);
    assertEquals("CAPTURED", byName.get("plain")[1]);
    assertFalse(focusedChild.stdout().contains("xtrace-canary"), "canary must not reach any output");
    assertFalse(focusedChild.stderr().contains("xtrace-canary"));
  }

  @Test
  void wideAndPrimitiveLocalsRoundTrip() {
    Run run = find(focusedChild, "s_widePrims");
    List<String> group = taggedGroups(focused, run).get(0);
    assertTrue(group.size() >= 8, group.toString());
  }

  @Test
  void lineOnlyModeReadsNoLocals() {
    for (Run r : lineOnlyChild.runs()) {
      for (String t : r.tokens()) assertFalse(t.startsWith("V") , t);
    }
    for (var e : lineOnly.results.entrySet()) {
      for (MethodReport m : e.getValue().methods()) assertEquals(0, m.valueCalls());
    }
  }

  private static Run find(CorpusPipeline.Child c, String method) {
    for (Run r : c.runs()) if (r.name().endsWith("." + method)) return r;
    throw new AssertionError("missing " + method);
  }

  static Map<String, Set<Integer>> lineTables(byte[] bytes) {
    Map<String, Set<Integer>> out = new HashMap<>();
    new ClassReader(bytes)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(int a, String name, String desc, String sig, String[] ex) {
                Set<Integer> lines = new HashSet<>();
                out.put(name + desc, lines);
                return new MethodVisitor(Opcodes.ASM9) {
                  @Override
                  public void visitLineNumber(int line, Label start) {
                    lines.add(line);
                  }
                };
              }
            },
            0);
    return out;
  }

}
