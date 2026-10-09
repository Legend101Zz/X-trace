package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs the corpus scenarios. Used in the child JVM (started with -Xverify:all) with instrumented
 * classes first on the class path, and in-process for the uninstrumented baseline.
 */
public final class CorpusHarness {
  /** Result of one scenario. */
  public record Run(String name, List<String> tokens, List<String> hits, String result) {}

  private CorpusHarness() {}

  /** Args: classes.txt (names to link+initialize), names.tsv (may be missing). */
  public static void main(String[] args) throws Exception {
    List<String> classNames = Files.readAllLines(Path.of(args[0]));
    Map<Integer, SiteRegistry.Name> names = loadNames(args.length > 1 ? Path.of(args[1]) : null);
    ClassLoader loader = CorpusHarness.class.getClassLoader();
    StringBuilder out = new StringBuilder();
    for (String c : classNames) {
      try {
        Class.forName(c, true, loader);
        out.append("LOADED ").append(c).append('\n');
      } catch (Throwable t) {
        out.append("LOAD_FAILED ").append(c).append(' ').append(t.getClass().getName()).append('\n');
      }
    }
    System.out.print(out);
    for (Run r : runAll(loader, names, classNames)) {
      System.out.println("SCENARIO " + r.name());
      for (String t : r.tokens()) System.out.println("T " + esc(t));
      for (String h : r.hits()) System.out.println("HIT " + esc(h));
      System.out.println("RESULT " + esc(r.result()));
      System.out.println("END");
    }
    System.out.flush();
  }

  /** Runs every static {@code s_*} method of each named class (name order), classes in list order. */
  @SuppressWarnings("unchecked")
  public static List<Run> runAll(
      ClassLoader loader, Map<Integer, SiteRegistry.Name> names, List<String> classNames)
      throws Exception {
    Class<?> trace = Class.forName("linecorpus.Trace", true, loader);
    List<String> hits = (List<String>) trace.getField("HITS").get(null);
    RecordingSink sink = new RecordingSink(names);
    LineProbeDispatch.install(sink);
    List<Run> runs = new ArrayList<>();
    try {
      for (String className : classNames) {
        Class<?> corpus;
        try {
          corpus = Class.forName(className, true, loader);
        } catch (Throwable t) {
          continue;
        }
        List<Method> methods = new ArrayList<>();
        for (Method m : corpus.getDeclaredMethods()) {
          if (m.getName().startsWith("s_")) methods.add(m);
        }
        methods.sort((x, y) -> x.getName().compareTo(y.getName()));
        for (Method m : methods) {
          hits.clear();
          sink.tokens.clear();
          String result;
          try {
            result = (String) m.invoke(null);
          } catch (InvocationTargetException e) {
            result = "THROWN " + e.getCause().getClass().getName();
          }
          runs.add(
              new Run(
                  className + "." + m.getName(),
                  new ArrayList<>(sink.tokens),
                  new ArrayList<>(hits),
                  result));
        }
      }
    } finally {
      LineProbeDispatch.install(null);
    }
    return runs;
  }

  static Map<Integer, SiteRegistry.Name> loadNames(Path file) throws Exception {
    Map<Integer, SiteRegistry.Name> out = new HashMap<>();
    if (file == null || !Files.exists(file)) return out;
    for (String line : Files.readAllLines(file)) {
      String[] p = line.split("\t", -1);
      int id = Integer.parseInt(p[0]);
      out.put(id, new SiteRegistry.Name(id, p[1], p[2], Integer.parseInt(p[3])));
    }
    return out;
  }

  /** Records line events and sanitized value snapshots as printable tokens. */
  static final class RecordingSink implements LineProbeSink {
    final List<String> tokens = new ArrayList<>();
    private final Map<Integer, SiteRegistry.Name> names;

    RecordingSink(Map<Integer, SiteRegistry.Name> names) {
      this.names = names;
    }

    @Override
    public void line(int siteId) {
      tokens.add("L " + siteId);
    }

    @Override
    public void valuesBegin(int siteId) {
      tokens.add("VB " + siteId);
    }

    @Override
    public void valueInt(int slot, int nameId, int value) {
      add(ValueSanitizer.ofInt(names.get(nameId), value, Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }

    @Override
    public void valueLong(int slot, int nameId, long value) {
      add(ValueSanitizer.ofLong(names.get(nameId), value, Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }

    @Override
    public void valueFloat(int slot, int nameId, float value) {
      add(ValueSanitizer.ofFloat(names.get(nameId), value, Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }

    @Override
    public void valueDouble(int slot, int nameId, double value) {
      add(ValueSanitizer.ofDouble(names.get(nameId), value, Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }

    @Override
    public void valueRef(int nameId, int role, Object value) {
      SiteRegistry.Name n = names.get(nameId);
      add(
          ValueSanitizer.ofRef(
              n.name(), NameOrigin.DECLARED, value, Role.LOCAL, ValueSanitizer.Limits.FOCUSED));
    }

    @Override
    public void valuesEnd() {
      tokens.add("VE");
    }

    private void add(ValueSnapshot s) {
      tokens.add(
          "V " + s.name() + "\t" + s.state() + "\t" + (s.preview() == null ? "" : s.preview())
              + "\t" + (s.ruleId() == null ? "" : s.ruleId()) + "\t" + s.typeName());
    }
  }

  static String esc(String s) {
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r");
  }

  static String unesc(String s) {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\' && i + 1 < s.length()) {
        char n = s.charAt(++i);
        b.append(n == 'n' ? '\n' : n == 'r' ? '\r' : n);
      } else {
        b.append(c);
      }
    }
    return b.toString();
  }

  static URLClassLoader loaderFor(Path dir) throws Exception {
    return new URLClassLoader(new URL[] {dir.toUri().toURL()}, CorpusHarness.class.getClassLoader());
  }
}
