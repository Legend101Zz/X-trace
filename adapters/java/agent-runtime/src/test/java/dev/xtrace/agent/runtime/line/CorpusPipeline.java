package dev.xtrace.agent.runtime.line;

import dev.xtrace.agent.runtime.line.CorpusHarness.Run;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/** Compiles the corpus, transforms it, runs it in a child JVM with -Xverify:all. */
final class CorpusPipeline {
  interface Transformer {
    LineProbeInstrumenter.Result transform(String internalName, byte[] bytes);
  }

  /** Parsed child output. */
  record Child(
      int exit,
      List<String> loaded,
      List<String> loadFailed,
      List<Run> runs,
      String stdout,
      String stderr) {}

  final Path work;
  final Path srcDir;
  final Path plainDir;
  final Path instrDir;
  final SiteRegistry registry;
  final Map<String, LineProbeInstrumenter.Result> results = new TreeMap<>();
  final Map<String, byte[]> plainBytes = new TreeMap<>();

  private CorpusPipeline(Path work, SiteRegistry registry) {
    this.work = work;
    this.srcDir = work.resolve("src");
    this.plainDir = work.resolve("plain");
    this.instrDir = work.resolve("instr");
    this.registry = registry;
  }

  static CorpusPipeline build(
      Path work, SiteRegistry registry, Map<String, String> extraSources, String[] javacFlags,
      java.util.function.Function<SiteRegistry, Transformer> transformerFactory)
      throws Exception {
    CorpusPipeline p = new CorpusPipeline(work, registry);
    Files.createDirectories(p.srcDir.resolve("linecorpus"));
    Files.createDirectories(p.plainDir);
    Files.createDirectories(p.instrDir);
    Files.writeString(
        p.srcDir.resolve("linecorpus/Trace.java"), resource("/line/Trace.java.txt"));
    Files.writeString(
        p.srcDir.resolve("linecorpus/LineCorpus.java"), resource("/line/LineCorpus.java.txt"));
    for (Map.Entry<String, String> e : extraSources.entrySet()) {
      Files.writeString(p.srcDir.resolve("linecorpus/" + e.getKey() + ".java"), e.getValue());
    }
    compile(p.srcDir, p.plainDir, javacFlags);
    Transformer t = transformerFactory.apply(registry);
    try (Stream<Path> s = Files.walk(p.plainDir)) {
      for (Path f : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
        String internal = p.plainDir.relativize(f).toString().replace('\\', '/');
        internal = internal.substring(0, internal.length() - ".class".length());
        byte[] bytes = Files.readAllBytes(f);
        p.plainBytes.put(internal, bytes);
        LineProbeInstrumenter.Result r = t.transform(internal, bytes);
        p.results.put(internal, r);
        Path out = p.instrDir.resolve(internal + ".class");
        Files.createDirectories(out.getParent());
        Files.write(out, r.bytes());
      }
    }
    return p;
  }

  static java.util.function.Function<SiteRegistry, Transformer> byteApi(LineProbeConfig cfg) {
    return reg -> {
      LineProbeInstrumenter inst = new LineProbeInstrumenter(cfg, reg);
      return (name, bytes) -> inst.instrument(bytes);
    };
  }

  static String resource(String name) throws IOException {
    try (var in = CorpusPipeline.class.getResourceAsStream(name)) {
      if (in == null) throw new IOException("missing resource " + name);
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  static void compile(Path src, Path out, String[] flags) throws Exception {
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    if (javac == null) throw new IllegalStateException("tests need a JDK (javax.tools)");
    List<String> args = new ArrayList<>(List.of(flags));
    args.add("-d");
    args.add(out.toString());
    try (Stream<Path> s = Files.walk(src)) {
      s.filter(x -> x.toString().endsWith(".java")).forEach(x -> args.add(x.toString()));
    }
    int rc = javac.run(null, null, null, args.toArray(new String[0]));
    if (rc != 0) throw new IllegalStateException("javac failed rc=" + rc);
  }

  List<String> classNames() {
    List<String> out = new ArrayList<>();
    for (String n : plainBytes.keySet()) out.add(n.replace('/', '.'));
    return out;
  }

  /** In-process run of the uninstrumented classes. */
  List<Run> runPlain() throws Exception {
    try (var loader = CorpusHarness.loaderFor(plainDir)) {
      return CorpusHarness.runAll(loader, Map.of(), classNames());
    }
  }

  /** Child JVM with -Xverify:all, instrumented classes first on the class path. */
  Child runChild() throws Exception {
    Path classes = work.resolve("classes.txt");
    Files.write(classes, classNames());
    Path names = work.resolve("names.tsv");
    List<String> lines = new ArrayList<>();
    for (int i = 1; i <= registry.nameCount(); i++) {
      SiteRegistry.Name n = registry.name(i);
      lines.add(n.id() + "\t" + n.name() + "\t" + n.descriptor() + "\t" + n.slot());
    }
    Files.write(names, lines);

    Set<String> cp = new LinkedHashSet<>();
    cp.add(instrDir.toString());
    for (Class<?> c :
        List.of(
            CorpusHarness.class,
            LineProbeDispatch.class,
            net.bytebuddy.jar.asm.ClassReader.class,
            org.bouncycastle.crypto.digests.Blake3Digest.class)) {
      cp.add(location(c));
    }
    Path out = work.resolve("child.out");
    Path err = work.resolve("child.err");
    String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    ProcessBuilder pb =
        new ProcessBuilder(
            javaBin,
            "-Xverify:all",
            "-cp",
            String.join(java.io.File.pathSeparator, cp),
            CorpusHarness.class.getName(),
            classes.toString(),
            names.toString());
    pb.redirectOutput(out.toFile()).redirectError(err.toFile());
    Process proc = pb.start();
    if (!proc.waitFor(240, TimeUnit.SECONDS)) {
      proc.destroyForcibly();
      throw new IllegalStateException("child JVM timed out");
    }
    String stdout = Files.readString(out);
    String stderr = Files.readString(err);
    return parse(proc.exitValue(), stdout, stderr);
  }

  private static String location(Class<?> c) throws URISyntaxException {
    return Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
  }

  static Child parse(int exit, String stdout, String stderr) {
    List<String> loaded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    List<Run> runs = new ArrayList<>();
    String name = null;
    List<String> tokens = new ArrayList<>();
    List<String> hits = new ArrayList<>();
    String result = null;
    for (String line : stdout.split("\n")) {
      if (line.startsWith("LOADED ")) loaded.add(line.substring(7));
      else if (line.startsWith("LOAD_FAILED ")) failed.add(line.substring(12));
      else if (line.startsWith("SCENARIO ")) {
        name = line.substring(9);
        tokens = new ArrayList<>();
        hits = new ArrayList<>();
        result = null;
      } else if (line.startsWith("T ")) tokens.add(CorpusHarness.unesc(line.substring(2)));
      else if (line.startsWith("HIT ")) hits.add(CorpusHarness.unesc(line.substring(4)));
      else if (line.startsWith("RESULT ")) result = CorpusHarness.unesc(line.substring(7));
      else if (line.equals("END")) runs.add(new Run(name, tokens, hits, result));
    }
    return new Child(exit, loaded, failed, runs, stdout, stderr);
  }

  static Map<String, String> noExtra() {
    return new LinkedHashMap<>();
  }
}
