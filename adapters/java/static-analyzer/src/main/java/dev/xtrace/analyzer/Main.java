package dev.xtrace.analyzer;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Command line entry point: {@code xtrace-java-static --source-root DIR [--framework F]}. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Path root = null;
        String framework = SpringMvcAnalyzer.FRAMEWORK_MVC;
        int maxFiles = SpringMvcAnalyzer.DEFAULT_MAX_FILES;
        long maxFileBytes = SpringMvcAnalyzer.DEFAULT_MAX_FILE_BYTES;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--source-root" -> root = Path.of(next(args, ++i));
                case "--framework" -> framework = next(args, ++i);
                case "--max-files" -> maxFiles = Integer.parseInt(next(args, ++i));
                case "--max-file-bytes" -> maxFileBytes = Long.parseLong(next(args, ++i));
                default -> usage("unknown argument " + args[i]);
            }
        }
        if (root == null) {
            usage("--source-root is required");
        }
        if (!Files.isDirectory(root)) {
            usage("source root is not a directory");
        }
        if (!framework.equals(SpringMvcAnalyzer.FRAMEWORK_MVC)
                && !framework.equals(SpringMvcAnalyzer.FRAMEWORK_WEBFLUX)) {
            usage("framework must be spring-mvc or spring-webflux");
        }
        SpringMvcAnalyzer analyzer = new SpringMvcAnalyzer(framework, maxFiles, maxFileBytes);
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        for (String line : analyzer.analyze(root)) {
            out.print(line);
            out.print('\n');
        }
        out.flush();
    }

    private static String next(String[] args, int index) {
        if (index >= args.length) {
            usage("missing value for " + args[index - 1]);
        }
        return args[index];
    }

    private static void usage(String message) {
        System.err.println("xtrace-java-static: " + message);
        System.err.println("usage: xtrace-java-static --source-root DIR [--framework spring-mvc|spring-webflux]"
                + " [--max-files N] [--max-file-bytes N]");
        System.exit(2);
    }
}
