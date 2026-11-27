package dev.xtrace.analyzer;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Command line entry point: {@code xtrace-java-static --source-root DIR [--framework F]}. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Path root = null;
        String framework = SpringMvcAnalyzer.FRAMEWORK_MVC;
        int maxFiles = StaticAnalysisSupport.DEFAULT_MAX_FILES;
        long maxFileBytes = StaticAnalysisSupport.DEFAULT_MAX_FILE_BYTES;
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
        List<String> lines;
        switch (framework) {
            case SpringMvcAnalyzer.FRAMEWORK_MVC, SpringMvcAnalyzer.FRAMEWORK_WEBFLUX ->
                    lines = new SpringMvcAnalyzer(framework, maxFiles, maxFileBytes).analyze(root);
            case JaxRsAnalyzer.FRAMEWORK_JAXRS ->
                    lines = new JaxRsAnalyzer(maxFiles, maxFileBytes).analyze(root);
            default -> {
                usage("framework must be spring-mvc, spring-webflux or jaxrs");
                return;
            }
        }
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        for (String line : lines) {
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
        System.err.println(
                "usage: xtrace-java-static --source-root DIR [--framework spring-mvc|spring-webflux|jaxrs]"
                        + " [--max-files N] [--max-file-bytes N]");
        System.exit(2);
    }
}
