package dev.xtrace.analyzer;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Range;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.TextBlockLiteralExpr;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads Spring MVC / WebFlux annotated controllers from source text and writes the static-claim JSON
 * lines described in {@code schema/fixtures/static-claim-contract.json}.
 *
 * <p>The analyzer only parses. It never loads, links, initializes or runs the code it reads, and it
 * starts no process.
 */
public final class SpringMvcAnalyzer {
    public static final String FRAMEWORK_MVC = "spring-mvc";
    public static final String FRAMEWORK_WEBFLUX = "spring-webflux";
    public static final int DEFAULT_MAX_FILES = 20_000;
    public static final long DEFAULT_MAX_FILE_BYTES = 1L << 20;

    static final String NAME = "xtrace-java-static";
    static final String VERSION = "0.0.1";
    static final String RULESET = "spring-mvc-annotations/1";

    private static final Set<String> SKIPPED_DIRECTORIES =
            Set.of(".git", ".gradle", ".idea", ".mvn", "build", "node_modules", "out", "target");
    private static final Map<String, String> SHORTCUT_METHODS = Map.of(
            "GetMapping", "GET",
            "PostMapping", "POST",
            "PutMapping", "PUT",
            "DeleteMapping", "DELETE",
            "PatchMapping", "PATCH");
    /** Methods a {@code @RequestMapping} without {@code method} answers that the catalog lists. */
    private static final List<String> UNCONSTRAINED_METHODS = List.of("GET", "POST", "PUT", "PATCH", "DELETE");

    private final String framework;
    private final int maxFiles;
    private final long maxFileBytes;

    public SpringMvcAnalyzer(String framework, int maxFiles, long maxFileBytes) {
        this.framework = framework;
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
    }

    /** How the text of a path expression was obtained, ordered from strongest to weakest. */
    enum Basis {
        LITERAL("literal"),
        CONCATENATED("concatenated"),
        COMPUTED("computed");

        final String wire;

        Basis(String wire) {
            this.wire = wire;
        }

        Basis weakest(Basis other) {
            return other.ordinal() > ordinal() ? other : this;
        }
    }

    /** Evaluated path expression. */
    record PathValue(String text, Basis basis, boolean unresolved) {}

    /** A parsed source file plus where it came from. */
    private record Source(String relativePath, CompilationUnit unit) {}

    /** All lines of the transcript for {@code root}, in order. */
    public List<String> analyze(Path root) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("{\"type\":\"header\",\"contractVersion\":1,\"analyzerName\":" + Json.string(NAME)
                + ",\"analyzerVersion\":" + Json.string(VERSION) + ",\"rulesetId\":" + Json.string(RULESET)
                + ",\"framework\":" + Json.string(framework) + "}");

        Set<String> incomplete = new TreeSet<>();
        List<String> diagnostics = new ArrayList<>();
        List<Path> files = collect(root, incomplete, diagnostics);

        ParserConfiguration configuration =
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        configuration.setAttributeComments(false);
        JavaParser parser = new JavaParser(configuration);

        List<Source> sources = new ArrayList<>();
        int scanned = 0;
        for (Path file : files) {
            String relative = relativize(root, file);
            try {
                if (Files.size(file) > maxFileBytes) {
                    diagnostics.add(diagnostic("file_too_large", relative));
                    incomplete.add("budget_exceeded");
                    continue;
                }
                ParseResult<CompilationUnit> result = parser.parse(file);
                scanned++;
                if (!result.isSuccessful() || result.getResult().isEmpty()) {
                    diagnostics.add(diagnostic("parse_error", relative));
                    incomplete.add("parse_error");
                    continue;
                }
                sources.add(new Source(relative, result.getResult().get()));
            } catch (IOException | RuntimeException e) {
                diagnostics.add(diagnostic("file_unreadable", relative));
                incomplete.add("file_unreadable");
            }
        }

        Constants constants = Constants.collect(sources.stream().map(Source::unit).toList());
        List<String> claims = new LinkedHashSet<>(claimsFor(sources, constants)).stream().toList();
        lines.addAll(claims);
        lines.addAll(diagnostics);
        lines.add("{\"type\":\"end\",\"claims\":" + claims.size() + ",\"filesScanned\":" + scanned
                + ",\"complete\":" + incomplete.isEmpty() + ",\"incompleteReasons\":"
                + Json.stringArray(new ArrayList<>(incomplete)) + "}");
        return lines;
    }

    private List<Path> collect(Path root, Set<String> incomplete, List<String> diagnostics)
            throws IOException {
        List<Path> found = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && SKIPPED_DIRECTORIES.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile() && !attrs.isSymbolicLink()
                        && file.getFileName().toString().endsWith(".java")) {
                    if (found.size() >= maxFiles) {
                        incomplete.add("budget_exceeded");
                        return FileVisitResult.CONTINUE;
                    }
                    found.add(file);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                diagnostics.add(diagnostic("file_unreadable", relativize(root, file)));
                incomplete.add("file_unreadable");
                return FileVisitResult.CONTINUE;
            }
        });
        found.sort(Comparator.comparing(path -> relativize(root, path)));
        return found;
    }

    private static String relativize(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }

    private static String diagnostic(String code, String path) {
        return "{\"type\":\"diagnostic\",\"code\":" + Json.string(code) + ",\"path\":" + Json.string(path) + "}";
    }

    private List<String> claimsFor(List<Source> sources, Constants constants) {
        List<String> claims = new ArrayList<>();
        for (Source source : sources) {
            for (ClassOrInterfaceDeclaration type : source.unit().findAll(ClassOrInterfaceDeclaration.class)) {
                if (!isHandlerType(type)) {
                    continue;
                }
                List<PathValue> prefixes = classPrefixes(type, constants);
                for (MethodDeclaration method : type.getMethods()) {
                    for (AnnotationExpr annotation : method.getAnnotations()) {
                        Mapping mapping = mappingOf(annotation, type, constants);
                        if (mapping != null) {
                            emit(claims, source, type, method, mapping, prefixes);
                        }
                    }
                }
            }
        }
        return claims;
    }

    private void emit(
            List<String> claims,
            Source source,
            ClassOrInterfaceDeclaration type,
            MethodDeclaration method,
            Mapping mapping,
            List<PathValue> prefixes) {
        Optional<Range> range = mapping.annotation().getRange();
        if (range.isEmpty()) {
            return;
        }
        Range r = range.get();
        String handler = binaryName(type) + "#" + method.getNameAsString();
        for (PathValue prefix : prefixes) {
            for (PathValue path : mapping.paths()) {
                for (String httpMethod : mapping.methods()) {
                    Basis basis = prefix.basis().weakest(path.basis());
                    Set<String> limitations = new TreeSet<>();
                    if (prefix.unresolved() || path.unresolved()) {
                        limitations.add("route_constant_unresolved");
                    }
                    if (mapping.unconstrained()) {
                        limitations.add("mapping_method_unconstrained");
                    }
                    claims.add("{\"type\":\"claim\",\"method\":" + Json.string(httpMethod)
                            + ",\"routeParts\":" + Json.stringArray(List.of(prefix.text(), path.text()))
                            + ",\"routeBasis\":" + Json.string(basis.wire)
                            + ",\"handler\":" + Json.string(handler)
                            + ",\"limitations\":" + Json.stringArray(new ArrayList<>(limitations))
                            + ",\"evidence\":{\"path\":" + Json.string(source.relativePath())
                            + ",\"startLine\":" + r.begin.line + ",\"startColumn\":" + r.begin.column
                            + ",\"endLine\":" + r.end.line + ",\"endColumn\":" + r.end.column + "}}");
                }
            }
        }
    }

    private static boolean isHandlerType(ClassOrInterfaceDeclaration type) {
        if (type.isInterface() && hasAnnotation(type, "FeignClient")) {
            return false;
        }
        return hasAnnotation(type, "Controller") || hasAnnotation(type, "RestController");
    }

    private static boolean hasAnnotation(BodyDeclaration<?> declaration, String simpleName) {
        return declaration.getAnnotations().stream().anyMatch(a -> simpleName(a).equals(simpleName));
    }

    private static String simpleName(AnnotationExpr annotation) {
        String name = annotation.getNameAsString();
        return name.substring(name.lastIndexOf('.') + 1);
    }

    private List<PathValue> classPrefixes(ClassOrInterfaceDeclaration type, Constants constants) {
        for (AnnotationExpr annotation : type.getAnnotations()) {
            if (simpleName(annotation).equals("RequestMapping")) {
                List<PathValue> paths = pathsOf(annotation, type, constants);
                return paths.isEmpty() ? List.of(new PathValue("", Basis.LITERAL, false)) : paths;
            }
        }
        return List.of(new PathValue("", Basis.LITERAL, false));
    }

    /** One method-level mapping annotation. */
    private record Mapping(AnnotationExpr annotation, List<PathValue> paths, List<String> methods, boolean unconstrained) {}

    private Mapping mappingOf(AnnotationExpr annotation, TypeDeclaration<?> owner, Constants constants) {
        String name = simpleName(annotation);
        List<PathValue> paths = pathsOf(annotation, owner, constants);
        if (paths.isEmpty()) {
            paths = List.of(new PathValue("", Basis.LITERAL, false));
        }
        String shortcut = SHORTCUT_METHODS.get(name);
        if (shortcut != null) {
            return new Mapping(annotation, paths, List.of(shortcut), false);
        }
        if (!name.equals("RequestMapping")) {
            return null;
        }
        List<String> methods = requestMethods(annotation);
        if (methods.isEmpty()) {
            return new Mapping(annotation, paths, UNCONSTRAINED_METHODS, true);
        }
        return new Mapping(annotation, paths, methods, false);
    }

    private static List<String> requestMethods(AnnotationExpr annotation) {
        List<String> methods = new ArrayList<>();
        if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (pair.getNameAsString().equals("method")) {
                    for (Expression expression : elements(pair.getValue())) {
                        String text = expression instanceof FieldAccessExpr access
                                ? access.getNameAsString()
                                : expression instanceof NameExpr nameExpr ? nameExpr.getNameAsString() : "";
                        if (List.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE").contains(text)) {
                            methods.add(text);
                        }
                    }
                }
            }
        }
        return methods;
    }

    private List<PathValue> pathsOf(AnnotationExpr annotation, TypeDeclaration<?> owner, Constants constants) {
        List<PathValue> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            for (Expression expression : elements(single.getMemberValue())) {
                values.add(constants.evaluate(expression, owner));
            }
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                String key = pair.getNameAsString();
                if (key.equals("value") || key.equals("path")) {
                    for (Expression expression : elements(pair.getValue())) {
                        values.add(constants.evaluate(expression, owner));
                    }
                }
            }
        }
        return values;
    }

    private static List<Expression> elements(Expression expression) {
        if (expression instanceof ArrayInitializerExpr array) {
            return new ArrayList<>(array.getValues());
        }
        return List.of(expression);
    }

    private static String binaryName(TypeDeclaration<?> type) {
        StringBuilder name = new StringBuilder(type.getNameAsString());
        Node parent = type.getParentNode().orElse(null);
        while (parent != null) {
            if (parent instanceof TypeDeclaration<?> outer) {
                name.insert(0, outer.getNameAsString() + "$");
            } else if (parent instanceof CompilationUnit unit) {
                unit.getPackageDeclaration().ifPresent(p -> name.insert(0, p.getNameAsString() + "."));
            }
            parent = parent.getParentNode().orElse(null);
        }
        return name.toString();
    }

    /** String constants ({@code static final String}) found in the scanned sources. */
    static final class Constants {
        /** Simple class name to constant name to value. */
        private final Map<String, Map<String, String>> byClass = new HashMap<>();

        static Constants collect(List<CompilationUnit> units) {
            Constants constants = new Constants();
            Map<String, VariableDeclarator> pending = new HashMap<>();
            Map<String, TypeDeclaration<?>> owners = new HashMap<>();
            for (CompilationUnit unit : units) {
                for (FieldDeclaration field : unit.findAll(FieldDeclaration.class)) {
                    if (!field.hasModifier(Modifier.Keyword.STATIC) || !field.hasModifier(Modifier.Keyword.FINAL)) {
                        continue;
                    }
                    Optional<TypeDeclaration> owner = field.findAncestor(TypeDeclaration.class);
                    if (owner.isEmpty()) {
                        continue;
                    }
                    for (VariableDeclarator variable : field.getVariables()) {
                        if (variable.getType().asString().equals("String") && variable.getInitializer().isPresent()) {
                            String key = owner.get().getNameAsString() + "." + variable.getNameAsString();
                            pending.putIfAbsent(key, variable);
                            owners.putIfAbsent(key, owner.get());
                        }
                    }
                }
            }
            // Constants may refer to each other; a bounded number of passes settles every chain.
            for (int pass = 0; pass < 8; pass++) {
                boolean changed = false;
                for (Map.Entry<String, VariableDeclarator> entry : pending.entrySet()) {
                    String key = entry.getKey();
                    int dot = key.indexOf('.');
                    String type = key.substring(0, dot);
                    String name = key.substring(dot + 1);
                    if (constants.byClass.getOrDefault(type, Map.of()).containsKey(name)) {
                        continue;
                    }
                    PathValue value = constants.evaluate(entry.getValue().getInitializer().get(), owners.get(key));
                    if (!value.unresolved()) {
                        constants.byClass.computeIfAbsent(type, k -> new HashMap<>()).put(name, value.text());
                        changed = true;
                    }
                }
                if (!changed) {
                    break;
                }
            }
            return constants;
        }

        PathValue evaluate(Expression expression, TypeDeclaration<?> owner) {
            if (expression instanceof StringLiteralExpr literal) {
                return new PathValue(literal.asString(), Basis.LITERAL, false);
            }
            if (expression instanceof TextBlockLiteralExpr block) {
                return new PathValue(block.asString(), Basis.LITERAL, false);
            }
            if (expression instanceof EnclosedExpr enclosed) {
                return evaluate(enclosed.getInner(), owner);
            }
            if (expression instanceof BinaryExpr binary && binary.getOperator() == BinaryExpr.Operator.PLUS) {
                PathValue left = evaluate(binary.getLeft(), owner);
                PathValue right = evaluate(binary.getRight(), owner);
                if (left.unresolved() || right.unresolved()) {
                    return new PathValue(left.text() + right.text(), Basis.COMPUTED, true);
                }
                return new PathValue(left.text() + right.text(), Basis.CONCATENATED, false);
            }
            if (expression instanceof NameExpr name) {
                return lookup(null, name.getNameAsString(), owner);
            }
            if (expression instanceof FieldAccessExpr access && access.getScope() instanceof NameExpr scope) {
                return lookup(scope.getNameAsString(), access.getNameAsString(), owner);
            }
            return new PathValue("{unresolved}", Basis.COMPUTED, true);
        }

        private PathValue lookup(String type, String name, TypeDeclaration<?> owner) {
            String placeholder = "{" + (name.matches("[A-Za-z0-9_.-]+") ? name : "unresolved") + "}";
            if (type != null) {
                String value = byClass.getOrDefault(type, Map.of()).get(name);
                return value == null
                        ? new PathValue(placeholder, Basis.COMPUTED, true)
                        : new PathValue(value, Basis.CONCATENATED, false);
            }
            // Own class first (nested types see their enclosing types' constants), then a unique match anywhere.
            Node node = owner;
            while (node != null) {
                if (node instanceof TypeDeclaration<?> declaration) {
                    String value = byClass.getOrDefault(declaration.getNameAsString(), Map.of()).get(name);
                    if (value != null) {
                        return new PathValue(value, Basis.CONCATENATED, false);
                    }
                }
                node = node.getParentNode().orElse(null);
            }
            Set<String> candidates = new LinkedHashSet<>();
            for (Map<String, String> constants : byClass.values()) {
                if (constants.containsKey(name)) {
                    candidates.add(constants.get(name));
                }
            }
            if (candidates.size() == 1) {
                return new PathValue(candidates.iterator().next(), Basis.CONCATENATED, false);
            }
            return new PathValue(placeholder, Basis.COMPUTED, true);
        }
    }
}
