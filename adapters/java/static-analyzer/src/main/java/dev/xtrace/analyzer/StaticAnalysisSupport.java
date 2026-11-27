package dev.xtrace.analyzer;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Range;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.AnnotationDeclaration;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.NameExpr;
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Shared parsing, constant evaluation, and JSON-lines emission helpers for Java static analyzers.
 *
 * <p>Only parses Java source text; never loads, links, initializes, or runs analyzed code.
 */
final class StaticAnalysisSupport {
    static final int DEFAULT_MAX_FILES = 20_000;
    static final long DEFAULT_MAX_FILE_BYTES = 1L << 20;
    static final String NAME = "xtrace-java-static";
    static final String VERSION = "0.0.1";

    private static final Set<String> SKIPPED_DIRECTORIES =
            Set.of(".git", ".gradle", ".idea", ".mvn", "build", "node_modules", "out", "target");

    private StaticAnalysisSupport() {}

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

    /** Evaluated string expression. */
    record PathValue(String text, Basis basis, boolean unresolved) {}

    /** A parsed source file plus its source-root-relative path. */
    record Source(String relativePath, CompilationUnit unit) {}

    /** Collected and parsed sources together with diagnostics and completeness state. */
    record ParsedProject(
            List<Source> sources,
            int filesScanned,
            Set<String> incomplete,
            List<String> diagnostics) {}

    /** Resolves well-known framework constants (such as JAX-RS {@code MediaType}) not defined in repo sources. */
    @FunctionalInterface
    interface BuiltinResolver {
        Optional<String> resolve(String qualifier, String member, CompilationUnit unit);
    }

    static ParsedProject collectAndParse(Path root, int maxFiles, long maxFileBytes) throws IOException {
        Set<String> incomplete = new TreeSet<>();
        List<String> diagnostics = new ArrayList<>();
        List<Path> files = collect(root, maxFiles, incomplete, diagnostics);

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
        return new ParsedProject(sources, scanned, incomplete, diagnostics);
    }

    private static List<Path> collect(
            Path root, int maxFiles, Set<String> incomplete, List<String> diagnostics)
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
                if (attrs.isRegularFile()
                        && !attrs.isSymbolicLink()
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

    static String relativize(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }

    static String headerLine(String rulesetId, String framework) {
        return "{\"type\":\"header\",\"contractVersion\":1,\"analyzerName\":" + Json.string(NAME)
                + ",\"analyzerVersion\":" + Json.string(VERSION)
                + ",\"rulesetId\":" + Json.string(rulesetId)
                + ",\"framework\":" + Json.string(framework) + "}";
    }

    static String claimLine(
            String method,
            List<String> routeParts,
            Basis basis,
            String handler,
            Set<String> limitations,
            String sourcePath,
            Range range) {
        return "{\"type\":\"claim\",\"method\":" + Json.string(method)
                + ",\"routeParts\":" + Json.stringArray(routeParts)
                + ",\"routeBasis\":" + Json.string(basis.wire)
                + ",\"handler\":" + Json.string(handler)
                + ",\"limitations\":" + Json.stringArray(new ArrayList<>(limitations))
                + ",\"evidence\":{\"path\":" + Json.string(sourcePath)
                + ",\"startLine\":" + range.begin.line
                + ",\"startColumn\":" + range.begin.column
                + ",\"endLine\":" + range.end.line
                + ",\"endColumn\":" + range.end.column + "}}";
    }

    static String diagnostic(String code, String path) {
        return "{\"type\":\"diagnostic\",\"code\":" + Json.string(code) + ",\"path\":" + Json.string(path) + "}";
    }

    static String endLine(int claims, int filesScanned, Set<String> incomplete) {
        return "{\"type\":\"end\",\"claims\":" + claims
                + ",\"filesScanned\":" + filesScanned
                + ",\"complete\":" + incomplete.isEmpty()
                + ",\"incompleteReasons\":" + Json.stringArray(new ArrayList<>(incomplete)) + "}";
    }

    static boolean hasAnnotation(BodyDeclaration<?> declaration, String simpleName) {
        return declaration.getAnnotations().stream().anyMatch(a -> simpleName(a).equals(simpleName));
    }

    static String simpleName(AnnotationExpr annotation) {
        String name = annotation.getNameAsString();
        return name.substring(name.lastIndexOf('.') + 1);
    }

    static List<Expression> elements(Expression expression) {
        if (expression instanceof ArrayInitializerExpr array) {
            return new ArrayList<>(array.getValues());
        }
        return List.of(expression);
    }

    static String binaryName(TypeDeclaration<?> type) {
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

    static String packageName(CompilationUnit unit) {
        if (unit == null) {
            return "";
        }
        return unit.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
    }

    static String dottedTypeName(TypeDeclaration<?> type) {
        StringBuilder name = new StringBuilder(type.getNameAsString());
        Node parent = type.getParentNode().orElse(null);
        while (parent instanceof TypeDeclaration<?> outer) {
            name.insert(0, outer.getNameAsString() + ".");
            parent = outer.getParentNode().orElse(null);
        }
        return name.toString();
    }

    static String qualifiedTypeName(TypeDeclaration<?> type) {
        String pkg = packageName(type.findCompilationUnit().orElse(null));
        String dotted = dottedTypeName(type);
        return pkg.isEmpty() ? dotted : pkg + "." + dotted;
    }

    /** Collects annotation declarations by package so local custom annotations are not misread as framework ones. */
    static Map<String, Set<String>> collectAnnotationDeclarations(List<CompilationUnit> units) {
        Map<String, Set<String>> declared = new HashMap<>();
        for (CompilationUnit unit : units) {
            String pkg = packageName(unit);
            for (AnnotationDeclaration ann : unit.findAll(AnnotationDeclaration.class)) {
                declared.computeIfAbsent(pkg, k -> new LinkedHashSet<>()).add(ann.getNameAsString());
            }
        }
        return declared;
    }

    /** String constants ({@code static final String} and interface {@code String} fields) found in scanned sources. */
    static final class Constants {
        private record Pending(String fqn, String typePath, String name, Expression init, TypeDeclaration<?> owner) {}

        /** Fully qualified type name -> constant name -> resolved string value. */
        private final Map<String, Map<String, String>> byFqn = new LinkedHashMap<>();
        /** Simple or inner dotted type path -> list of FQNs declaring that type path. */
        private final Map<String, Set<String>> fqnsByTypePath = new LinkedHashMap<>();
        private final BuiltinResolver builtin;

        private Constants(BuiltinResolver builtin) {
            this.builtin = builtin;
        }

        static Constants collect(List<CompilationUnit> units) {
            return collect(units, null);
        }

        static Constants collect(List<CompilationUnit> units, BuiltinResolver builtin) {
            Constants constants = new Constants(builtin);
            List<Pending> pending = new ArrayList<>();
            for (CompilationUnit unit : units) {
                for (FieldDeclaration field : unit.findAll(FieldDeclaration.class)) {
                    Optional<TypeDeclaration> ownerOpt = field.findAncestor(TypeDeclaration.class);
                    if (ownerOpt.isEmpty()) {
                        continue;
                    }
                    TypeDeclaration<?> owner = ownerOpt.get();
                    boolean inInterface =
                            owner instanceof ClassOrInterfaceDeclaration cid && cid.isInterface();
                    boolean isStaticFinal = (field.hasModifier(Modifier.Keyword.STATIC)
                                    && field.hasModifier(Modifier.Keyword.FINAL))
                            || inInterface;
                    if (!isStaticFinal) {
                        continue;
                    }
                    String fqn = qualifiedTypeName(owner);
                    String typePath = dottedTypeName(owner);
                    constants.fqnsByTypePath.computeIfAbsent(typePath, k -> new LinkedHashSet<>()).add(fqn);
                    for (VariableDeclarator variable : field.getVariables()) {
                        String varType = variable.getType().asString();
                        if ((varType.equals("String") || varType.equals("java.lang.String"))
                                && variable.getInitializer().isPresent()) {
                            pending.add(new Pending(
                                    fqn, typePath, variable.getNameAsString(), variable.getInitializer().get(), owner));
                        }
                    }
                }
            }
            // Constants may refer to each other across files; bounded passes settle chains deterministically.
            for (int pass = 0; pass < 8; pass++) {
                boolean changed = false;
                for (Pending entry : pending) {
                    if (constants.byFqn.getOrDefault(entry.fqn(), Map.of()).containsKey(entry.name())) {
                        continue;
                    }
                    PathValue value = constants.evaluate(entry.init(), entry.owner());
                    if (!value.unresolved()) {
                        constants.byFqn
                                .computeIfAbsent(entry.fqn(), k -> new LinkedHashMap<>())
                                .put(entry.name(), value.text());
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
                return lookupUnqualified(name.getNameAsString(), owner);
            }
            if (expression instanceof FieldAccessExpr access) {
                String scope = dottedScope(access.getScope());
                if (scope != null) {
                    return lookupQualified(scope, access.getNameAsString(), owner);
                }
            }
            return new PathValue("{unresolved}", Basis.COMPUTED, true);
        }

        private static String dottedScope(Expression scope) {
            if (scope instanceof NameExpr name) {
                return name.getNameAsString();
            }
            if (scope instanceof FieldAccessExpr access) {
                String parent = dottedScope(access.getScope());
                return parent == null ? null : parent + "." + access.getNameAsString();
            }
            return null;
        }

        private static String placeholder(String name) {
            return "{" + (name.matches("[A-Za-z0-9_.-]+") ? name : "unresolved") + "}";
        }

        private Optional<String> resolveFromBuiltin(String qualifier, String name, CompilationUnit unit) {
            return builtin == null ? Optional.empty() : builtin.resolve(qualifier, name, unit);
        }

        private PathValue lookupUnqualified(String name, TypeDeclaration<?> owner) {
            Node node = owner;
            while (node != null) {
                if (node instanceof TypeDeclaration<?> declaration) {
                    String value = byFqn.getOrDefault(qualifiedTypeName(declaration), Map.of()).get(name);
                    if (value != null) {
                        return new PathValue(value, Basis.CONCATENATED, false);
                    }
                }
                node = node.getParentNode().orElse(null);
            }
            CompilationUnit unit = owner.findCompilationUnit().orElse(null);
            if (unit != null) {
                for (ImportDeclaration imp : unit.getImports()) {
                    if (!imp.isStatic()) {
                        continue;
                    }
                    String imported = imp.getNameAsString();
                    if (!imp.isAsterisk()) {
                        int dot = imported.lastIndexOf('.');
                        if (dot > 0 && imported.substring(dot + 1).equals(name)) {
                            String ownerFqn = imported.substring(0, dot);
                            String value = byFqn.getOrDefault(ownerFqn, Map.of()).get(name);
                            if (value != null) {
                                return new PathValue(value, Basis.CONCATENATED, false);
                            }
                            Optional<String> built = resolveFromBuiltin(ownerFqn, name, unit);
                            if (built.isPresent()) {
                                return new PathValue(built.get(), Basis.CONCATENATED, false);
                            }
                        }
                    } else {
                        String value = byFqn.getOrDefault(imported, Map.of()).get(name);
                        if (value != null) {
                            return new PathValue(value, Basis.CONCATENATED, false);
                        }
                        Optional<String> built = resolveFromBuiltin(imported, name, unit);
                        if (built.isPresent()) {
                            return new PathValue(built.get(), Basis.CONCATENATED, false);
                        }
                    }
                }
            }
            Set<String> candidates = new LinkedHashSet<>();
            for (Map<String, String> values : byFqn.values()) {
                if (values.containsKey(name)) {
                    candidates.add(values.get(name));
                }
            }
            if (candidates.size() == 1) {
                return new PathValue(candidates.iterator().next(), Basis.CONCATENATED, false);
            }
            return new PathValue(placeholder(name), Basis.COMPUTED, true);
        }

        private PathValue lookupQualified(String scope, String name, TypeDeclaration<?> owner) {
            Node node = owner;
            while (node != null) {
                if (node instanceof TypeDeclaration<?> declaration) {
                    String candidateFqn = qualifiedTypeName(declaration) + "." + scope;
                    String value = byFqn.getOrDefault(candidateFqn, Map.of()).get(name);
                    if (value != null) {
                        return new PathValue(value, Basis.CONCATENATED, false);
                    }
                }
                node = node.getParentNode().orElse(null);
            }
            CompilationUnit unit = owner.findCompilationUnit().orElse(null);
            String ownerPkg = packageName(unit);

            if (!scope.contains(".")) {
                if (unit != null) {
                    for (ImportDeclaration imp : unit.getImports()) {
                        if (imp.isStatic() || imp.isAsterisk()) {
                            continue;
                        }
                        String imported = imp.getNameAsString();
                        int dot = imported.lastIndexOf('.');
                        if (dot > 0 && imported.substring(dot + 1).equals(scope)) {
                            String value = byFqn.getOrDefault(imported, Map.of()).get(name);
                            if (value != null) {
                                return new PathValue(value, Basis.CONCATENATED, false);
                            }
                            Optional<String> built = resolveFromBuiltin(imported, name, unit);
                            if (built.isPresent()) {
                                return new PathValue(built.get(), Basis.CONCATENATED, false);
                            }
                            // Explicit import targets a specific class; do not fall back to another package.
                            return new PathValue(placeholder(name), Basis.COMPUTED, true);
                        }
                    }
                }
                String samePkgFqn = ownerPkg.isEmpty() ? scope : ownerPkg + "." + scope;
                String samePkgValue = byFqn.getOrDefault(samePkgFqn, Map.of()).get(name);
                if (samePkgValue != null) {
                    return new PathValue(samePkgValue, Basis.CONCATENATED, false);
                }
                if (unit != null) {
                    for (ImportDeclaration imp : unit.getImports()) {
                        if (!imp.isStatic() && imp.isAsterisk()) {
                            String candidateFqn = imp.getNameAsString() + "." + scope;
                            String value = byFqn.getOrDefault(candidateFqn, Map.of()).get(name);
                            if (value != null) {
                                return new PathValue(value, Basis.CONCATENATED, false);
                            }
                            Optional<String> built = resolveFromBuiltin(candidateFqn, name, unit);
                            if (built.isPresent()) {
                                return new PathValue(built.get(), Basis.CONCATENATED, false);
                            }
                        }
                    }
                }
                Optional<String> built = resolveFromBuiltin(scope, name, unit);
                if (built.isPresent()) {
                    return new PathValue(built.get(), Basis.CONCATENATED, false);
                }
                Set<String> candidates = new LinkedHashSet<>();
                for (String fqn : fqnsByTypePath.getOrDefault(scope, Set.of())) {
                    Map<String, String> values = byFqn.getOrDefault(fqn, Map.of());
                    if (values.containsKey(name)) {
                        candidates.add(values.get(name));
                    }
                }
                if (candidates.size() == 1) {
                    return new PathValue(candidates.iterator().next(), Basis.CONCATENATED, false);
                }
                return new PathValue(placeholder(name), Basis.COMPUTED, true);
            }

            String direct = byFqn.getOrDefault(scope, Map.of()).get(name);
            if (direct != null) {
                return new PathValue(direct, Basis.CONCATENATED, false);
            }
            if (!ownerPkg.isEmpty()) {
                String inPkg = byFqn.getOrDefault(ownerPkg + "." + scope, Map.of()).get(name);
                if (inPkg != null) {
                    return new PathValue(inPkg, Basis.CONCATENATED, false);
                }
            }
            if (unit != null) {
                int firstDot = scope.indexOf('.');
                String head = scope.substring(0, firstDot);
                String tail = scope.substring(firstDot);
                for (ImportDeclaration imp : unit.getImports()) {
                    if (!imp.isStatic() && !imp.isAsterisk()) {
                        String imported = imp.getNameAsString();
                        int dot = imported.lastIndexOf('.');
                        if (dot > 0 && imported.substring(dot + 1).equals(head)) {
                            String value = byFqn.getOrDefault(imported + tail, Map.of()).get(name);
                            if (value != null) {
                                return new PathValue(value, Basis.CONCATENATED, false);
                            }
                        }
                    }
                }
            }
            Optional<String> built = resolveFromBuiltin(scope, name, unit);
            if (built.isPresent()) {
                return new PathValue(built.get(), Basis.CONCATENATED, false);
            }
            return new PathValue(placeholder(name), Basis.COMPUTED, true);
        }
    }
}
