package dev.xtrace.analyzer;

import com.github.javaparser.Range;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import dev.xtrace.analyzer.StaticAnalysisSupport.Basis;
import dev.xtrace.analyzer.StaticAnalysisSupport.Constants;
import dev.xtrace.analyzer.StaticAnalysisSupport.ParsedProject;
import dev.xtrace.analyzer.StaticAnalysisSupport.PathValue;
import dev.xtrace.analyzer.StaticAnalysisSupport.Source;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
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
    public static final int DEFAULT_MAX_FILES = StaticAnalysisSupport.DEFAULT_MAX_FILES;
    public static final long DEFAULT_MAX_FILE_BYTES = StaticAnalysisSupport.DEFAULT_MAX_FILE_BYTES;

    static final String NAME = StaticAnalysisSupport.NAME;
    static final String VERSION = StaticAnalysisSupport.VERSION;
    static final String RULESET = "spring-mvc-annotations/1";

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

    /** All lines of the transcript for {@code root}, in order. */
    public List<String> analyze(Path root) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(StaticAnalysisSupport.headerLine(RULESET, framework));

        ParsedProject parsed = StaticAnalysisSupport.collectAndParse(root, maxFiles, maxFileBytes);
        Constants constants = Constants.collect(parsed.sources().stream().map(Source::unit).toList());
        List<String> claims = new LinkedHashSet<>(claimsFor(parsed.sources(), constants)).stream().toList();
        lines.addAll(claims);
        lines.addAll(parsed.diagnostics());
        lines.add(StaticAnalysisSupport.endLine(claims.size(), parsed.filesScanned(), parsed.incomplete()));
        return lines;
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
        String handler = StaticAnalysisSupport.binaryName(type) + "#" + method.getNameAsString();
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
                    claims.add(StaticAnalysisSupport.claimLine(
                            httpMethod,
                            List.of(prefix.text(), path.text()),
                            basis,
                            handler,
                            limitations,
                            source.relativePath(),
                            r));
                }
            }
        }
    }

    private static boolean isHandlerType(ClassOrInterfaceDeclaration type) {
        if (type.isInterface() && StaticAnalysisSupport.hasAnnotation(type, "FeignClient")) {
            return false;
        }
        return StaticAnalysisSupport.hasAnnotation(type, "Controller")
                || StaticAnalysisSupport.hasAnnotation(type, "RestController");
    }

    private List<PathValue> classPrefixes(ClassOrInterfaceDeclaration type, Constants constants) {
        for (AnnotationExpr annotation : type.getAnnotations()) {
            if (StaticAnalysisSupport.simpleName(annotation).equals("RequestMapping")) {
                List<PathValue> paths = pathsOf(annotation, type, constants);
                return paths.isEmpty() ? List.of(new PathValue("", Basis.LITERAL, false)) : paths;
            }
        }
        return List.of(new PathValue("", Basis.LITERAL, false));
    }

    /** One method-level mapping annotation. */
    private record Mapping(AnnotationExpr annotation, List<PathValue> paths, List<String> methods, boolean unconstrained) {}

    private Mapping mappingOf(AnnotationExpr annotation, TypeDeclaration<?> owner, Constants constants) {
        String name = StaticAnalysisSupport.simpleName(annotation);
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
                    for (Expression expression : StaticAnalysisSupport.elements(pair.getValue())) {
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
            for (Expression expression : StaticAnalysisSupport.elements(single.getMemberValue())) {
                values.add(constants.evaluate(expression, owner));
            }
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                String key = pair.getNameAsString();
                if (key.equals("value") || key.equals("path")) {
                    for (Expression expression : StaticAnalysisSupport.elements(pair.getValue())) {
                        values.add(constants.evaluate(expression, owner));
                    }
                }
            }
        }
        return values;
    }
}
