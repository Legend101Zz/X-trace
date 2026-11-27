package dev.xtrace.analyzer;

import com.github.javaparser.Range;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
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
 * Reads JAX-RS ({@code jakarta.ws.rs.*} and {@code javax.ws.rs.*}) annotated resource classes from
 * source text and emits the static-claim JSON lines described in
 * {@code schema/fixtures/static-claim-contract.json}.
 *
 * <p>The analyzer only parses. It never loads, links, initializes or runs the code it reads, and it
 * starts no process.
 */
public final class JaxRsAnalyzer {
    public static final String FRAMEWORK_JAXRS = "jaxrs";
    public static final int DEFAULT_MAX_FILES = StaticAnalysisSupport.DEFAULT_MAX_FILES;
    public static final long DEFAULT_MAX_FILE_BYTES = StaticAnalysisSupport.DEFAULT_MAX_FILE_BYTES;

    static final String NAME = StaticAnalysisSupport.NAME;
    static final String VERSION = StaticAnalysisSupport.VERSION;
    static final String RULESET = "jaxrs-annotations/1";

    private static final Set<String> JAXRS_PACKAGES = Set.of("jakarta.ws.rs", "javax.ws.rs");
    private static final Set<String> MEDIA_TYPE_FQNS =
            Set.of("jakarta.ws.rs.core.MediaType", "javax.ws.rs.core.MediaType");
    private static final Set<String> HTTP_METHOD_ANNOTATIONS =
            Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS");
    private static final Set<String> CONFLICTING_WILDCARD_PACKAGES = Set.of(
            "retrofit2.http",
            "org.springframework.web.bind.annotation",
            "io.micronaut.http.annotation",
            "feign");
    private static final Map<String, ParamSource> PARAM_ANNOTATIONS = Map.of(
            "PathParam", ParamSource.PATH,
            "QueryParam", ParamSource.QUERY,
            "HeaderParam", ParamSource.HEADER,
            "CookieParam", ParamSource.COOKIE,
            "FormParam", ParamSource.FORM);
    private static final Map<String, String> STANDARD_MEDIA_TYPES = Map.ofEntries(
            Map.entry("WILDCARD", "*/*"),
            Map.entry("APPLICATION_XML", "application/xml"),
            Map.entry("APPLICATION_ATOM_XML", "application/atom+xml"),
            Map.entry("APPLICATION_XHTML_XML", "application/xhtml+xml"),
            Map.entry("APPLICATION_SVG_XML", "application/svg+xml"),
            Map.entry("APPLICATION_JSON", "application/json"),
            Map.entry("APPLICATION_FORM_URLENCODED", "application/x-www-form-urlencoded"),
            Map.entry("MULTIPART_FORM_DATA", "multipart/form-data"),
            Map.entry("APPLICATION_OCTET_STREAM", "application/octet-stream"),
            Map.entry("TEXT_PLAIN", "text/plain"),
            Map.entry("TEXT_XML", "text/xml"),
            Map.entry("TEXT_HTML", "text/html"),
            Map.entry("SERVER_SENT_EVENTS", "text/event-stream"),
            Map.entry("APPLICATION_JSON_PATCH_JSON", "application/json-patch+json"),
            Map.entry("APPLICATION_MERGE_PATCH_JSON", "application/merge-patch+json"));

    private final int maxFiles;
    private final long maxFileBytes;

    public JaxRsAnalyzer() {
        this(DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES);
    }

    public JaxRsAnalyzer(int maxFiles, long maxFileBytes) {
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
    }

    public JaxRsAnalyzer(String framework, int maxFiles, long maxFileBytes) {
        if (!FRAMEWORK_JAXRS.equals(framework)) {
            throw new IllegalArgumentException("unsupported framework: " + framework);
        }
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
    }

    /** Source kind for extracted JAX-RS parameter annotations. */
    public enum ParamSource {
        PATH,
        QUERY,
        HEADER,
        COOKIE,
        FORM
    }

    /** Extracted JAX-RS parameter binding. */
    public record ParamSpec(
            ParamSource source,
            String name,
            String javaType,
            String variableName,
            boolean unresolved) {}

    /** Evaluated media type annotation entry. */
    public record MediaTypeValue(String value, boolean unresolved) {}

    /** Rich extracted JAX-RS endpoint metadata used both for transcript emission and inspection. */
    public record Endpoint(
            String httpMethod,
            String classPath,
            String methodPath,
            String displayPath,
            Basis routeBasis,
            String handler,
            List<ParamSpec> parameters,
            List<MediaTypeValue> consumes,
            List<MediaTypeValue> produces,
            Set<String> limitations,
            String sourcePath,
            Range evidenceRange) {}

    /** Detailed analysis output including structured endpoints, diagnostics, and completeness state. */
    public record AnalysisResult(
            List<Endpoint> endpoints,
            List<String> diagnostics,
            Set<String> incompleteReasons,
            int filesScanned) {}

    /** All lines of the ST-2 JSON-lines transcript for {@code root}, in canonical order. */
    public List<String> analyze(Path root) throws IOException {
        AnalysisResult result = analyzeDetailed(root);
        List<String> lines = new ArrayList<>();
        lines.add(StaticAnalysisSupport.headerLine(RULESET, FRAMEWORK_JAXRS));

        List<String> claims = new ArrayList<>();
        for (Endpoint endpoint : result.endpoints()) {
            claims.add(StaticAnalysisSupport.claimLine(
                    endpoint.httpMethod(),
                    List.of(endpoint.classPath(), endpoint.methodPath()),
                    endpoint.routeBasis(),
                    endpoint.handler(),
                    endpoint.limitations(),
                    endpoint.sourcePath(),
                    endpoint.evidenceRange()));
        }
        List<String> deduplicatedClaims = new LinkedHashSet<>(claims).stream().toList();
        lines.addAll(deduplicatedClaims);
        lines.addAll(result.diagnostics());
        lines.add(StaticAnalysisSupport.endLine(
                deduplicatedClaims.size(), result.filesScanned(), result.incompleteReasons()));
        return lines;
    }

    /** Extracts structured JAX-RS endpoints, diagnostics, and completeness state for {@code root}. */
    public AnalysisResult analyzeDetailed(Path root) throws IOException {
        ParsedProject parsed = StaticAnalysisSupport.collectAndParse(root, maxFiles, maxFileBytes);
        List<CompilationUnit> units = parsed.sources().stream().map(Source::unit).toList();
        Map<String, Set<String>> localAnnotations = StaticAnalysisSupport.collectAnnotationDeclarations(units);
        Constants constants = Constants.collect(units, JaxRsAnalyzer::resolveMediaTypeConstant);

        List<Endpoint> endpoints = new ArrayList<>();
        for (Source source : parsed.sources()) {
            CompilationUnit unit = source.unit();
            for (ClassOrInterfaceDeclaration type : unit.findAll(ClassOrInterfaceDeclaration.class)) {
                if (!isResourceType(type, unit, localAnnotations)) {
                    continue;
                }
                PathValue classPrefix = classPathOf(type, unit, localAnnotations, constants);
                List<MediaTypeValue> classConsumes = mediaTypesOf(type, "Consumes", unit, localAnnotations, constants);
                List<MediaTypeValue> classProduces = mediaTypesOf(type, "Produces", unit, localAnnotations, constants);
                List<ParamSpec> fieldParams = fieldParamsOf(type, unit, localAnnotations, constants);
                String handlerPrefix = StaticAnalysisSupport.binaryName(type) + "#";

                for (MethodDeclaration method : type.getMethods()) {
                    List<AnnotationExpr> httpAnnotations = httpMethodAnnotations(method, unit, localAnnotations);
                    if (httpAnnotations.isEmpty()) {
                        // A method with @Path but no HTTP method annotation is a sub-resource locator.
                        continue;
                    }
                    PathValue methodPath = methodPathOf(method, type, unit, localAnnotations, constants);
                    List<MediaTypeValue> consumes =
                            methodMediaTypes(method, classConsumes, "Consumes", unit, localAnnotations, constants);
                    List<MediaTypeValue> produces =
                            methodMediaTypes(method, classProduces, "Produces", unit, localAnnotations, constants);
                    List<ParamSpec> params = methodParamsOf(method, fieldParams, type, unit, localAnnotations, constants);
                    String handler = handlerPrefix + method.getNameAsString();
                    String displayPath = normalizeDisplayPath(classPrefix.text(), methodPath.text());
                    Basis basis = classPrefix.basis().weakest(methodPath.basis());
                    Set<String> limitations = new TreeSet<>();
                    if (classPrefix.unresolved() || methodPath.unresolved()) {
                        limitations.add("route_constant_unresolved");
                    }

                    for (AnnotationExpr httpAnn : httpAnnotations) {
                        Optional<Range> range = httpAnn.getRange();
                        if (range.isEmpty()) {
                            continue;
                        }
                        String httpMethod = StaticAnalysisSupport.simpleName(httpAnn);
                        endpoints.add(new Endpoint(
                                httpMethod,
                                classPrefix.text(),
                                methodPath.text(),
                                displayPath,
                                basis,
                                handler,
                                params,
                                consumes,
                                produces,
                                limitations,
                                source.relativePath(),
                                range.get()));
                    }
                }
            }
        }
        return new AnalysisResult(
                List.copyOf(endpoints),
                List.copyOf(parsed.diagnostics()),
                Set.copyOf(parsed.incomplete()),
                parsed.filesScanned());
    }

    /**
     * Composes class and method {@code @Path} segments and strips JAX-RS regex constraints such as
     * {@code {clientId:\d+}} to {@code {clientId}}, matching {@code RouteFramework::JaxRs} display syntax.
     */
    static String normalizeDisplayPath(String classPath, String methodPath) {
        StringBuilder joined = new StringBuilder();
        if (classPath != null && !classPath.isEmpty()) {
            joined.append(classPath);
        }
        if (methodPath != null && !methodPath.isEmpty()) {
            if (joined.length() > 0) {
                joined.append('/');
            }
            joined.append(methodPath);
        }
        if (joined.length() == 0) {
            return "/";
        }
        String raw = stripRegexConstraints(joined.toString());
        List<String> segments = new ArrayList<>();
        for (String segment : raw.split("/")) {
            if (!segment.isEmpty()) {
                segments.add(segment);
            }
        }
        return segments.isEmpty() ? "/" : "/" + String.join("/", segments);
    }

    private static String stripRegexConstraints(String path) {
        StringBuilder out = new StringBuilder(path.length());
        int i = 0;
        while (i < path.length()) {
            char c = path.charAt(i);
            if (c != '{') {
                out.append(c);
                i++;
                continue;
            }
            int depth = 0;
            int j = i;
            int close = -1;
            while (j < path.length()) {
                char cur = path.charAt(j);
                if (cur == '\\') {
                    j += 2;
                    continue;
                }
                if (cur == '{') {
                    depth++;
                } else if (cur == '}') {
                    depth--;
                    if (depth == 0) {
                        close = j;
                        break;
                    }
                }
                j++;
            }
            if (close < 0) {
                out.append(path.substring(i));
                break;
            }
            String inside = path.substring(i + 1, close);
            int colon = inside.indexOf(':');
            String name = (colon >= 0 ? inside.substring(0, colon) : inside).trim();
            if (name.isEmpty()) {
                out.append(path, i, close + 1);
            } else {
                out.append('{').append(name).append('}');
            }
            i = close + 1;
        }
        return out.toString();
    }

    private static boolean isResourceType(
            ClassOrInterfaceDeclaration type,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations) {
        if (type.isInterface()
                && (StaticAnalysisSupport.hasAnnotation(type, "FeignClient")
                        || StaticAnalysisSupport.hasAnnotation(type, "RegisterRestClient"))) {
            return false;
        }
        if (hasJaxRsAnnotation(type, "Path", unit, localAnnotations)) {
            return true;
        }
        for (MethodDeclaration method : type.getMethods()) {
            if (hasJaxRsAnnotation(method, "Path", unit, localAnnotations)
                    || !httpMethodAnnotations(method, unit, localAnnotations).isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private static PathValue classPathOf(
            ClassOrInterfaceDeclaration type,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        for (AnnotationExpr ann : type.getAnnotations()) {
            if (isJaxRsAnnotation(ann, "Path", unit, localAnnotations)) {
                return extractSinglePath(ann, type, constants);
            }
        }
        return new PathValue("", Basis.LITERAL, false);
    }

    private static PathValue methodPathOf(
            MethodDeclaration method,
            TypeDeclaration<?> owner,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        for (AnnotationExpr ann : method.getAnnotations()) {
            if (isJaxRsAnnotation(ann, "Path", unit, localAnnotations)) {
                return extractSinglePath(ann, owner, constants);
            }
        }
        return new PathValue("", Basis.LITERAL, false);
    }

    private static PathValue extractSinglePath(
            AnnotationExpr annotation, TypeDeclaration<?> owner, Constants constants) {
        Optional<Expression> expr = annotationValueExpr(annotation);
        if (expr.isEmpty()) {
            return new PathValue("", Basis.LITERAL, false);
        }
        List<Expression> values = StaticAnalysisSupport.elements(expr.get());
        if (values.isEmpty()) {
            return new PathValue("", Basis.LITERAL, false);
        }
        return constants.evaluate(values.get(0), owner);
    }

    private static List<AnnotationExpr> httpMethodAnnotations(
            MethodDeclaration method,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations) {
        List<AnnotationExpr> found = new ArrayList<>();
        for (AnnotationExpr ann : method.getAnnotations()) {
            String simple = StaticAnalysisSupport.simpleName(ann);
            if (HTTP_METHOD_ANNOTATIONS.contains(simple)
                    && isJaxRsAnnotation(ann, simple, unit, localAnnotations)) {
                found.add(ann);
            }
        }
        return found;
    }

    private static List<MediaTypeValue> methodMediaTypes(
            MethodDeclaration method,
            List<MediaTypeValue> classInherited,
            String annotationName,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        if (!hasJaxRsAnnotation(method, annotationName, unit, localAnnotations)) {
            return classInherited;
        }
        return mediaTypesOf(method, annotationName, unit, localAnnotations, constants);
    }

    private static List<MediaTypeValue> mediaTypesOf(
            BodyDeclaration<?> declaration,
            String annotationName,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        TypeDeclaration<?> owner = declaration instanceof TypeDeclaration<?> td
                ? td
                : declaration.findAncestor(TypeDeclaration.class).orElse(null);
        if (owner == null) {
            return List.of();
        }
        List<MediaTypeValue> values = new ArrayList<>();
        for (AnnotationExpr ann : declaration.getAnnotations()) {
            if (!isJaxRsAnnotation(ann, annotationName, unit, localAnnotations)) {
                continue;
            }
            Optional<Expression> expr = annotationValueExpr(ann);
            if (expr.isEmpty()) {
                continue;
            }
            for (Expression element : StaticAnalysisSupport.elements(expr.get())) {
                PathValue evaluated = constants.evaluate(element, owner);
                values.add(new MediaTypeValue(evaluated.text(), evaluated.unresolved()));
            }
        }
        return List.copyOf(values);
    }

    private static List<ParamSpec> fieldParamsOf(
            ClassOrInterfaceDeclaration type,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        List<ParamSpec> params = new ArrayList<>();
        for (FieldDeclaration field : type.getFields()) {
            for (AnnotationExpr ann : field.getAnnotations()) {
                ParamSource source = paramSourceOf(ann, unit, localAnnotations);
                if (source == null) {
                    continue;
                }
                PathValue name = extractSinglePath(ann, type, constants);
                for (VariableDeclarator variable : field.getVariables()) {
                    params.add(new ParamSpec(
                            source,
                            name.text(),
                            variable.getType().asString(),
                            variable.getNameAsString(),
                            name.unresolved()));
                }
            }
        }
        return List.copyOf(params);
    }

    private static List<ParamSpec> methodParamsOf(
            MethodDeclaration method,
            List<ParamSpec> fieldParams,
            TypeDeclaration<?> owner,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations,
            Constants constants) {
        List<ParamSpec> params = new ArrayList<>(fieldParams);
        for (Parameter parameter : method.getParameters()) {
            for (AnnotationExpr ann : parameter.getAnnotations()) {
                ParamSource source = paramSourceOf(ann, unit, localAnnotations);
                if (source == null) {
                    continue;
                }
                PathValue name = extractSinglePath(ann, owner, constants);
                params.add(new ParamSpec(
                        source,
                        name.text(),
                        parameter.getType().asString(),
                        parameter.getNameAsString(),
                        name.unresolved()));
            }
        }
        return List.copyOf(params);
    }

    private static ParamSource paramSourceOf(
            AnnotationExpr ann, CompilationUnit unit, Map<String, Set<String>> localAnnotations) {
        String simple = StaticAnalysisSupport.simpleName(ann);
        ParamSource source = PARAM_ANNOTATIONS.get(simple);
        if (source != null && isJaxRsAnnotation(ann, simple, unit, localAnnotations)) {
            return source;
        }
        return null;
    }

    private static Optional<Expression> annotationValueExpr(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            return Optional.of(single.getMemberValue());
        }
        if (annotation instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (pair.getNameAsString().equals("value")) {
                    return Optional.of(pair.getValue());
                }
            }
        }
        return Optional.empty();
    }

    private static boolean hasJaxRsAnnotation(
            BodyDeclaration<?> declaration,
            String simpleName,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations) {
        return declaration.getAnnotations().stream()
                .anyMatch(a -> isJaxRsAnnotation(a, simpleName, unit, localAnnotations));
    }

    private static boolean isJaxRsAnnotation(
            AnnotationExpr annotation,
            String targetSimpleName,
            CompilationUnit unit,
            Map<String, Set<String>> localAnnotations) {
        String raw = annotation.getNameAsString();
        String simple = StaticAnalysisSupport.simpleName(annotation);
        if (!simple.equals(targetSimpleName)) {
            return false;
        }
        int dot = raw.lastIndexOf('.');
        if (dot > 0) {
            return JAXRS_PACKAGES.contains(raw.substring(0, dot));
        }
        for (ImportDeclaration imp : unit.getImports()) {
            if (imp.isStatic() || imp.isAsterisk()) {
                continue;
            }
            String imported = imp.getNameAsString();
            int impDot = imported.lastIndexOf('.');
            if (impDot > 0 && imported.substring(impDot + 1).equals(targetSimpleName)) {
                return JAXRS_PACKAGES.contains(imported.substring(0, impDot));
            }
        }
        boolean hasJaxRsImport = false;
        boolean hasConflictingWildcard = false;
        for (ImportDeclaration imp : unit.getImports()) {
            String imported = imp.getNameAsString();
            if (!imp.isStatic() && imp.isAsterisk()) {
                if (JAXRS_PACKAGES.contains(imported)) {
                    return true;
                }
                if (CONFLICTING_WILDCARD_PACKAGES.contains(imported)) {
                    hasConflictingWildcard = true;
                }
            } else if (imported.startsWith("jakarta.ws.rs.") || imported.startsWith("javax.ws.rs.")) {
                hasJaxRsImport = true;
            }
        }
        if (hasConflictingWildcard) {
            return false;
        }
        if (hasJaxRsImport) {
            return true;
        }
        String pkg = StaticAnalysisSupport.packageName(unit);
        if (JAXRS_PACKAGES.contains(pkg)) {
            return true;
        }
        return !localAnnotations.getOrDefault(pkg, Set.of()).contains(targetSimpleName);
    }

    private static Optional<String> resolveMediaTypeConstant(
            String qualifier, String member, CompilationUnit unit) {
        String resolved = STANDARD_MEDIA_TYPES.get(member);
        if (resolved == null) {
            return Optional.empty();
        }
        if (MEDIA_TYPE_FQNS.contains(qualifier)) {
            return Optional.of(resolved);
        }
        if (!"MediaType".equals(qualifier)) {
            return Optional.empty();
        }
        if (unit != null) {
            for (ImportDeclaration imp : unit.getImports()) {
                if (imp.isStatic() || imp.isAsterisk()) {
                    continue;
                }
                String imported = imp.getNameAsString();
                if (imported.endsWith(".MediaType") && !MEDIA_TYPE_FQNS.contains(imported)) {
                    return Optional.empty();
                }
            }
        }
        return Optional.of(resolved);
    }
}
