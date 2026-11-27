package dev.xtrace.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.analyzer.JaxRsAnalyzer.AnalysisResult;
import dev.xtrace.analyzer.JaxRsAnalyzer.Endpoint;
import dev.xtrace.analyzer.JaxRsAnalyzer.MediaTypeValue;
import dev.xtrace.analyzer.JaxRsAnalyzer.ParamSource;
import dev.xtrace.analyzer.JaxRsAnalyzer.ParamSpec;
import dev.xtrace.analyzer.StaticAnalysisSupport.Basis;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class JaxRsAnalyzerTest {
    private static final Path FIXTURES = Path.of("src/test/resources/fixtures");
    private static final Path CONTRACT = Path.of("../../../schema/fixtures/static-claim-contract.json");

    private static List<String> analyze(String fixture) throws IOException {
        return new JaxRsAnalyzer(100, 1 << 20).analyze(FIXTURES.resolve(fixture));
    }

    private static AnalysisResult analyzeDetailed(String fixture) throws IOException {
        return new JaxRsAnalyzer(100, 1 << 20).analyzeDetailed(FIXTURES.resolve(fixture));
    }

    private static List<String> claims(List<String> lines) {
        return lines.stream().filter(l -> l.startsWith("{\"type\":\"claim\"")).toList();
    }

    private static List<String> matching(List<String> lines, String fragment) {
        return claims(lines).stream().filter(l -> l.contains(fragment)).toList();
    }

    private static Endpoint findEndpoint(
            AnalysisResult result, String method, String handlerSuffix, String displayPath) {
        return result.endpoints().stream()
                .filter(e -> e.httpMethod().equals(method)
                        && e.handler().endsWith(handlerSuffix)
                        && e.displayPath().equals(displayPath))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Missing endpoint " + method + " " + displayPath + " " + handlerSuffix));
    }

    @Test
    void supports_jakarta_and_javax_paths_and_all_http_methods() throws IOException {
        List<String> lines = analyze("jaxrs-basic");
        String header = lines.get(0);
        assertTrue(header.contains("\"framework\":\"jaxrs\""), header);
        assertTrue(header.contains("\"rulesetId\":\"jaxrs-annotations/1\""), header);

        // jakarta.ws.rs Fineract-style ClientsApiResource
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/v1/clients\",\"\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/v1/clients\",\"{clientId}\"]").size());
        assertEquals(
                1,
                matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/v1/clients\",\"{clientId:\\\\d+}/accounts\"]")
                        .size());
        assertEquals(1, matching(lines, "\"method\":\"POST\",\"routeParts\":[\"/v1/clients\",\"\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"PUT\",\"routeParts\":[\"/v1/clients\",\"{clientId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"PATCH\",\"routeParts\":[\"/v1/clients\",\"{clientId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"DELETE\",\"routeParts\":[\"/v1/clients\",\"{clientId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"HEAD\",\"routeParts\":[\"/v1/clients\",\"health\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"OPTIONS\",\"routeParts\":[\"/v1/clients\",\"\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"POST\",\"routeParts\":[\"/v1/clients\",\"form\"]").size());

        // javax.ws.rs OfficesApiResource (including fully qualified @javax.ws.rs.POST)
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/v1/offices\",\"\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/v1/offices\",\"{officeId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"PUT\",\"routeParts\":[\"/v1/offices\",\"{officeId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"POST\",\"routeParts\":[\"/v1/offices\",\"\"]").size());

        String show = matching(lines, "\"handler\":\"org.example.fineract.ClientsApiResource#retrieveOne\"").get(0);
        assertTrue(show.contains("\"routeBasis\":\"literal\""), show);
        assertTrue(show.contains("\"limitations\":[]"), show);
        assertTrue(
                show.contains(
                        "\"evidence\":{\"path\":\"org/example/fineract/ClientsApiResource.java\",\"startLine\":38,"),
                show);

        // 10 (ClientsApiResource) + 4 (OfficesApiResource) + 4 (ConstantPathsResource)
        assertEquals(18, claims(lines).size());
    }

    @Test
    void extracts_parameters_media_types_and_normalizes_regex_display_paths() throws IOException {
        AnalysisResult result = analyzeDetailed("jaxrs-basic");

        Endpoint retrieveAll = findEndpoint(result, "GET", "#retrieveAll", "/v1/clients");
        assertEquals(
                List.of(
                        new ParamSpec(ParamSource.QUERY, "sqlSearch", "String", "sqlSearch", false),
                        new ParamSpec(ParamSource.QUERY, "offset", "Integer", "offset", false),
                        new ParamSpec(ParamSource.HEADER, "Fineract-Platform-TenantId", "String", "tenantId", false),
                        new ParamSpec(ParamSource.COOKIE, "JSESSIONID", "String", "sessionId", false)),
                retrieveAll.parameters());
        assertEquals(List.of(new MediaTypeValue("application/json", false)), retrieveAll.consumes());
        assertEquals(List.of(new MediaTypeValue("application/json", false)), retrieveAll.produces());

        Endpoint regexAccounts =
                findEndpoint(result, "GET", "#retrieveAccounts", "/v1/clients/{clientId}/accounts");
        assertEquals("{clientId:\\d+}/accounts", regexAccounts.methodPath());
        assertEquals(
                List.of(new ParamSpec(ParamSource.PATH, "clientId", "Long", "clientId", false)),
                regexAccounts.parameters());

        Endpoint submitForm = findEndpoint(result, "POST", "#submitForm", "/v1/clients/form");
        assertEquals(
                List.of(new ParamSpec(ParamSource.FORM, "displayName", "String", "displayName", false)),
                submitForm.parameters());
        assertEquals(
                List.of(new MediaTypeValue("application/x-www-form-urlencoded", false)),
                submitForm.consumes());
        assertEquals(List.of(new MediaTypeValue("text/plain", false)), submitForm.produces());

        // javax.ws.rs class-level @Consumes/@Produces inheritance and method-level override
        Endpoint listOffices = findEndpoint(result, "GET", "#retrieveOffices", "/v1/offices");
        assertEquals(List.of(new MediaTypeValue("application/json", false)), listOffices.consumes());
        assertEquals(
                List.of(
                        new MediaTypeValue("application/json", false),
                        new MediaTypeValue("text/plain", false)),
                listOffices.produces());

        Endpoint oneOffice = findEndpoint(result, "GET", "#retrieveOffice", "/v1/offices/{officeId}");
        assertEquals(List.of(new MediaTypeValue("application/json", false)), oneOffice.consumes());
        assertEquals(List.of(new MediaTypeValue("application/xml", false)), oneOffice.produces());
        assertEquals(
                List.of(
                        new ParamSpec(ParamSource.PATH, "officeId", "Long", "officeId", false),
                        new ParamSpec(ParamSource.HEADER, "X-Correlation-Id", "String", "correlationId", false)),
                oneOffice.parameters());
    }

    @Test
    void normalizes_complex_regex_path_templates() {
        assertEquals("/users/{id}", JaxRsAnalyzer.normalizeDisplayPath("/users", "{ id : [0-9]{1,3} }"));
        assertEquals("/files/{path}/raw", JaxRsAnalyzer.normalizeDisplayPath("/files/{path: .+/[a-z]{2}}", "/raw"));
        assertEquals("/v1/clients", JaxRsAnalyzer.normalizeDisplayPath("/v1/clients/", ""));
        assertEquals("/", JaxRsAnalyzer.normalizeDisplayPath("", ""));
    }

    @Test
    void ignores_non_jaxrs_classes_clients_and_subresource_locators() throws IOException {
        List<String> lines = analyze("jaxrs-basic");
        assertTrue(matching(lines, "NotAResource").isEmpty());
        assertTrue(matching(lines, "SpringOnlyController").isEmpty());
        assertTrue(matching(lines, "RetrofitClient").isEmpty());
        assertTrue(matching(lines, "MicroProfileClient").isEmpty());
        assertTrue(matching(lines, "NestedHelper").isEmpty());
        assertTrue(matching(lines, "notesSubResource").isEmpty());
    }

    @Test
    void resolves_constants_in_package_and_reports_unresolved_honestly() throws IOException {
        List<String> lines = analyze("jaxrs-basic");
        String search = matching(lines, "\"routeParts\":[\"/v2/clients\",\"/search\"]").get(0);
        assertTrue(search.contains("\"routeBasis\":\"concatenated\""), search);
        assertTrue(search.contains("\"limitations\":[]"), search);

        String local = matching(lines, "\"routeParts\":[\"/v2/clients\",\"/local/items\"]").get(0);
        assertTrue(local.contains("\"routeBasis\":\"concatenated\""), local);
        assertTrue(local.contains("\"limitations\":[]"), local);

        String missing = matching(lines, "\"{MISSING}\"").get(0);
        assertTrue(missing.contains("\"routeBasis\":\"computed\""), missing);
        assertTrue(missing.contains("\"limitations\":[\"route_constant_unresolved\"]"), missing);

        String dynamic = matching(lines, "/dyn/").get(0);
        assertTrue(dynamic.contains("\"routeBasis\":\"computed\""), dynamic);
        assertTrue(dynamic.contains("route_constant_unresolved"), dynamic);

        AnalysisResult detailed = analyzeDetailed("jaxrs-basic");
        Endpoint searchEp = findEndpoint(detailed, "GET", "#search", "/v2/clients/search");
        assertEquals(Basis.CONCATENATED, searchEp.routeBasis());
        assertEquals(List.of(new MediaTypeValue("application/json", false)), searchEp.consumes());
        assertEquals(List.of(new MediaTypeValue("application/vnd.fineract+json", false)), searchEp.produces());
        assertEquals(
                List.of(new ParamSpec(ParamSource.QUERY, "filter", "String", "filter", false)),
                searchEp.parameters());

        Endpoint missingEp = findEndpoint(detailed, "GET", "#missing", "/v2/clients/{MISSING}");
        assertEquals(List.of(new MediaTypeValue("{MISSING_MEDIA}", true)), missingEp.produces());
    }

    @Test
    void parse_error_makes_scan_incomplete_but_preserves_valid_claims() throws IOException {
        List<String> lines = analyze("jaxrs-broken");
        assertEquals(1, matching(lines, "\"routeParts\":[\"\",\"/healthy\"]").size());
        assertTrue(lines.contains("{\"type\":\"diagnostic\",\"code\":\"parse_error\",\"path\":\"BrokenResource.java\"}"));
        String end = lines.get(lines.size() - 1);
        assertTrue(end.contains("\"complete\":false"), end);
        assertTrue(end.contains("\"incompleteReasons\":[\"parse_error\"]"), end);
    }

    @Test
    void file_budget_makes_scan_incomplete() throws IOException {
        List<String> lines = new JaxRsAnalyzer(1, 1 << 20).analyze(FIXTURES.resolve("jaxrs-basic"));
        String end = lines.get(lines.size() - 1);
        assertTrue(end.contains("\"incompleteReasons\":[\"budget_exceeded\"]"), end);

        List<String> big = new JaxRsAnalyzer(100, 10).analyze(FIXTURES.resolve("jaxrs-basic"));
        assertTrue(big.stream().anyMatch(l -> l.contains("\"code\":\"file_too_large\"")), big.toString());
        assertTrue(big.get(big.size() - 1).contains("budget_exceeded"));
    }

    @Test
    void complete_scan_reports_complete_counts_and_is_deterministic() throws IOException {
        List<String> first = analyze("jaxrs-basic");
        List<String> second = analyze("jaxrs-basic");
        assertEquals(first, second);

        String end = first.get(first.size() - 1);
        assertTrue(end.contains("\"complete\":true"), end);
        assertTrue(end.contains("\"filesScanned\":5"), end);
        assertTrue(end.contains("\"claims\":" + claims(first).size()), end);
    }

    @Test
    void emitted_vocabulary_is_in_shared_contract() throws IOException {
        String contract = Files.readString(CONTRACT);
        Pattern code = Pattern.compile("\"limitations\":\\[([^\\]]*)\\]");
        for (String fixture : List.of("jaxrs-basic", "jaxrs-broken")) {
            for (String line : analyze(fixture)) {
                Matcher matcher = code.matcher(line);
                if (matcher.find() && !matcher.group(1).isEmpty()) {
                    for (String item : matcher.group(1).split(",")) {
                        assertTrue(contract.contains(item), item + " missing from the shared contract");
                    }
                }
            }
        }
        assertTrue(contract.contains("\"jaxrs\""));
    }

    @Test
    void analyzer_never_executes_source() throws IOException {
        Path marker = Path.of(System.getProperty("java.io.tmpdir"), "xtrace-jaxrs-analyzer-marker");
        Path processMarker = Path.of("xtrace-jaxrs-analyzer-process-marker");
        Files.deleteIfExists(marker);
        Files.deleteIfExists(processMarker);
        List<String> lines = analyze("jaxrs-side-effect");
        assertEquals(1, matching(lines, "/v1/side-effect").size());
        assertFalse(Files.exists(marker), "static initializer of analyzed code must not run");
        assertFalse(Files.exists(processMarker), "analyzed code must not start processes");
    }
}
