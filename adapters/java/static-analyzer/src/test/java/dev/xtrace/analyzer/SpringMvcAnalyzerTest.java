package dev.xtrace.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class SpringMvcAnalyzerTest {
    private static final Path FIXTURES = Path.of("src/test/resources/fixtures");
    private static final Path CONTRACT = Path.of("../../../schema/fixtures/static-claim-contract.json");

    private static List<String> analyze(String fixture) throws IOException {
        return new SpringMvcAnalyzer(SpringMvcAnalyzer.FRAMEWORK_MVC, 100, 1 << 20).analyze(FIXTURES.resolve(fixture));
    }

    private static List<String> claims(List<String> lines) {
        return lines.stream().filter(l -> l.startsWith("{\"type\":\"claim\"")).toList();
    }

    private static List<String> matching(List<String> lines, String fragment) {
        return claims(lines).stream().filter(l -> l.contains(fragment)).toList();
    }

    @Test
    void spring_class_and_method_paths_join() throws IOException {
        List<String> lines = analyze("spring-basic");
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/owners\",\"/{ownerId}\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"POST\",\"routeParts\":[\"/owners\",\"/new\"]").size());
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/owners\",\"/search\"]").size());
        // @GetMapping without a path maps the class prefix itself.
        assertEquals(1, matching(lines, "\"method\":\"GET\",\"routeParts\":[\"/owners\",\"\"]").size());
        String show = matching(lines, "\"/{ownerId}\"").get(0);
        assertTrue(show.contains("\"routeBasis\":\"literal\""), show);
        assertTrue(show.contains("\"handler\":\"org.example.web.OwnerController#show\""), show);
        assertTrue(show.contains("\"limitations\":[]"), show);
        assertTrue(
                show.contains("\"evidence\":{\"path\":\"org/example/web/OwnerController.java\",\"startLine\":13,"),
                show);
    }

    @Test
    void spring_array_paths_emit_one_claim_each() throws IOException {
        List<String> lines = analyze("spring-basic");
        // {"/a","/b"} x {GET, HEAD}
        for (String path : List.of("/a", "/b")) {
            for (String method : List.of("GET", "HEAD")) {
                assertEquals(
                        1,
                        matching(lines, "\"method\":\"" + method + "\",\"routeParts\":[\"/owners\",\"" + path + "\"]")
                                .size(),
                        method + " " + path);
            }
        }
        // {"/api/v1","/api/v2"} x {PUT, DELETE} on the same pet path.
        for (String prefix : List.of("/api/v1", "/api/v2")) {
            assertEquals(1, matching(lines, "\"method\":\"PUT\",\"routeParts\":[\"" + prefix + "\",\"/pets/{petId}\"]").size());
            assertEquals(1, matching(lines, "\"method\":\"DELETE\",\"routeParts\":[\"" + prefix + "\",\"/pets/{petId}\"]").size());
        }
        assertEquals(1 + 1 + 1 + 1 + 4 + 4, claims(lines).size());
    }

    @Test
    void non_controllers_are_not_endpoints() throws IOException {
        assertTrue(matching(analyze("spring-basic"), "/feign/only").isEmpty());
        assertTrue(matching(analyze("spring-basic"), "notAHandler").isEmpty());
    }

    @Test
    void request_mapping_without_method_emits_ambiguity_code() throws IOException {
        List<String> lines = analyze("spring-ambiguity");
        assertEquals(5, claims(lines).size());
        for (String method : List.of("GET", "POST", "PUT", "PATCH", "DELETE")) {
            List<String> hit = matching(lines, "\"method\":\"" + method + "\"");
            assertEquals(1, hit.size(), method);
            assertTrue(hit.get(0).contains("\"limitations\":[\"mapping_method_unconstrained\"]"), hit.get(0));
        }
    }

    @Test
    void constants_resolve_across_files_and_concatenation_is_marked() throws IOException {
        List<String> lines = analyze("spring-constants");
        String users = matching(lines, "\"routeParts\":[\"/api\",\"/api/users\"]").get(0);
        assertTrue(users.contains("\"routeBasis\":\"concatenated\""), users);
        assertTrue(users.contains("\"limitations\":[]"), users);
        String local = matching(lines, "\"/local/x\"").get(0);
        assertTrue(local.contains("\"routeBasis\":\"concatenated\""), local);
        assertEquals(1, matching(lines, "\"/lit/api\"").size());
    }

    @Test
    void unresolvable_constant_yields_limitation_and_low_confidence() throws IOException {
        List<String> lines = analyze("spring-constants");
        String missing = matching(lines, "\"{MISSING}\"").get(0);
        assertTrue(missing.contains("\"routeBasis\":\"computed\""), missing);
        assertTrue(missing.contains("\"limitations\":[\"route_constant_unresolved\"]"), missing);
        String dynamic = matching(lines, "/dyn/").get(0);
        assertTrue(dynamic.contains("\"routeBasis\":\"computed\""), dynamic);
        assertTrue(dynamic.contains("route_constant_unresolved"), dynamic);
    }

    @Test
    void parse_error_makes_the_scan_incomplete_but_keeps_other_claims() throws IOException {
        List<String> lines = analyze("broken");
        assertEquals(1, matching(lines, "\"routeParts\":[\"\",\"/good\"]").size());
        assertTrue(lines.contains("{\"type\":\"diagnostic\",\"code\":\"parse_error\",\"path\":\"Broken.java\"}"));
        String end = lines.get(lines.size() - 1);
        assertTrue(end.contains("\"complete\":false"), end);
        assertTrue(end.contains("\"incompleteReasons\":[\"parse_error\"]"), end);
    }

    @Test
    void file_budget_makes_the_scan_incomplete() throws IOException {
        List<String> lines = new SpringMvcAnalyzer(SpringMvcAnalyzer.FRAMEWORK_MVC, 1, 1 << 20)
                .analyze(FIXTURES.resolve("spring-basic/org/example/web"));
        String end = lines.get(lines.size() - 1);
        assertTrue(end.contains("\"incompleteReasons\":[\"budget_exceeded\"]"), end);
        List<String> big = new SpringMvcAnalyzer(SpringMvcAnalyzer.FRAMEWORK_MVC, 100, 10)
                .analyze(FIXTURES.resolve("spring-ambiguity"));
        assertTrue(big.stream().anyMatch(l -> l.contains("\"code\":\"file_too_large\"")), big.toString());
        assertTrue(big.get(big.size() - 1).contains("budget_exceeded"));
    }

    @Test
    void complete_scan_reports_complete_and_counts() throws IOException {
        List<String> lines = analyze("spring-basic");
        assertTrue(lines.get(0).startsWith("{\"type\":\"header\",\"contractVersion\":1,"), lines.get(0));
        String end = lines.get(lines.size() - 1);
        assertTrue(end.contains("\"complete\":true"), end);
        assertTrue(end.contains("\"filesScanned\":3"), end);
        assertTrue(end.contains("\"claims\":" + claims(lines).size()), end);
    }

    @Test
    void output_is_deterministic() throws IOException {
        assertEquals(analyze("spring-basic"), analyze("spring-basic"));
    }

    @Test
    void emitted_vocabulary_is_in_the_shared_contract() throws IOException {
        String contract = Files.readString(CONTRACT);
        Pattern code = Pattern.compile("\"limitations\":\\[([^\\]]*)\\]");
        for (String fixture : List.of("spring-basic", "spring-ambiguity", "spring-constants", "broken")) {
            for (String line : analyze(fixture)) {
                Matcher matcher = code.matcher(line);
                if (matcher.find() && !matcher.group(1).isEmpty()) {
                    for (String item : matcher.group(1).split(",")) {
                        assertTrue(contract.contains(item), item + " missing from the shared contract");
                    }
                }
            }
        }
        assertTrue(contract.contains("\"spring-mvc\"") && contract.contains("\"spring-webflux\""));
    }

    @Test
    void analyzer_never_executes_source() throws IOException {
        Path marker = Path.of(System.getProperty("java.io.tmpdir"), "xtrace-static-analyzer-marker");
        Path processMarker = Path.of("xtrace-static-analyzer-process-marker");
        Files.deleteIfExists(marker);
        Files.deleteIfExists(processMarker);
        List<String> lines = analyze("side-effect");
        // The claim is found by reading text...
        assertEquals(1, matching(lines, "/side-effect").size());
        // ...and nothing in the analyzed class ran.
        assertFalse(Files.exists(marker), "static initializer of analyzed code must not run");
        assertFalse(Files.exists(processMarker), "analyzed code must not start processes");
    }

    @Test
    void analyzer_sources_contain_no_execution_or_class_loading_apis() throws IOException {
        Pattern forbidden = Pattern.compile(
                "ProcessBuilder|Runtime\\s*\\.\\s*getRuntime|Class\\s*\\.\\s*forName|ClassLoader|MethodHandles|"
                        + "ScriptEngine|java\\.lang\\.reflect|JavaCompiler");
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String text = Files.readString(file);
                assertFalse(forbidden.matcher(text).find(), file + " uses an execution or class-loading API");
            }
        }
    }
}
