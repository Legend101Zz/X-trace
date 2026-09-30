package dev.xtrace.fixture;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/** Test-only leader that leaves a same-process-group helper behind on exit. */
public final class ProcessGroupLeaderTest {
    @Test
    void fixtureClassIsDiscoveredByGradle() {
        // The main method is launched by the Unix supervision integration test.
    }

    public static void main(String[] arguments) throws Exception {
        Path pidFile = Path.of(arguments[0]);
        Path survivorMarker = Path.of(arguments[1]);
        Process helper = new ProcessBuilder(
                "/bin/sh",
                "-c",
                "sleep 2; printf survivor > \"$1\"",
                "xtrace-helper",
                survivorMarker.toString())
                .start();
        Files.writeString(pidFile, Long.toString(helper.pid()));
    }
}
