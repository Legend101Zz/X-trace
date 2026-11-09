# adapters/java: notes for agents

- Gradle 9 wrapper, strict dependency verification and lockfiles. Always pass
  `--dependency-verification strict`. A new dependency needs updated verification metadata and lockfiles in the
  same change (a shared-contract change: ask in the ticket).
- Modules: `agent-bootstrap` (JDK-only premain/bridge JAR, keep it dependency-free), `agent-runtime` (capture:
  Spring MVC seam, method/line/value probes, JDBC/H2), `attach-helper`, `static-analyzer` (routes for `xtrace scan`),
  `spring-fixture` (the pinned Spring Boot fixture app used by Rust journey tests), and the root synthetic
  conformance client.
- The Rust CLI tests consume the built outputs of `installDist agentDist fixtureBootJar`. After changing the agent,
  the Rust journey tests on CI are the real check.
- Fast check: `tools/dev/check.sh java:<module>` (offline; needs `tools/dev/prep.sh` once).
- Runtime targets are Java 17 and 21 (CI also runs 25). Do not use APIs newer than 17 in agent code.
