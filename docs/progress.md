# X-trace implementation progress

This file is maintained by the main orchestrator after independent review and
verification. It is also the execution checkpoint. The active launch mandate
below supersedes the historical per-phase approval pauses and model assignments
recorded later in this file; mandatory reviews and verification still apply.

## Active v0.01 autonomous launch authorization (2026-10-04)

The owner explicitly authorized autonomous implementation through the full v0.01 release gate, feature pushes, independently reviewed no-ff merges and main pushes, and publication only after acceptance. This supersedes older per-phase approval pauses for this launch scope. Use Luna High implementation and separate Sol High architecture/security/build reviews. Root alone merges/releases. Every required gate remains mandatory.

The release specification is `docs/releases/v0.01.md`; machine-readable dependency plan and requirement ledger are in `evidence/v0.01/`. Initial baseline is clean fetched `3e47895`, CI `37140004261` green. No v0.01 release candidate is accepted yet. Source/replay and general Java/Node product journeys remain incomplete. P01 is the genuine Spring verified method-source increment; Node HTTP is isolated preparation, not accepted Slice4. Shared Cargo and Gradle builders are serialized through explicit task leases; the private execution checkpoint records current ownership. Same-chat 30-minute continuation is configured and active; it requires the powered machine, running desktop app and mounted SSD. Signing/notarization identity and real human study/owner acceptance are pending external gates. The historical sections below remain evidence of prior bounded work, not current release acceptance.

## External baseline preparation (2026-10-04)

All six disposable upstream servers now have uninstrumented baseline receipts: Petclinic (6 checks), JHipster (8), Fineract (11), Directus (8), Medusa (10), and Vendure (13). Exact upstream/runtime/database pins and private receipt hashes are recorded in `evidence/v0.01/external-baselines.preparation.json`. Petclinic uses the explicitly approved maintained-main SHA exception. Medusa was repeated from a verified pinned starter checkout; the earlier installer checkout had unknown provenance. Vendure exercised its upstream GraphQL API and direct SQLite effect. Earlier failed attempts remain preserved.

These 56 baseline checks do not prove X-trace instrumentation, packaged installation, response parity under capture, source/line/value/outcome replay, privacy, performance, or release acceptance. Upstream test suites were not run. All mandatory release rows remain pending; no candidate is accepted.

## Execution workflow checkpoint

Every bounded phase follows `Phase -> Implement -> Review -> Verify -> Status
-> user approval -> Next phase`. GPT-6 Terra and Luna agents may perform
implementation, review, debugging, or architecture checks at Medium or High
reasoning according to slice complexity. They commit coherent branch changes
only; they do not merge or push `main`. The main orchestrator independently
reviews and tests their work, keeps shared architecture coherent, and reports
the completed work, changes, verification, issues or decisions, remaining
work, and exact next proposed phase before stopping for approval. No background
automation may cross that approval boundary.

Active continuation authorization (2026-10-01): the user explicitly authorized
reviewed phases to continue autonomously, with individual implementation,
independent review, exact verification, merge/push, CI, and progress gates.
The user accepted the recording-ID compatibility proposal: preserve canonical
RFC UUIDv4/v7 recording identities in observed reads and cursors, retain UUIDv7
project/operation identities, and generate UUIDv7 for future real captures.
Implement this as a separately reviewed ADR/prerequisite before completing B2.
Use GPT-6 Luna for implementation and GPT-6 Sol for reviews because Terra is
unavailable, as the user instructed. The orchestrator alone merges and pushes;
stop for any new material architecture/product decision. Do not use PIO,
OpenCode, MiniMax, Kimi, or GLM. No failing candidate is accepted by this
workflow authorization; all required gates still apply.

Continuation checkpoint (2026-10-03): the user explicitly resumed work after
the Oct 1 SSD-removal pause and requested a next-session prompt if this chat
became too long. The approved autonomous scope and Luna High implementation /
Sol High review assignment remain in force. HTTP and the endpoint-first browser
are now reviewed, merged, pushed, and verified as recorded below. The bounded
Slice 1E.3 exact-fixture product journey is accepted; broader Slice 1 remains
incomplete. This chat ends at a clean handoff because it is long. Next session
reconciles the remaining Slice 1 exit criteria and proposes the smallest bounded
source/active-line/provenance evidence increment, resolving any material decision
before implementation. No background implementation or scheduled continuation is
running. The historical pause section below is superseded by this completion
checkpoint.

## Historical B2 stop checkpoint (superseded by accepted ADR 0002)

The initial CLI draft `2e41a3c224e9abe95696af43e67a890a46cf52fe` and
checkpoint `714b3cca5a3e4b89b397b68ada6b6e92cb5de81d` were local/unmerged
on baseline `db13dfbf970aa54a6d9152d3fd9ea3e159ead932`. Exact focused tests
passed 211 with one failure; workspace tests passed 446 with the same failure.
The real Spring linked-recording continuation exposed UUIDv4 captures rejected
by B1's v7-only observed reader. Later assertions in that test were unreached.
Formatting, strict Clippy/rustdoc, restricted-PATH build, and diff checks passed.
The initial Luna source reviews found no further blocker; no failing draft was
merged or pushed.

The user accepted historical v4 read/cursor compatibility and future v7 capture,
requested Sol reviews, and authorized continuation. The separately reviewed
prerequisite below is merged, tested, pushed, and CI-green. B2 is rebased onto
it, with a malformed/ambiguous CLI argument privacy repair and stronger genuine-
capture and historical-v4 pagination evidence. Those amendments require their
own pinned Sol reviews and full acceptance gate before B2 merge.

| Slice | Goal | Files changed | Verification | Result | Next slice |
|---|---|---|---|---|---|
| Baseline | Preserve approved gates and worker rules in the repository | `AGENTS.md`, `docs/plans/x-trace/**`, `docs/progress.md` | File inventory, clean Git baseline, and push of `7eb002a` | Complete | Slice 1A foundation |
| Slice 1A candidate | Rust domain/application/protocol/SQLite/CLI foundation | Candidate commit `7724ed7` on `slice/1a-core-spine` (not merged) | 52 tests, strict Clippy, CLI smoke, restricted-PATH vendored-protoc build; independent architecture/code review | Historical rejected-candidate record: user-data storage layout, durable idempotency, error/correlation correctness, canonical validation, migration checksums/pragmas, and docs/CI required repair. The repair is recorded below. | Historical next step superseded by the approval-gated GPT-6 Terra/Luna workflow above; do not resume it automatically. |
| Slice 1A repaired and merged | Establish the reviewed Rust domain/application/protocol/SQLite/CLI spine without claiming capture or replay | Feature head `030dc8b`; merge commit `20037ee` on `main`; 54 implementation/schema/tooling files plus README and developer setup | Independent full-diff review; `cargo fmt`; strict Clippy; 109 tests; strict rustdoc; restricted-PATH clean vendored-protoc build; CLI uninitialized/init/replay/conflict/open/status, pointer precedence/corruption, migration-tamper, and Unix permission cases | Complete and merged. The six original blocker groups and follow-up concurrency, atomic-open, catalog-validation, permission, and documentation findings are resolved. Known risk: a pointer commit failure after DB initialization can leave an orphaned user-data directory requiring manual cleanup. | Slice 1B: smallest runnable daemon/XTP ingestion increment toward one real Spring Boot request |
| Slice 1B reviewed and merged | Daemon bootstrap and XTP handshake on top of the Slice 1A spine without claiming capture or replay | Feature head `249c2e0`; merge commit `9c07d47` on `main` (present on `origin/main`); adds the `xtrace-daemon` crate plus protocol handshake helpers, small domain canonical-fingerprint hardening, and accurate README/path docs | Independent full-diff review; `cargo fmt`; strict Clippy workspace all-targets all-features; strict rustdoc all-features; `cargo test` workspace all-targets all-features 242 passed; `cargo test` workspace all-features 244 passed including 1 daemon doctest; loopback integration 18 tests passed across three extra serial repetitions; restricted-PATH clean `xtrace-protocol` all-targets all-features build with vendored protoc; CLI acceptance for no-write uninitialized status, pointer-only repo state, exact idempotent receipt replay, `XTR-COMMAND-409` changed-input conflict, and pointer-based open/status | Complete and merged. `xtrace-daemon` exposes a loopback-only listener, owner-only atomic one-shot bootstrap artifact, ephemeral pinned TLS 1.3 materials, session secret and bidirectional transcript proofs via real `rustls` exporter, `AdapterHello`/`DaemonHello` negotiation, canonical repository/manifest validation, strict sequence/replay/gap handling, bounded volatile staging with `Staged` ACKs, health and protocol errors, and supervised connection lifecycle with clean shutdown. Honest boundary: complete infrastructure increment, not completion of the Gate 4 Slice 1 vertical journey — no real Java adapter/events, durable recording assembler, browser/TUI replay, or evidence package yet | Slice 1C: smallest bounded recording ingress/assembler plus durable storage behind this XTP session, retaining fake-adapter tests without claiming end-to-end Java/UI |
| Slice 1C.1 reviewed and merged | Authenticated recording wire admission only on top of the Slice 1B handshake | Feature head `485f007`; merge commit `d35625f` on `main`; `crates/xtrace-daemon/src/runtime.rs`, `crates/xtrace-daemon/src/session.rs`, `crates/xtrace-daemon/tests/loopback_handshake.rs` | Independent full-diff review; `cargo fmt`; strict Clippy workspace all-targets all-features; strict rustdoc all-features no-deps; `cargo test` workspace all-targets all-features 245 passed; `cargo test` workspace all-features 246 passed including 1 doctest; loopback integration 19 tests passed across three extra serial repetitions; restricted-PATH clean vendored-protoc build | Complete and merged. `RecordingStarted`, `EventBatch`, and `RecordingFinished` post-hello payloads now map to exact typed `IncomingEnvelope` variants, enter the bounded volatile staging queue in session order, and receive `Staged` ACKs; unsupported post-hello payloads such as `EndpointClaimBatch` are still rejected without mutating session state so a subsequent recording payload at the same sequence still admits. Honest boundary: no recording-level sequence validation, lifecycle assembly, semantic translation, persistence, `Committed` ACKs, real adapter, UI, or capture/replay capability claim | Slice 1C.2: smallest pure, framework-neutral recording lifecycle/order assembler contract, designed for interleaved recording IDs and still without storage/XTF/capability claims |
| Slice 1C.2 reviewed and merged | Pure IO-free framework-neutral recording lifecycle/order assembler on top of Slice 1C.1 wire admission | Feature head `bfe3279`; merge commit `faffba0` on `main`; new `crates/xtrace-ingest` crate (`Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/validator.rs`) plus root `Cargo.toml` and `Cargo.lock` workspace membership | Independent full-diff review; no production `panic!`/`unwrap`/`expect`/ignored-result/`unsafe` patterns; deterministic BLAKE3 event digest schema cross-checked through the nested `RecordingEvent` prost path with a private `xtrace.ingest.event.v1` type-domain prefix; `cargo fmt`; strict Clippy workspace all-targets all-features; strict rustdoc workspace all-features no-deps; focused `xtrace-ingest` 24/24 tests; `cargo test` workspace all-targets all-features 269 passed; `cargo test` workspace all-features 270 passed including 1 doctest; restricted-PATH clean vendored-protoc build; `git diff --check`; CLI smoke for no-write uninitialized status, exact replay, `XTR-COMMAND-409` conflict, and pointer-based status/open; post-merge separately reran `cargo fmt`, strict Clippy workspace all-targets all-features, strict rustdoc workspace all-features no-deps, `cargo test` workspace all-targets all-features, `cargo test` workspace all-features, restricted-PATH clean vendored-protoc build, and `git diff --check` (focused `xtrace-ingest` suite and CLI smoke were not separately rerun after merge — focused ingest was included within both full workspace suites) | Complete and merged. `xtrace-ingest` exposes a pure, async-free `IngestValidator` that owns per-`RecordingId` `RecordingLifecycle` (`Recording` → `Finalizing`) with support for interleaved recordings, strict monotonic `recording_seq` ordering with forward-gap `RetransmissionNeeded` hints that never mutate state, structural `RecordingStarted` and `RecordingFinished` retries accepted via cloned prost structs compared with `PartialEq`-derived field equality against the prior admission, while event-batch retries are accepted via the retained deterministic BLAKE3 digest of the typed `RecordingEvent` payload, whole-batch atomicity so a rejected batch never mutates validator state, bounded capacity at both active-recording and per-recording event budgets returned as typed rejections, retention of `Finalizing` entries plus their event digests for the validator's lifetime (no drain/eviction API), and `u64::MAX` inclusive preflight bounds so exact replays and final contiguous events at the maximum are accepted without checked arithmetic overflow. Honest boundary: the validator is not yet wired into `xtrace-daemon`, so there is no durable recording persistence, no XTF translation, no segment writer, no `Committed` ACK, no Java/Node adapter, no UI, and no real capture/replay journey claimed — Slice 1C.2 stops at the typed seam between generated protocol envelopes and the recording aggregate | Slice 1C.3: smallest daemon-side integration of `xtrace-ingest` behind the existing authenticated XTP session so post-hello `RecordingStarted`/`EventBatch`/`RecordingFinished` envelopes route through `IngestValidator`, return typed `Acceptance`/`IngestError` verdicts, and continue to emit the same `Staged` ACKs as Slice 1C.1 — still no durable persistence, XTF writer, segment writer, `Committed` ACK, or domain-terminal recording state |
| Slice 1C.3 reviewed and merged | Wire the pure `xtrace-ingest` `IngestValidator` into each authenticated daemon Session before volatile staging | Feature head `38d040f`; merge commit `a3c788d` on `main` (present on `origin/main`); `Cargo.lock`, `crates/xtrace-daemon/Cargo.toml`, `crates/xtrace-daemon/src/daemon.rs`, `crates/xtrace-daemon/src/error.rs`, `crates/xtrace-daemon/src/lib.rs`, `crates/xtrace-daemon/src/runtime.rs`, `crates/xtrace-daemon/src/session.rs`, `crates/xtrace-daemon/tests/loopback_handshake.rs` | Independent pre-merge verification passed: `cargo fmt`; strict Clippy workspace all-targets all-features; strict rustdoc workspace all-features no-deps; `xtrace-daemon` 119 unit plus 20 loopback tests; `cargo test` workspace all-targets all-features 275 passed; `cargo test` workspace all-features 276 passed including 1 doctest; restricted-PATH clean vendored-protoc build; `git diff --check`; the real recoverable loopback journey passed three extra serial repetitions. Independent post-merge verification passed the same `cargo fmt`, strict Clippy, strict rustdoc, daemon test suite, both workspace suites, `git diff --check`, and a clean restricted-PATH vendored-protoc build | Complete and merged. Each authenticated Session now owns one `IngestValidator`, so `RecordingStarted`/`EventBatch`/`RecordingFinished` are validated before admission; successful accepted and retry outcomes continue to emit the same `Staged` ACK shape with the canonical recording UUID key and validator-derived watermarks, recoverable ingest rejections send the safe `XTR-CAPTURE-INGEST` protocol error and permit a corrected retry at the same `session_seq`, fatal ingest or other session errors send the protocol error and close, while validator rejection and capacity/overflow preflight leave session state unchanged. Honest boundary: still volatile process-local staging only — no SQLite recording persistence, XTF/segment writer, `Committed` ACK, domain-terminal recording state, restart recovery, retransmission command delivery, Java/Node adapter, UI, or real capture/replay claim | Slice 1C.4: central recording-persistence schema plus a crash-safe XTF segment commit port/contract with deterministic store tests, still not wired into daemon admission and without a Committed ACK claim |
| Slice 1C.4 reviewed and merged | Establish the storage-local canonical XTF v1 codec, recording schema, and crash-safe segment-object commit seam | Feature head `6c1d73c`; merge commit `c052314` on `main`; XTF storage protobuf and protocol generation, `xtrace-store` migration/codec/recording-store implementation, and deterministic store tests | Independent pre-merge review and post-merge verification passed: `cargo fmt`; strict Clippy workspace all-targets all-features; strict rustdoc workspace all-features no-deps; `xtrace-protocol` 11/11; `xtrace-store` 67/67, including five default-parallel full-store repetitions after replay-hook isolation repair; both workspace test forms; restricted-PATH clean vendored-protoc `xtrace-protocol` build; and `git diff --check`. `cargo-deny` was unavailable. Review repairs covered strict migration fail-closed behavior, bounded/verified XTF compression, shared writer and root binding, complete object identity, staging-link durability across every post-publication boundary, and scoped panic-safe replay test hooks. | Complete and merged. `xtrace-store` now provides a storage-local typed recording anchor and segment commit seam that canonicalizes typed events into verified compressed XTF v1 objects, atomically publishes content-addressed objects on the supported Unix path, and records `recording_segments` metadata with exact-replay, conflict, continuity, root-safety, and deterministic fault-boundary coverage. Honest boundary: it is not wired to live daemon capture/admission; it emits no `Committed` ACK and does not claim a complete recording commit. Frame indexes, recording counters, outbox, recovery, retention, source snapshots, adapters, query/UI, and terminal state handling remain deferred. | Approval-gated Slice 1C.5: add an application port/use case and daemon composition over the storage seam; replan and extend the atomic transaction before any `Committed` ACK or terminal-state claim. |
| Slice 1C.5 reviewed and merged | Connect validated XTP recording admission through an application-owned capture service and `xtrace-store` adapter, retaining `Staged` ACK semantics | Feature commits `d1c2207` (application port/use case and SQLite adapter) and `35ade84` (daemon composition and lifecycle repairs); merge commit `fcaa2f2` on `main`; `xtrace-application`, `xtrace-store`, and `xtrace-daemon` capture seams/tests | `cargo fmt --all`; strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`; strict `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`; `cargo test --workspace --all-targets --all-features`: 347 passed; `cargo test --workspace --all-features`: 347 passed plus 1 doctest; restricted-PATH clean vendored-protoc build; `git diff --check`. `cargo-deny` was unavailable. | Reviewed and merged. The daemon optionally receives an application capture port and has no production dependency on `xtrace-store`; its pipeline maps start/finish into application lifecycle requests and translates only admitted `RecordingEvent` payloads into typed XTF envelopes, while batches remain application record-events requests, on a one-active/64-total bounded blocking lane. The application owns bounded per-recording assembly, exact-retry preflight, stable begin identity, deterministic segment sealing, finish flush, and typed persistence; the SQLite adapter receives an explicitly injected project data root. Capture succeeds before the staged Session front is released and its existing `Staged` ACK is sent; persistence failures are safe and connection-local. Honest boundary: validator admission and persistence are not one atomic transaction; no `Committed` ACK, durable terminal transition, recording counters/frame indexes, outbox, restart recovery, or retention cleanup is implemented (retained recording IDs may exhaust their configured daemon-lifetime budget until restart). Started synchronous port work is non-preemptible; abrupt cancellation of `serve` cannot stop an already-started blocking call. No Java/Node adapter, UI, or complete real capture/replay Gate journey is claimed. | Approval-gated next step: define the smallest real-adapter vertical journey and its evidence gate; do not infer completion of Gate 4 from this infrastructure slice. |
| Slice 1C.6 reviewed and merged | Launch a Unix-only project daemon from the CLI with private lifecycle artifacts and real selected-root SQLite recording ingress, preserving `Staged` ACK semantics | Feature commit `d7d870f`; progress commit `60c2281`; merge commit `5fb2594` on `main` (`origin/main`); `crates/xtrace-cli` daemon command/composition, advisory project lock, secure path handling, and subprocess tests | `cargo fmt --all`; strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`; strict `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`; full workspace all-targets suite: 367 passed; full workspace all-features suite: 367 passed plus 1 doctest; CLI: 42 unit tests plus 3 subprocess tests; daemon: 122 unit plus 23 loopback tests; restricted-PATH clean vendored-protoc build; `git diff --check`. `cargo-deny` was unavailable. | Complete, reviewed, and merged. `xtrace daemon --project-dir DIR` validates an existing project, acquires its advisory lock before permission repair or SQLite open/migration, composes selected-root SQLite capture, creates a unique private per-session bootstrap artifact, and emits one structured `daemon_bound` readiness record after bind/publication. SIGINT/SIGTERM resolve graceful shutdown; known runtime artifacts are cleaned on graceful exit and stale known artifacts on the next locked start. The readiness record describes durable segment ingress with `Staged` ACKs; global `capture_supported` and `replay_supported` remain false. Honest boundary: no app child launch/`run`, Java/Node adapter, full capture/replay support, query/UI, terminal state, `Committed` ACK, derived index/counters, outbox, or recovery semantics. Bootstrap artifacts have no time-expiry contract; SIGKILL may leave residue until next start, and hostile same-UID namespace mutation is outside the lock boundary. Linux mode-000 permission repair depends on procfs and fails closed when unavailable. | Slice 1D.1: Node 22 synthetic XTP protocol foundation only; no instrumentation or Node support claim. |
| Slice 1D.1 reviewed and merged | Establish generated Node XTP bindings, a pinned-TLS/exporter authenticated protocol client, and a private synthetic recording emitter that proves `Staged` ACKs plus selected-root XTF persistence | Feature commit `86f8d49`; docs commit `b6477ce`; merge commit `c59ddaa` on `origin/main`; `adapters/node` protocol and adapter-core packages, generated canonical schema bindings, synthetic client and fixture, shared Rust/Node handshake vector, CI and setup docs, and daemon integration acceptance | Post-merge reproduction passed: Node tests 11/11; `cargo fmt --all -- --check`; strict workspace Clippy; strict workspace rustdoc; `cargo test --workspace --all-targets --all-features`: 369 passed; `cargo test --workspace --all-features`: 369 passed plus 1 doctest; live Node-to-daemon selected-root SQLite/XTF persistence integration included; restricted-PATH clean vendored-protoc build; `git diff --check` | Reviewed and merged. Honest boundary: this is a Unix-only synthetic protocol/conformance client, not Node instrumentation or a Node capture-support claim. It proves only staged ACKs and stored synthetic XTF data. No Java agent, Spring instrumentation, UI/query path, `Committed` ACK, or complete capture/replay journey is claimed. | Proposed next slice: Java 17 synthetic protocol foundation, first checking security-reviewed Conscrypt TLS-exporter feasibility; still no instrumentation or Java capture-support claim. |
| Slice 1D.2 reviewed and merged | Establish a Java 17 synthetic XTP protocol/conformance foundation with generated protobuf bindings, isolated pinned TLS 1.3 exporter authentication, strict bootstrap/framing/envelope validation, and a private synthetic recording emitter | Feature commit `79275fd`; merge commit `2f5f490` on `main`; `adapters/java` Gradle workspace, Java protocol client and tests, shared handshake vector, CI/setup integration, and real daemon acceptance in `crates/xtrace-cli/tests/java_synthetic_adapter.rs` | Independent security and build re-reviews were clean after repairs. Strict Gradle `clean test installDist`: 13 tests discovered, 12 passed and 1 expected current-platform skip; Node regression 11/11; `cargo fmt --all -- --check`; strict workspace Clippy on both the current toolchain and Rust 1.98; strict workspace rustdoc; both full workspace test forms passed 370 tests, with the second also passing 1 doctest; real Java and Node daemon integrations verified selected-root SQLite rows and XTF contents; restricted-PATH clean vendored-protoc build; CLI smoke; actionlint; `git diff --check`; feature CI run `36643446966` passed all three jobs. | Reviewed and merged. The slice proves a Java synthetic client can authenticate and persist staged synthetic recording data without weakening the transport contract. The inherited CI expression parser issue and Rust 1.98 lint drift exposed during review were repaired and closed. Honest boundary: synthetic protocol client only—no `javaagent`, `premain`, attach, framework discovery, or real capture-support claim. Live bootstrap use remains Unix-only; the strict build/protoc verification matrix covers Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, and Windows x86_64. | Slice 1D.3: smallest launch-only Java `premain` plus one real Spring MVC fixture capture; no attach, async, broad compatibility, or UI claim. |
| Slice 1D.3 reviewed and merged | Prove a launch-only, fixture-scoped Java `premain` path captures one real Spring MVC/JDBC request through the existing daemon into selected-root SQLite/XTF while remaining fail-open and privacy-bounded | Candidate `4424bbe`; merge `bf5af10`; 43 files across `adapters/java` bootstrap/runtime/fixture modules, strict Gradle metadata/locks, the real daemon acceptance in `crates/xtrace-cli/tests/java_premain_spring.rs`, CI, README/setup, and the shared event-digest fixture | Independent security, concurrency, privacy, shutdown, build, and architecture re-reviews were clean after repairs. Strict Gradle completed 32 tasks; 34 Java tests were discovered, 33 passed and 1 expected platform test skipped. Node passed 11/11; focused Rust integrations passed 3 premain + 1 Java synthetic + 1 Node synthetic; full Rust suites passed 373 and 373 plus 1 doctest; format, strict Clippy, strict rustdoc, restricted-PATH clean vendored-protoc, CLI smoke, actionlint, and diff check passed. Feature CI `36652340632` and post-merge CI `36652536432` were fully green. | Reviewed and merged. The proof captures ordered request, controller, service, repository, coarse H2, response, and thrown-error frames with bounded nonblocking handoff, deterministic loss accounting, private runtime isolation, full-stream canary checks, and honest incomplete-capture diagnostics. Boundary: exact Spring fixture only and launch-only; route identity is fixed source-derived metadata, not general endpoint discovery. No attach path, browser replay, source/line/value capture, WebFlux, or general Java/Spring/Servlet framework-support claim exists yet. | Approval-gated Slice 1D.4: smallest CLI-supervised Java launch path, `xtrace run -- <application command>`, that composes the existing project daemon and private `-javaagent` bootstrap injection, supervises child exit/cleanup, and proves the same fixture capture; still no attach, discovery, browser replay, or broad compatibility claim. |
| Slice 1D.4 reviewed and merged | Add experimental Unix-only `xtrace run` supervision for a direct Java executable while capturing the exact Spring fixture into the selected project's SQLite/XTF store | Final candidate `2e5fd535f0b42bb81c7a19b6b7771cbccc5bb74f`; merge `c40945ef64e54664319fed72bcf351b4d8518019`; `crates/xtrace-runtime/src/java.rs` owns direct-JDK validation, Java process-group supervision, and typed launch errors; `crates/xtrace-cli/src/run.rs` composes the selected-root daemon lifecycle; `crates/xtrace-cli/src/daemon_lock.rs` owns lock/runtime-artifact cleanup; `adapters/java/agent-bootstrap/build.gradle.kts` emits and permission-normalizes the exact JAR distribution and SHA-256 manifest; `crates/xtrace-cli/tests/java_run_spring.rs` and `adapters/java/spring-fixture/src/test/java/dev/xtrace/fixture/ProcessGroupLeaderTest.java` exercise real Spring capture and process cleanup; README, setup docs, and Java 17/21 CI updated | On the final candidate, with `umask 0002` set: `cargo test -p xtrace-runtime` passed 10/10 and `cargo test -p xtrace-cli --test java_run_spring -- --test-threads=1` passed 4/4; `cargo fmt --all -- --check`; strict `cargo clippy --workspace --all-targets --all-features -- -D warnings`; strict `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`; `cargo test --workspace --all-features`; `cargo test --workspace --all-targets --all-features --no-fail-fast`; restricted-PATH clean `xtrace-protocol` build with vendored protoc; strict Gradle `clean test installDist agentDist fixtureBootJar` plus repeated `agentDist` with identical manifest SHA-256; and `git diff --check` passed. Feature CI `36661501374` and post-merge CI `36661662191` were green. Linux `umask 0002` exposed distribution-mode assumptions, fixed by normalizing directories to 0755 and files to 0644 while retaining rejection of group-writable artifacts. The Temurin failure was an OpenJDK marker window off-by-one (`openjdk version ` is 16 bytes); the literal-length fix and marker regression passed on Ubuntu JDK 17/21. | Reviewed and merged. `xtrace run --project-dir DIR --java-agent PATH -- java ...` validates and launches only a direct native JDK executable, preserves OS argv, injects only the existing `-javaagent:<bootstrap-jar>=<private-bootstrap-path>` argument, composes the project-scoped daemon in-process, forwards signals and kills same-process-group residue, drains for at most five seconds, and returns the child's status. Security/architecture decisions: Java policy stays in `xtrace-runtime`; ambient `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, and `_JAVA_OPTIONS` are cleared; JVM `@argfile` and caller-supplied agents are rejected; distribution membership/digests and Unix ownership, link-count, symlink, and write-mode checks remain enforced; the same-UID replacement race after validation is explicitly outside this experiment. If drain exceeds five seconds, capture is marked incomplete and the CLI retains the project lock and known runtime artifacts through process exit; the next locked start removes recognized stale artifacts. Honest boundary: experimental Unix-only direct `java` launch for the exact Spring fixture, not Gradle/Maven or wrapper orchestration, attach-to-running JVM, general endpoint discovery, browser/TUI, Node launch, or broad Spring/Servlet support. | Slice 1E.1: add a storage/application read path and bounded CLI `recording list/show` Linear JSON projection over verified persisted XTF, establishing the shared DTO/query seam for the browser; no browser/TUI, source/value inspection, or debugger-complete claim is in scope for 1E.1. |
| Slice 1E.1 reviewed and merged | Add safe read-only recording list/show over verified persisted XTF, with bounded Linear event projections | Candidate `68010fc9`; merge `9286934`; application DTO/use case in `crates/xtrace-application/src/recording_queries.rs`, verified XTF read in `crates/xtrace-store/src/recording_store.rs`, and CLI composition in `crates/xtrace-cli/src/commands.rs`; README and developer setup describe the commands and bounds | Architecture review's three blockers were repaired: oversized display fields remain paginatable with explicit safe replacement metadata, aggregate verified-input work is capped per show request, and raw interaction paths are omitted. Formatting, strict Clippy/rustdoc, both full workspace suites, actual Spring `xtrace run` integration, restricted-PATH vendored-protoc build, and `git diff --check` passed. Feature CI `36671553641` and post-merge CI `36671767307` passed. | Reviewed and merged. The read path validates project/root binding and decodes touched segments through the existing XTF verifier; list/show output is bounded by event/JSON/input limits, uses project-and-recording-bound cursors, and excludes values, source bodies, raw interaction paths, and completion claims. Honest boundary: this is a local CLI/read seam, not a browser or TUI; only persisted metadata is projected, and it does not establish source locations, captured values, or completion semantics. | Completed reference: Slice 1E.2 below. |
| Slice 1E.2 reviewed and merged | Add an experimental browser Linear recording workspace over the shared application query seam without changing the existing `xtrace open` default | Candidate `457814181c3b1bf9b2ba06bcf6f35d32f42773b6`; merge `c0f1de9558a86826e7f234eb58c67bb51967ed98`; shared `RecordingQueryService`/verified SQLite-XTF query path in `xtrace-application` and `xtrace-store`; foreground viewer and isolated HTTP adapter in `xtrace-daemon`; explicit CLI composition in `xtrace-cli`; pinned React app, generated OpenAPI TypeScript, embedded asset manifest, browser journey, and CI in `web/app`, `schema/xtp-client/openapi.yaml`, and `.github/workflows/ci.yml` | Feature CI `36691711591` and post-merge CI `36693125899` completed successfully with all four jobs green. Gates include Rust formatting, strict Clippy and workspace tests; restricted-PATH vendored-protoc build and CLI smoke; Java 17/21 Spring `xtrace run` acceptance; web typecheck, six UI tests, 7.32:1 quiet-text contrast, OpenAPI generation drift and embedded-asset checks. The real browser journey compares persisted API event order with the actual `xtrace run` Spring recording, exercises selection, keyboard/pane navigation and 390×844 layout constraints, checks unavailable evidence and privacy canaries, verifies session-cookie/URL/storage behavior, and confirms query-time SQLite and project-pointer bytes remain unchanged. Independent full-diff architecture/security review resolved OpenAPI response/required-field drift, bootstrap expiry consumption, and stale detail response handling before merge. | Reviewed and merged. `xtrace open --viewer` explicitly runs a separate IPv4-loopback HTTP viewer in the foreground; plain `xtrace open` retains its prior behavior. A one-use 60-second fragment token exchanges for a host-only HttpOnly SameSite=Strict browser-session cookie with an in-memory 15-minute server expiry; exact Host, Origin/Fetch Metadata and client-marker checks are enforced, while the experimental plain-HTTP listener cannot set `Secure` and does not defend against hostile same-UID processes. The shared query service returns bounded, ordered, verified persisted event windows; the UI retains bounded windows and exposes safe metadata only, renders text as text, and omits raw interaction paths. Source locations, captured values, durations, completion semantics, and route inference are not established. Honest boundary: experimental local viewer and exact existing Spring fixture journey only—not source replay/debugger completion, broad Java/Spring support, general endpoint discovery/static inference, TUI, or complete Gate 4 support. | Completed reference: Slice 1E.3A below; next is Slice 1E.3B, shared observed-endpoint query and bounded CLI JSON, no viewer yet. |
| Slice 1E.3A reviewed and merged | Persist an observed-only endpoint association for the exact Spring fixture while retaining UUIDv7 public operation IDs | Feature `1a0760ddd7de093e4d9e99ed9a1d89d2645ef29a`; merge `af8886641de1a99a264e7cd429b7ff445cee7c97`; ADR and schema v3 `operations` plus `recording_endpoint_observations` sidecar; begin-recording persistence, application/domain/store/CLI seams, and fixture acceptance | Independent architecture, security, and build approvals. `cargo fmt`; strict Clippy; strict rustdoc; 92 store tests; full workspace all-features plus doctest; Java Gradle 35 tasks; real premain/run/synthetic suites; restricted-PATH vendored-protoc build; `git diff --check`; post-merge main CI `36708896655` green across all four jobs. Initial local post-merge full command lacked generated Java/web prerequisites; after building those prerequisites on the SSD, the exact failed suites passed—the first result was environment setup, not a code failure. | Complete and merged. Public `OperationId` remains UUIDv7; an internal versioned deterministic-CBOR/BLAKE3 fingerprint deduplicates endpoint tuples. The CLI requires the operator-selected `spring-orders-v1` policy plus run-scoped `spring-fixture`/`default` identity; the policy is an assertion, not adapter/application attestation. The finite rule accepts only `POST /orders`. Recording and linked/unmatched sidecar disposition commit atomically at begin; safe replay equivalence ignores rejected raw values, legacy recordings remain unmatched, and UUID/tuple/fingerprint/sidecar/project mismatches fail closed. Rejected raw inputs and their digests are not retained. A real Spring run verified one operation linked to two persisted recordings. | Completed reference: Slice 1E.3B1 below; next is Slice 1E.3B2 CLI commands/integration. |
| Slice 1E.3B1 reviewed and merged | Add the shared observed-endpoint read/query service and bounded safe projections over persisted endpoint associations | Feature `a5c2629766a11b67388355e2a323c1f6a7c21fe4`; merge `88b54bb2823f9b9040d9eefa7905092ff1a29dfb`; `xtrace-application` shared `ObservedEndpointReadPort` and query service, safe endpoint/recording DTOs, plus SQLite read-port implementation in `xtrace-store` | Independent architecture, security, and build approvals. Formatting, strict Clippy, strict rustdoc, focused and full workspace suites, restricted-PATH vendored-protoc build, and `git diff --check` passed. Post-merge full workspace verification, including Java/Node integration, passed. GitHub CI run `36773014509` passed all four jobs. | Complete and merged. Provides versioned canonical query-bound keyset cursors and project-scoped SQLite `limit + 1` reads for endpoint listing, linked recordings, and unmatched recordings (including legacy sidecar-absent recordings). Tuple, fingerprint, sidecar, orphan, UUIDv7, and time integrity checks fail closed. Reads are read-only. Honest boundary: B1 adds no CLI command wiring; Slice 1E.3 remains incomplete. | Slice 1E.3B2: wire CLI endpoint list, linked-recording, and unmatched-recording modes through the shared application query service, preserving the existing recording-list behavior. |

## Recording-ID compatibility prerequisite merged (2026-10-01)

Feature `8973b24885b85eacb6ebdd143cfdfd468429a33a`; branch authorization
checkpoint `8595a5d0c8b5c978aaba86debcb8ae5c87edd0ae`; no-ff merge
`b479ef29ed6eacc0005ce794bf9e202b13de77ea`. Feature CI `36817040759` and
main CI `36817399287` passed all four jobs, including Java 17/21 and Node.
The user accepted ADR 0002 and requested GPT-6 Sol reviews because Terra was
unavailable. Luna implemented; Sol separately approved architecture,
security/privacy, and build evidence. The orchestrator independently inspected
the complete pinned diff and verified both feature and merged main.

Observed stored recording IDs and canonical scoped recording cursors accept
RFC UUIDv4/v7; operation/project identities retain their existing v7 rules. New
Java capture IDs are v7 using JDK-only timestamp/random encoding. There is no
ID re-key, sidecar backfill, XTF rewrite, schema migration, or capture expansion.
Historical linked/unmatched/sidecar-absent v4 IDs retain their stored bytes;
mixed v4/v7 keyset pagination and invalid version/variant rejection pass.

On feature and merged main: formatting, strict locked all-target/all-feature
Clippy, strict locked all-feature rustdoc, focused tests (211 passed), full
locked all-feature workspace tests (446 passed including doctest), clean
restricted-PATH locked workspace build with no system protoc, and diff checks
passed. Strict Java clean/test/installDist/agentDist/fixtureBootJar, Node
generation/tests, and web typecheck/tests/API/embedded asset checks passed.
The real Spring run checks new persisted UUIDv7 IDs and the existing viewer
journey; this is not B2 endpoint CLI acceptance.

Next slice: resume B2 on this reviewed prerequisite. Repair malformed leading-
hyphen/ambiguous CLI argument privacy, prove actual linked captures before
supplemental fixtures, and exercise historical v4 continuation. Then independently
review and run the exact gate before B2 merge/push/CI. HTTP/OpenAPI follows B2;
endpoint-first browser UI and its real journey follow the HTTP contract.

| Slice | Goal | Files changed | Verification | Result | Next slice |
|---|---|---|---|---|---|
| Recording-ID compatibility prerequisite | Preserve historical identities and generate v7 for future Java captures | Feature `8973b248`; store/app recording validation, Java bootstrap/tests, ADR 0002, narrow plan references, real Spring test | Independent Sol architecture/security/build reviews, exact feature and postmerge gates, CI `36817040759` / `36817399287` | Reviewed, merged, pushed; no broader framework or B2 query claim | Slice 1E.3B2 real CLI acceptance and privacy repair |

## Slice 1E.3B2 reviewed and merged (2026-10-01)

Source feature `73b085765818a5ae28460361a52a268afcb59ea6`; feature head
`084488f55b2bdf6d7f060b8beee28b110d0e0efe`; no-ff merge
`cbc245b3ccbaa90bd1514be5f4fb9a982fd0c93e`. Feature CI `36818429219`
and main CI `36819077501` passed all four jobs (aggregate gates, Node,
Java 17, and Java 21). Luna implemented; Sol independently approved the
complete pinned architecture/security diff and separately audited build and
integration evidence. The orchestrator inspected the complete diff and ran
the exact gates on both feature and merged main.

The bounded `endpoint list`, `endpoint recordings OPERATION_ID`, and explicit
`recording list --unmatched` JSON commands use the shared observed query service
and DTOs. Legacy recording-list `--after` behavior remains available. Conflicting
modes fail before storage opens. Malformed leading-hyphen and ambiguous arguments
produce static correlated JSON errors without echoing raw input; help/version
remain available. Shared service limits, canonical scoped cursors, safe NotFound,
and v4/v7 recording compatibility are preserved.

All eight gates passed on feature and merged main: formatting, strict locked
workspace/all-target/all-feature Clippy, strict locked all-feature rustdoc,
focused tests (215 passed), full locked all-feature workspace tests (450 passed
including doctest), a fresh restricted-PATH locked workspace build with no
system protoc, and worktree/committed diff checks. Fresh strict Java
clean/test/installDist/agentDist/fixtureBootJar passed. Seven disposable-project
parser/help probes passed. The genuine Spring captures are queried and paged
before supplemental linked/unmatched fixtures; assertions then cover historical
v4 continuation, stable timestamp ties, malformed/stale/cross-scope cursors,
unknown/cross-project lookup, privacy canaries, and unchanged SQLite, pointer,
and XTF bytes and metadata. The previously blocked assertions now all run.

Boundary: the finite policy permits one endpoint per project, so endpoint
continuation boundaries are tested without fabricating multi-endpoint discovery.
Supplemental synthetic rows exercise ordering and unmatched compatibility; they
do not stand in for actual captures. The existing recording-first browser journey
passes, but B2 adds no HTTP routes or endpoint-first UI and does not complete
Slice 1E.3 or the broader Slice 1 journey.

Next bounded phase: Slice 1E.3C, the three approved observed-query HTTP routes
plus OpenAPI/generated client types. Preserve viewer authentication, query-lane
bounds, legacy response behavior, safe errors, and shared DTOs; verify actual
authenticated reads of persisted Spring and historical-v4 unmatched recordings.
The endpoint-first browser and real visual journey follow the stable HTTP seam.

| Slice | Goal | Files changed | Verification | Result | Next slice |
|---|---|---|---|---|---|
| Slice 1E.3B2 | Expose bounded endpoint/linked/unmatched CLI JSON through the shared service | CLI commands/parser/output, test-only temp paths, Spring integration, dev dependencies/lock, setup/progress | Sol architecture/security/build approvals; exact feature/postmerge eight gates; 215 focused and 450 workspace tests; CI `36818429219` / `36819077501` | Reviewed, merged, pushed, CI-green; no endpoint-first browser claim | Slice 1E.3C HTTP/OpenAPI |

## User-requested pause / SSD removal checkpoint (2026-10-01)

The user explicitly requested stopping and committing current work before
disconnecting the SSD. Implementation and both Sol review agents were stopped.
Main remains clean and pushed at `c1527544922785892d90d8c527235ad530f24b41`;
B2 merge `cbc245b3ccbaa90bd1514be5f4fb9a982fd0c93e` and checkpoint CI
`36819456708` are green across all four jobs.

The isolated `slice/1e3c-http-api` branch preserves unfinished HTTP/OpenAPI work:
shared observed service composition, three observed GET modes, strict bounded
query parsing, canonical operation validation, safe correlated problems,
OpenAPI schemas, and partial real Spring HTTP/browser acceptance additions.
`git diff --check` passes. Luna reported focused daemon tests passing before
the latest integration additions; that report is not an independent final gate.

This is a WIP preservation commit, not an accepted phase. Complete pinned Sol
architecture/security reviews, generated OpenAPI TypeScript, HTTP corruption/
saturation/scoped-cursor coverage, real Spring pagination/restart/privacy checks,
the exact eight gates, feature CI, and merge/postmerge verification remain
pending. No HTTP feature was merged or pushed to main; no endpoint-first UI was
implemented. The browser acceptance script and integration additions were still
being edited when work stopped and must be verified on resume.

Resume only after the user requests continuation with the SSD mounted. Start
from this checkpoint and current Git/process truth, finish and amend this same
bounded feature, then review and verify before publishing/merging. Preserve B2
and the accepted ADR 0002; do not recreate or re-key completed work.

## Slice 1E.3C reviewed and merged (2026-10-03)

Source feature `4009b61b60fc2b6658f2037f276953e4d81e3141`; no-ff merge
`9b530b097763c148a0c158b10b62396f9fb0aa34`. Feature CI `37123864124`
and main CI `37124174180` passed all four jobs (aggregate gates, Node,
Java 17, Java 21). The Oct 1 WIP `9667649` is historical preservation only;
it was completed and amended before review, gates, publication, and merge.
Luna High implemented. Sol High independently approved the complete pinned
architecture and security/privacy diff, then separately audited local build/
integration evidence. The orchestrator inspected every actual changed line,
ran all exact gates, and alone pushed and merged.

Three observed query modes now compose `ObservedEndpointQueryService` through
the existing read-only reader and two-permit `QueryLane`:

- `GET /api/v1/endpoints?limit&cursor` (default 50, maximum 100).
- `GET /api/v1/endpoints/{operationId}/recordings?limit&cursor` (25/50).
- `GET /api/v1/recordings?unmatched=true&limit&cursor` (25/50).

They return the shared lowerCamelCase `{items,nextCursor}` DTOs. Existing
recording-list response/after behavior remains available when unmatched is
absent. Strict mode parsing, canonical operation paths (including invalid-UTF8
path rejection), and bounded cursor transport fail safely without echoing
input. Authentication precedes queries. Unknown and cross-project operations
have indistinguishable safe 404 responses. Corruption is 422; observed SQLite
busy or shared-lane saturation is 503; legacy resource classification remains
unchanged. Existing Host/Origin/Fetch Metadata/client marker/session/bootstrap,
response headers, connection/time/header limits, and shutdown bounds remain.
OpenAPI and generated TypeScript match direct pages, required nullable fields,
conditional recording modes, limits, and request-ID headers.

All eight exact gates passed on the final feature and merged main: formatting,
strict locked workspace/all-target/all-feature Clippy, strict locked all-feature
rustdoc, focused application/store/CLI tests (215 passed), full locked all-feature
workspace tests (453 passed including doctest), fresh restricted-PATH locked
workspace build with no system protoc, and worktree/committed diff checks.
Zero failures or ignored tests. Strict Java clean/test/installDist/agentDist/
fixtureBootJar passed on feature preparation and again on merged main (35 tasks
executed). Web typecheck, six unit tests, 7.32:1 contrast, generated API drift,
embedded assets, Node generation and 11 tests passed in feature preparation;
those component sources did not change in the final test-only amendment.

The real packaged Spring test pages two genuine persisted linked captures with
HTTP limit 1 and compares CLI/API DTOs before synthetic supplements. It proves
cross-project 404 parity and cursor rejection, stops viewers, then restarts
and runs actual Chromium assertions for tied v4/v7 linked/unmatched and legacy
sidecar-absent v4 rows, no duplicates, privacy/session/storage/URL constraints,
unchanged verified detail order, and query-only SQLite/pointer/XTF checks.
Authenticated actual SQLite identity corruption returns safe HTTP 422. Holding
both shared-lane permits produces HTTP 503 with zero port calls; releasing them
restores HTTP 200. Supplemental fixtures test ordering/compatibility and do not
replace genuine capture evidence. Interrupted browser-script scope errors were
fixed and all acceptance assertions now execute.

Boundary: UI remains recording-first. The finite operator-selected policy
permits one endpoint/project, without adapter/application attestation or general
endpoint discovery. HTTP completes this bounded API phase, not Slice 1E.3's
endpoint-first product journey or broader Slice 1. No migration, capture/XTP,
source/line/value, duration, completion, static inference, or replay expansion.

Next bounded phase: Slice 1E.3D endpoint-first browser. Use the stable shared
HTTP seam to show observed endpoint -> linked genuine recording -> existing
verified detail, plus a separate unmatched-recordings path. Label policy as
operator-selected and explicitly non-attesting. Preserve independently bounded
pages/cursors, stale-response protection, keyboard/mobile behavior, and privacy.
Rebuild/embed the shipped assets, prove the exact Spring restart browser journey,
and visually inspect desktop/mobile evidence before acceptance. Follow the
same Luna implementation, independent Sol architecture/security/build reviews,
exact gates, feature CI, no-ff merge, postmerge gates/CI, and progress workflow.

| Slice | Goal | Files changed | Verification | Result | Next slice |
|---|---|---|---|---|---|
| Slice 1E.3C | Bounded authenticated observed endpoint/linked/unmatched HTTP through the shared service | CLI reader/viewer composition, daemon HTTP/tests/dev dependency, Spring/Chromium acceptance, OpenAPI/generated TypeScript, lock and progress | Pinned Sol architecture/security/build approval; exact feature/postmerge eight gates; 215 focused / 453 workspace tests; CI `37123864124` / `37124174180` all four jobs green | Reviewed, merged, pushed, CI-green; UI remains recording-first | Slice 1E.3D endpoint-first browser and real visual journey |

## Slice 1E.3D reviewed and merged (2026-10-03)

Source feature `a1d89cd22f6075c56779fcda41c33177b31439d0`; no-ff merge
`5c848dd52ebb5d748f616559e1526313d4ef7556`. Feature CI
`37139481240` and merge CI `37139761333` passed all four jobs (aggregate
gates, Node, Java 17, Java 21). Luna High implemented. Sol High independently
approved the pinned complete architecture and security/privacy diff and separately
audited build/integration evidence. Root reviewed the complete actual eight-file
diff, visually opened all ten final desktop/mobile screenshots, confirmed the
restricted build environment, and alone pushed and merged.

The browser starts with observed endpoint method/exact route/component/binding.
Selecting an endpoint opens only its bounded linked recordings, then the existing
verified detail. Unmatched recordings remain separate, including historical v4
with null reason. The UI labels `spring-orders-v1` as operator-selected and
explicitly non-attesting. Endpoint/linked/unmatched/event windows and cursors are
independent and bounded, async generations reject obsolete replies, and session
expiry, keyboard navigation, mobile 390x844 tabs, and the three desktop regions
are preserved. Shipped assets were rebuilt with exact manifest parity.

All eight exact gates passed on feature and merged main: formatting, strict
locked workspace/all-target/all-feature Clippy, strict locked all-feature
rustdoc, focused application/store/CLI tests (215 passed), full locked all-feature
workspace tests (453 passed including doctest), fresh restricted-PATH locked
workspace build with no system protoc, and working/full committed diff checks.
Zero failures or ignored tests. Strict Java clean/test/installDist/agentDist/
fixtureBootJar passed before feature integration and again on merged main (35
tasks executed). Web typecheck, 12 tests, 7.32:1 contrast, API/embedded parity,
Node generation and 11 tests passed on the final feature and merged main.
The earlier `edf70ad` candidate failed Rust formatting; a small formatting repair
and stronger negative session assertion were amended before full repeated gates.
No failed candidate was accepted.

Real checked-in Spring runs through packaged `xtrace run` with all three explicit
opt-ins. Two genuine `POST /orders` captures are persisted before supplemental
ordering/compatibility fixtures. After stop/restart, authenticated actual Chromium
selects endpoint -> genuine linked recording -> verified detail, then separately
identifies historical unmatched v4/null reason. Verified CLI/API/browser event
order, truthful unavailable labels, cookie/session/URL/storage/full-origin privacy,
canaries, and query-only SQLite/pointer/XTF bytes, mtime, and modes pass. Root
visually accepted all ten candidate desktop1280x720/mobile390x844 screenshots;
postmerge repeats the real journey with identical shipped assets.

Local evidence: SSD `.cache/xtrace/orchestrator/phases/browser-a1d89cd`,
`browser-preparation`, `browser-main-5c848dd`, and `browser-reviews`.
The Oct 3 projectless continuation outputs contain sanitized screenshots,
independent/root reviews, command/result JSON, status report, and resume prompt.

Bounded Slice 1E.3 observed endpoint catalog/product journey is complete for the
exact finite operator-selected policy. Whole Slice 1 and the product remain
incomplete. This is not general endpoint discovery or adapter/application
attestation; source/line/value/duration/completion/replay expansion is absent.
The fixture has one endpoint and fewer than a page of linked rows: backend
continuations and UI state/unit pagination pass, but actual Chromium does not
click every new list's next-page control. Local Java17 and CI Java17/21 evidence
remain distinct. No schema, capture, XTP, HTTP, or shared query contract changed.

Next session: reconcile current source against remaining approved Slice 1 exit
criteria, then propose the smallest bounded source/active-line/provenance evidence
increment. Preserve the verified endpoint/query/browser seam and accepted ADRs.
Source mapping, launch support, replay controls, values/outcomes, and
completion/partial-state semantics still need their own reviewed real evidence.
Resolve material architecture/product choices before implementation; routine
reviewed continuation remains authorized. This long chat ends at a clean handoff,
with no background implementation or scheduled continuation left running.

| Slice | Goal | Files changed | Verification | Result | Next slice |
|---|---|---|---|---|---|
| Slice 1E.3D | Endpoint-first observed catalog -> genuine linked recording -> verified detail; separate historical unmatched path | Browser source/tests/CSS, actual Chromium script, Spring integration plumbing, embedded JS/CSS/manifest | Pinned Sol architecture/security/build approvals; root complete diff/ten screenshot review; exact feature/postmerge gates; 215 focused/453 workspace, 12 web/11 Node; CI `37139481240` / `37139761333` all four jobs | Reviewed, merged, pushed, CI-green; bounded Slice 1E.3 exact-fixture journey accepted; broader Slice 1 incomplete | Reconcile remaining Slice 1 criteria and plan smallest source/active-line evidence increment |


## v0.01 owner-requested WIP preservation and orchestrator handoff (2026-10-04)

The owner requested committing/pushing all current preparation and handing the remaining launch to Opus 5.5 with Sonnet 5.5 agents, using batched routine checks. This supersedes the next-session model assignment; it does not accept unfinished phases. Main remains `3e47895f`; all 55 mandatory release rows remain pending. Focused control tooling passed 85 tests, but the subsequent 23-gate floor failed before every gate. Both exact leases were manually recovered under fresh proof; original failures remain unchanged. All active agents are frozen/completed, and the continuation heartbeat is paused for handoff.

Twelve feature branches preserve current WIP. The pack admission commit `e48d6d2` is unbuilt/untested; the global-quiescence source patch is unapplied and requires changes. See [the sanitized source pins, failures, review findings and remaining launch scope](../evidence/v0.01/handoff-2026-10-04.md). No new phase was accepted, merged into main, tagged or released. Next root must refresh live state, finish the runner and full floor, then complete dependency-aware implementation, exact accepted-phase gates, six real packaged campaigns, platform/supply-chain verification and genuine human/owner acceptance before publication.


## P00 accepted and merged — Opus 5.5 / Sonnet 5.5 Session 0 (2026-10-04)

**P00 (release control, exact gate runner and CI floor) is accepted.** `slice/v001-control-admission` at `a304a21ba32a` was no-ff merged into `main` as `77784d9c638f`. **No product requirement row is claimed. All 55 mandatory rows in `evidence/v0.01/requirements.json` remain pending.** The release decision stays `not_ready`.

Evidence on the exact candidate and on `main`:
- **Leased macOS arm64 floor**, pre-merge, on `a304a21`: `P00-floor-a304a21-210142-ba90c7` passed all 23 gates (`checks_passed_for_review`). Receipt sha256 `257881f6f13bcded9b6f65a288ef640fedc6a754b13c7c8471c1f821068a10aa`. Fresh builder leases were taken and released.
- **Leased macOS arm64 floor**, post-merge, on `main` `77784d9`: `P00-postmerge-main-77784d9-211015-2450a3` passed all 23 gates. Receipt sha256 `432aff9e2f81a78e7c7892fea47a43cc47ed2e4f56a37ad672d12ae09c682aa1`.
- **GitHub feature CI run 37234304072** on `a304a21`: every job green, including the Linux x86_64 23-gate release floor for `jdk17-node22` and `jdk21-node24`, and the release-tool suite (265 tests, OK, no skips).
- **Main CI** on `77784d9`: run 37234986469 attempt 1 had every job green except the Linux floor `jdk17-node22`, where one product test (`run_launches_spring_fixture_captures_selected_root_and_forwards_shutdown`, `crates/xtrace-cli/tests/java_run_spring.rs:138`) failed in gate 17 although the tree is byte-identical to the candidate that passed both tuples; a single re-run of the failed job (attempt 2) passed, so every main job is green on attempt 2 and the test is recorded as nondeterministic (S1 finding, #3). The attempt-1 failure is preserved, not hidden.
- **Reviews:** independent architecture, security/privacy and build/integration reviews, followed by two delta re-review rounds. Every required fix was applied and verified, including removing a public CI-log leak path found in review.

What P00 delivers:
- The global-quiescence churn repair: one absolute 120 s settle and two quiet scans after the latest uncertainty, failing closed.
- **ADR 0007**, provenance classification. On macOS an uninspectable process is classified by its resource coalition; on Linux, by child-subreaper descendant tracking. There are no UID or process-name exemptions and no privileged inspection; delegated-work residuals are documented.
- The generic leased runner: command allowlist, private HOME, env policy and bounded receipts.
- The reviewed dry-run-first lease-recovery tool.
- The release ledger checker, the CI floor workflow (Linux x86_64, both runtime tuples) and the release-control evidence and docs.
- A deterministic `npm run generate` for the Node adapter. The floor proved the earlier generator was not idempotent.

**Incidents, recorded honestly:**
- The original owner-authorized task-private cache root was deleted outside this session, most likely by a system cache cleaner. That wiped the two previously retained builder leases and the earlier failed floor and run receipts. Those receipts now survive only as the hashes recorded in the private execution state. The owner approved recreating the private cache at a new location (not published). Nothing was recovered or overwritten; the failed results stay failed.
- One worker ran a name-based `pkill` against its own dev-container image name, which the lane rules forbid. No other lane's container was running, and no evidence was affected. The rule is restated for future sessions.

**Product finding for S1 (#3):** `xtrace init` derives its default idempotency key from the raw repository path, capped at 128 characters, so it fails on long paths. CI works around this with short private roots; the product fix is a digest-based key.

Next: consolidate the repaired preparation lanes on `slice/v001-integration` and merge them only after their own gates pass. The remaining work is split into seven sessions under epic #2 (#3–#9); start with S1 (#3).

## S0b integration base accepted and merged — Opus 5.5 / Sonnet 5.5 (2026-10-08)

**The v0.01 integration base is consolidated, green on Linux x86_64 and macOS arm64, and merged to `main`.** `slice/v001-integration` at `34176cadeb91b17df26af934513023933cf0e3a2` was no-ff merged into `main` as `fa4ffa4e320768001a97f63d3d94644c929c5a4d`. This is preparation consolidation: **no product requirement row is claimed. All 55 mandatory rows in `evidence/v0.01/requirements.json` remain pending**, and the release decision stays `not_ready`.

Evidence on the exact candidate and on `main`:
- **Leased macOS arm64 floor**, pre-merge, on `34176ca`: `S0bF4-34176ca` passed all 23 gates (`checks_passed_for_review`). Receipt sha256 `fc6f2375a80bc8571416c0978cfe32db3d9550c6a52c583481e37d3d791f1c8d`. Three earlier macOS floors on intermediate heads are kept on record:
  - `S0bF-ec82730` failed at gate 2 (`rust-clippy`). The newer host clippy caught macOS-only lints that no CI job compiles. Receipt sha256 `05e2210b622f99b8d044fd22eba29d0131757e5c9e0f8d15d0a963beafe88208`.
  - `S0bF2-6edd2ea` passed 23/23. Receipt sha256 `f7d0b5f572c258e61aa055fa66b931f123c086a5a997c0a40fecb263874835d7`. That head then failed GitHub CI on a pack-cache race (run 37745516886), which was fixed.
  - `S0bF3-1eee1df` failed at gate 17 (`rust-focused`). Parallel tests collided on test-directory names because macOS clocks tick in microseconds. Receipt sha256 `0d744afd6c7b82fe0fb751a1ceffa177ad7f17da56fd66abb2723f93524783e4`.
- **Leased macOS arm64 floor**, post-merge, on `main` `fa4ffa4`: `S0bPM-fa4ffa4` passed all 23 gates (`checks_passed_for_review`). Receipt sha256 `1154aadac8c74a5ace8b68589c574b045b22658f5b362ef334cacb01e35d5eba`.
- **GitHub CI** on the candidate `34176ca`: ci run 37759726381 and package run 37759726252, every job green, including the Linux x86_64 23-gate release floor for `jdk17-node22` and `jdk21-node24` and the package build on linux-x86_64 and macos-arm64.
- **Main CI** on `fa4ffa4`: run 37768052891, every job green on attempt 1, including the Linux x86_64 23-gate floor for both tuples.
- **Spring stability:** `java_premain_spring` and `java_run_spring` passed 20 consecutive leased macOS runs per runtime tuple on the final candidate `34176ca` (jdk17-node22 and jdk21-node24). They also passed 20 repeats per tuple in the Linux devbox on the earlier head `59ba631`, and both Linux CI floors run them again on every head.
- **Reviews:** independent architecture, security/privacy and build/integration acceptance reviews at `876cc67`, then focused independent reviews of every fix, then a second full acceptance round at `3a5e2de` (all approve; every requested fix applied and root-reviewed), then independent reviews of the later race and lint fixes.

What S0b delivers on top of P00:
- **Private storage.** Named-file validation is now descriptor-free (stat, path ACL probe, re-stat), because closing a second descriptor on a live SQLite file releases its POSIX locks. It is extended to macOS. The policy now lives in one leaf crate, `xtrace-private-storage`, shared by the store, daemon, CLI and Java attach. Admission uses one deadline per operation (budget unchanged at 750 ms). macOS ACL probes are memoized per operation and batched into one `ls` run per walk. The Linux traversal ACL policy admits the stock runner layout (a default ACL on `/home`). Java attach caches again admit tmpfs through an explicit filesystem profile. **ADR 0008** records the policy, its residuals and its test obligations.
- **Recording capacity (owner-ordered contract change).** Past 2,048 events a recording no longer fails: extra events are dropped, counted under their own priority, never persisted, and the recording ends Partial. The SQL CHECK in the unreleased v0004 migration is gone. ADR 0003 carries a dated amendment.
- **Java pack snapshot cache.** Snapshots are built under a private incoming name and published by rename. Per-snapshot use leases protect in-use snapshots, the least recently used one is evicted, crash residue heals, and hashing streams. State files use exclusive create, because concurrent plain `O_CREAT` on APFS can return a spurious ENOENT. Listers tolerate entries that vanish concurrently, while unknown names still fail closed.
- **Spring tests** wait for durable `status='complete'` within their existing deadlines. The nondeterministic `run_launches_spring_fixture…` failure was the test observing a row visible at RecordingStarted before the finish commit.
- **Test fixtures** create explicit 0700/0600 modes, so they pass under CI's umask 022. No product path depends on umask.
- **Release tooling.** One run-start epoch for both leases. Recovery tolerates at most 120 s of epoch skew for the same pid, label and token. macOS start times come from sysctl when proc_pidinfo is denied. Day-first `ps lstart` is parsed (en_AU hosts). The `ps` uid of nobody is read correctly. Epochs that are huge or invalid are refused in a structured way.
- **CI and packaging.** Test scratch lives under the runner temp directory. Every checkout drops persisted credentials. The process-group termination test treats a zombie under the floor's subreaper as gone. Packaging strips the macOS debug map, which made `LC_UUID` depend on the build path.

**Incidents, recorded honestly:**
- **The SSD unmounted during the session** (~2026-10-07 20:29Z). All agents and containers were stopped and Docker Desktop was restarted. Nothing was written to the external volumes while they were unmounted, and repository integrity was verified after the remount.
- **Builder leases retained three times** by `uncertain_process_tree` endings: two from tooling bugs since fixed, and one from an unrelated root login process started on the host during a run. Each was recovered with the reviewed tool after clean dry runs (manual-recovery sha256 `a36ed66f…`, `c30a4a74…`, `3c2f32af…`). The only lease removed by hand is the owner-approved case below.
- **The owner decision on scope.** The first architecture review required five pre-existing design fixes (F1–F5). The owner chose to land all of them in S0b. The session paused about 7 h waiting for that answer.
- **One worker ran `cargo fmt` on the host** instead of in the devbox. It only formatted files; nothing was built and no cache was written.
- **A worker ran `pkill -f x` on the host** (~2026-10-08 09:44Z), which the rules forbid. It killed many of the owner's processes, including Docker Desktop, editor and browser helpers, a local database's workers and the owner's messaging gateway, and it killed the worker's own leased run. The two builder leases were left behind by a runner killed mid-flight, which the recovery tool cannot clear. With the owner's approval they were removed by hand under recorded proof that no process from that run survived (proof sha256 `c4ca0550…d370`, addendum `9a71bcd0…ec0a`). Docker Desktop was restarted with the owner's approval.

**Findings for later sessions:**
- **S1 (#3):**
  - The default `init` idempotency key is still derived from the raw path, so it exceeds 128 characters on long paths.
  - Nothing yet recovers a recording left in `recording` (F6), and the default port reports `Ok(Partial)` for a finish that persisted nothing.
  - Before v0004 is released, decide whether `capacity_dropped_events` becomes a column or API field, whether the `AdapterSummary` shape is right (F9), and whether stored request JSON gets a format version (F10).
- **Private storage:**
  - The macOS ACL listing parser is ASCII-only, so paths with non-ASCII names are refused (fail closed).
  - Under extreme parallel I/O, the parent-directory fsync can exhaust the 750 ms budget and admission refuses (seen in the Linux devbox, never in CI).
  - A native ACL query would replace `ls` parsing (S7, #9).
  - `create_private_child` reports a name collision (EEXIST) as the generic `Operation` error instead of `AlreadyExists`.
- **Java pack cache:** `evict()` lacks the name-to-inode recheck that `lease()` performs (hardening).
- **Release tooling (#8):**
  - Add Python and Rust golden vectors for the private-root policy.
  - Amend ADR 0007 for start-instant comparison and epoch skew.
  - `recover_leases` cannot recover leases whose runner was killed mid-run (receipt still `running`).

Next: S1 (#3). The session prompt is in the private execution state's session kit.
