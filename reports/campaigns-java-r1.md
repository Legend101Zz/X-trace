Sonnet 5.5 (model ID claude-sonnet-5-5)

# Java campaigns preparation, round 1 (NOT acceptance)

Branch `slice/v001-campaigns-java` from 3e47895f90e6a78e08b1d808d4498e4595f71a5d. Preparation only: uninstrumented baselines,
no packaged xtrace, no browser/privacy/overhead evidence. `releaseAcceptance: false`.

## Pins (verified with `git ls-remote` against canonical https URLs, checkouts verified at exact SHA, tracked files clean)

| project | canonical URL | tag | commit SHA | license (SPDX, sha256 of file) | JDK | build | Boot | web stack | DB |
|---|---|---|---|---|---|---|---|---|---|
| spring-petclinic | github.com/spring-projects/spring-petclinic | none (exception) | 500158f732419217507c7656904b8e6aa1bcc0d6 (refs/heads/main) | Apache-2.0, LICENSE.txt 56dfc19e0dc836e30177332f73e8e6fbc297941acf3d906eec6eaaa46c2c452a | 17 | Maven wrapper | 4.1.0 | Spring MVC / Tomcat / Thymeleaf | PostgreSQL 18.3 (profile `postgres`) |
| jhipster-sample-app | github.com/jhipster/jhipster-sample-app | v9.4.0 (latest stable tag) | 6b000b5d23a36c45e01472471b84a44fa2464044 | Apache-2.0, LICENSE.txt be304eadb6744cc7d260966f80f195fce43388caf9b4fe3866476a9ada89d415 | 21 | Maven wrapper, `-Pprod` | 4.1.1 (jhipster-framework 9.4.0) | Spring MVC / Tomcat, JWT security | PostgreSQL 18.3 (prod DB) |
| apache/fineract | github.com/apache/fineract | 1.15.0 (latest; annotated, tag object 9e76f088, peeled commit pinned) | d5636847ac556c30b437254c353f05526d172b97 | Apache-2.0, LICENSE_SOURCE 7e3b13f42d05b1da02165c5b0e200c9496a3e22f5642afa6b6909f3b1298cc98 (LICENSE_RELEASE c86b4df3..., APACHE_LICENSETEXT.md 1420334d...) | 21 | Gradle wrapper 8.14.5 `:fineract-provider:bootJar` | 3.5.15 | Tomcat 10.1.55 + **Jersey 3.1.11** (jersey-server/common read from the built jar) + Spring Security Basic | PostgreSQL 18.3, pgjdbc 42.7.11 |

Petclinic ledger fields recorded in its `campaign.json`: ownerDecision "Use current main SHA with explicit tag exception", obsoleteTagUsed false,
tagWasMissing true, testedRefKind "branch-main-sha". DB image: `postgres:18.3@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db`
(already local; linux/arm64). JDK images `eclipse-temurin:17-jdk-jammy` / `21-jdk-jammy` (pulled by me, anonymous docker config).
Jars (sha256): petclinic 45a515bc..., jhipster c4163d10..., fineract e4cff0ca... (full values in each `baseline-summary.json`).

## Scenarios (8 per project; every scenario has recorded request, status, body digest, DB-effect digest, fingerprint, timing)

- petclinic: search-seeded (+vets JSON); owner-create-roundtrip; owner-validation-error; pet-and-visit-flow (duplicate pet, past-date visit rejected); owner-edit; missing-owner-error (500); controller-crash-path (/oups 500); concurrent-isolation (30 parallel reads + 10 parallel creates). No auth/outbound in upstream.
- jhipster: anonymous-and-invalid-login-denied; admin-and-user-authentication (JWT, ROLE_USER 403 on admin API); account-create-read-roundtrip; account-validation-errors; account-update-and-missing; operation-with-relations; concurrent-isolation (12 create+reopen, 12 mixed-principal logins); delete-and-not-found. No outbound (mail health disabled upstream).
- fineract: denied-without-valid-credentials; authenticated-seed-read; client-create-read-roundtrip; client-validation-errors; client-update; client-activate-command (`?command=activate`, second activation rejected); concurrent-isolation (12 create+reopen, 16 reads); delete-and-not-found. No outbound dependency configured (not added: unrequested scope).

semanticEffectFingerprint = sha256(canonical JSON of scenario id, per-request label/status/headers/normalized-body digest, check outcomes, DB rows read via psql). Volatile data (timestamps, jsessionid, host:port, JWT, UUID, generated ids in concurrency scenarios) normalized.

## Baseline stability (private: `$XTRACE_CAMPAIGN_ROOT/java/<project>/baseline-<n>/`; sanitized `campaigns/java/<project>/baseline-summary.json`)

| project | runs from full reset | all 8 scenarios passed | fingerprints identical across runs |
|---|---|---|---|
| petclinic | 5 (4 container, baseline-5 on host macOS arm64 JDK 17) | yes | yes (host equals container) |
| jhipster | 3 | yes | yes |
| fineract | 3 (boot 52-72 s) | yes | yes |

Each run recreates network, Postgres (tmpfs) and app containers. Fingerprints (first 16 hex), petclinic: search 8809e203, create d291d328, validation fc44a0fc, pet/visit 5353905d, edit 5aa987aa, missing 02c92bb8, crash 4c9767a8, concurrent d7f724a9.
Defects fixed in the harness while stabilizing (failed attempts preserved under `failed-attempts/`): redirect Location has absolute host+jsessionid; time-dependent visit date (now fixed 2099 date); relative `href="N/..."` and Fineract `savingsProductName` echo leaked generated ids in concurrency scenarios; normalizer list leaked between scenarios; fineract effect queries targeted the tenant-store DB instead of `fineract_default`.

## Config-only adaptations (no upstream source change; documented in each campaign.json)
petclinic: profile postgres + env, skip tests/checkstyle/javaformat. jhipster: Maven prod profile with Angular client build skipped (REST/JWT backend only), skip tests/lint plugins, env datasource and a synthetic campaign JWT secret. fineract: SSL off + port 8080 via FINERACT_* env, bootJar only with tests/spotless skipped. All: Postgres on tmpfs with fsync off; upstream tests NOT run.

## Docker footprint (`docker system df`)
Before: Images 43 / 18.29GB, Volumes 13 / 948.5MB, Build cache 3.299GB. After: Images 49 / 22.22GB (+eclipse-temurin 17/21 ~0.8GB incl. shared layers; other lanes also added images), Volumes 17 / 6.428GB (+ my `xtrace-camp-m2`, `xtrace-camp-gradle`, roughly 1.5-2GB; the rest is other lanes), Build cache unchanged. My additions are within the 8 GB cap. No containers/networks of mine remain. I removed nothing I did not create.

## Blockers / risks for the later instrumented run
1. Platform: containers are linux/arm64, not a release platform. Instrumented runs must use the host JVM (macOS arm64, harness `XCAMP_APP_MODE=host`, proven with petclinic) or Linux x86_64 CI; see `campaigns/java/INSTRUMENTED-RUN.md`. Fineract/jhipster host mode is implemented but not run (needs JDK 21 path via `XCAMP_JAVA`).
2. `xtrace run` accepts only a direct `java` executable, so Maven/Gradle wrapper launch forms are not usable; attach flow needs a start/run split in `Stack` (not built).
3. Fineract boot is ~1 min on a loaded host; Gradle build took 29 min under load 30-40 (cold, one-time; cache volume `xtrace-camp-gradle`).
4. Jersey module (ADR 0005) is required for Fineract handler identity; Jersey 3.1.11 is the version fixture must cover. Auth 401s occur before Jersey/MVC (expect no handler).
5. Host machine is heavily loaded by other lanes: timings are for same-host A/B only.
6. Not done (out of preparation scope): browser, privacy canaries, overhead measurement, upstream test suites.

## Files
`campaigns/lib/xcamp.py`, `campaigns/README.md`, `campaigns/java/INSTRUMENTED-RUN.md`, `campaigns/java/{petclinic,jhipster,fineract}/{campaign.json,baseline-summary.json,harness/run.py}`, this report.
No shared-contract changes. No Cargo/Gradle runs of X-trace itself.
