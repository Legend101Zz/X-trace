# Java campaigns: how the INSTRUMENTED run is done later

Status: preparation only. Nothing here is acceptance evidence. The baseline harness
(`campaigns/java/<project>/harness/run.py`) records an uninstrumented, reproducible
reference; the instrumented run reuses the same scenarios and compares fingerprints.

## Platform constraint (read first)

The v0.01 release claim covers macOS arm64 and Linux x86_64 only (ADR 0005 section 3). The
baseline containers here are `linux/arm64` (Docker Desktop on Apple silicon), which is NOT a
release platform. The baseline proves determinism of scenarios and database reset, not capture.
The packaged `xtrace` therefore runs the application JVM on the HOST (macOS arm64) or on a
Linux x86_64 runner, with only PostgreSQL in a container:

```
export XTRACE_CAMPAIGN_ROOT=<private cache root>            # contains java/<project>/src
export XCAMP_APP_MODE=host                                   # app on host JVM, DB in container
export XCAMP_JAVA=<JDK17-or-21>/bin/java                     # petclinic 17; jhipster, fineract 21
export XCAMP_LAUNCH_PREFIX="xtrace run --project-dir <P> --java-agent <agent.jar> --"   # empty = baseline
python3 campaigns/java/<project>/harness/run.py baseline     # same scenarios, host JVM
```

`xtrace run` accepts only a direct executable named `java` and preserves the argument vector
(setup.md "Experimental xtrace run"); the harness already builds exactly
`<prefix> java -Duser.timezone=UTC -Dfile.encoding=UTF-8 <jvm opts> -jar <jar> <args>` and clears
`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`. The prefix is where the packaged
launcher (final released command shape, `xtrace run -- java -jar ...`) is placed. The JAR is the
SAME file the baseline used (sha256 in `pin.jarSha256`); Maven/Gradle wrapper launch forms
(`xtrace run -- ./mvnw spring-boot:run`) are NOT used because `run` rejects non-`java` launchers.
Attach form for the second journey: start the baseline JAR with `XCAMP_LAUNCH_PREFIX=` empty and
a long-lived stack, then `xtrace attach --pid <pid>` and replay the scenarios (needs the
attach-capable stack split of `Stack.up()` from scenario execution; not built yet).

To obtain a host baseline fingerprint set for comparison, run the harness in host mode with an
empty prefix first; it must equal the container baseline fingerprints (cross-check recorded in
the report) before any instrumented run is compared to it.

## Per-project launch and seams each scenario must show

Seam vocabulary (ADR 0005): `H` = handler/resource-method identity with route template,
`I` = at least one intermediate application method frame (repository/service), `D` = JDBC
statement (sanitized SQL text, no parameters by default) and `O` = outcome (status/exception).

### spring-petclinic (JDK 17, Spring MVC + JDBC/pgjdbc)
Launch: `xtrace run -- java -Xmx768m -jar target/spring-petclinic-4.0.0-SNAPSHOT.jar --spring.profiles.active=postgres ...`
| scenario | H | I | D | O |
|---|---|---|---|---|
| search-seeded | `OwnerController.processFindForm` `GET /owners`, `VetController.showResourcesVetList` `GET /vets` | `OwnerRepository.findByLastNameStartingWith` | select owners/pets | 200 |
| owner-create-roundtrip | `OwnerController.processCreationForm` `POST /owners/new`, `showOwner` `GET /owners/{ownerId}` | `OwnerRepository.save` | insert owners | 302 then 200 |
| owner-validation-error | `processCreationForm` | (none expected: validation fails before save) | no write | 200 form |
| pet-and-visit-flow | `PetController.processCreationForm`, `VisitController.processNewVisitForm` | `OwnerRepository.save/saveAndFlush` | insert pets, visits | 302; duplicate/past-date 200 |
| owner-edit | `OwnerController.processUpdateOwnerForm` `POST /owners/{ownerId}/edit` | `OwnerRepository.save` | update owners | 302 |
| missing-owner-error | `OwnerController.showOwner` | `OwnerRepository.findById` | select | exception IllegalArgumentException, 500 |
| controller-crash-path | `CrashController.triggerException` `GET /oups` | - | none | RuntimeException, 500 |
| concurrent-isolation | 30 x `showOwner` + 10 x create: each recording's route/path params match its own request | repository frames per request | per-request | no cross-association |

### jhipster-sample-app v9.4.0 (JDK 21, Spring MVC/Boot 4.1.1 + JDBC + servlet root)
Launch: `xtrace run -- java -Xmx1g -jar target/jhipster-sample-application-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod ...` (env as in harness).
Seams: `AuthenticateController.authorize` `POST /api/authenticate`; `AccountResource.getAccount`; `UserResource.getAllUsers`;
`BankAccountResource.{createBankAccount,getBankAccount,updateBankAccount}`, `LabelResource.*`, `OperationResource.*`; intermediate
`BankAccountService`/`*Repository` methods; JDBC on `bank_account`, `operation`, `label`, `rel_operation__label`, `jhi_user*`.
Auth scenarios: 401 from the Spring Security filter chain happens BEFORE any controller: the recording must show a servlet root
with outcome 401 and `handler_unresolved`/no handler (not a wrongly attributed handler). The JWT bearer value must never appear in
any captured surface (privacy canary: use the JWT and the synthetic passwords).

### apache/fineract 1.15.0 (JDK 21, Spring Boot 3.5.15, servlet root + Jersey, pgjdbc)
Launch: `xtrace run -- java -Xmx2g -jar fineract-provider/build/libs/fineract-provider-1.15.0.jar --server.address=127.0.0.1` with the
FINERACT_* env of the harness (`FINERACT_SERVER_SSL_ENABLED=false` adaptation).
Seams: servlet root, then Jersey resource-method identity at `ResourceMethodInvoker` for
`ClientsApiResource.create/retrieveOne/update/delete/activate` (`/fineract-provider/api/v1/clients[/{clientId}]`, `?command=activate`),
`OfficesApiResource.retrieveOffices/retrieveOffice`; intermediate: `PortfolioCommandSourceWritePlatformService.logCommandSource`,
`ClientReadPlatformService`, `ClientWritePlatformService`; JDBC pgjdbc on `m_client`, `m_office`, `m_appuser` (+ command audit tables).
Basic-auth 401 occurs in Spring Security before Jersey: expected outcome is servlet root + 401 without a Jersey method.
The 404/400 JSON errors are produced by Jersey exception mappers: recording outcome = mapped status, not an unhandled exception.
If the Jersey module is unavailable the honest degraded outcome is `handler_unresolved` (ADR 0005), never a pass.

## Comparison and receipt

For every scenario the instrumented run recomputes `semanticEffectFingerprint` with the same normalization;
`campaign-compare` equals `compare` in `xcamp.py`: scenario fingerprints must be byte-equal to baseline.
`check_ledger.py` (CAMPAIGN-* validator) requires per campaign receipt, inside the attestation:

- `upstream`: `canonicalUrl` (https), `sha` (40 hex), `stableTag` (non-empty, EXCEPT petclinic);
  petclinic instead carries `tagException` = `{ownerDecision: "Use current main SHA with explicit tag exception",
  obsoleteTagUsed: false, tagWasMissing: true, testedRefKind: "branch-main-sha"}` (already in its `campaign.json`);
- `scenarios`: list of >= 5; each with a non-empty `name`, artifact refs `baseline`, `instrumented`, `browser`, `privacy`,
  `overhead` (each a file ref under the evidence root, hash-checked), `semanticEffectFingerprint` (64 lowercase hex) and
  `instrumentedSemanticEffectFingerprint` EQUAL to it;
- `artifacts` (attested release artifact refs), and a trusted signature with role `campaign-runner`;
- the receipt must bind to the exact accepted `releaseBuild` (id, source SHA, artifactSetSha256).

Map: scenario `id` -> receipt `name`; baseline receipt.json (this preparation, sanitized) -> `baseline` ref;
instrumented capture/assert JSON -> `instrumented`; desktop/mobile browser journey record -> `browser`;
canary scan of wire/logs/storage/API/export/diagnostics -> `privacy`; repeatable timing runs -> `overhead`.
Baseline timing for overhead comparison is in every scenario's `elapsedMs` / per-request `elapsedMs` (container on a loaded host:
use only for same-host A/B ratios).
