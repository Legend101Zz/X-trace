#!/usr/bin/env bash
# Owner release check (2026-11-11 decision, W2-R27a). Run from a clean checkout:
#   bash tools/dev/macos-release-check.sh
# Prerequisites: macOS, Xcode command line tools, stable Rust (rustfmt/clippy),
# Python 3, Node 22 or 24/npm, OpenSSL 3 first on PATH, and a local JDK 17.
# Locally installed JDKs 17/21/25 are tested; missing versions are reported.
# Set XTRACE_DEV_CACHE and XTRACE_DEV_SCRATCH as in tools/dev/README.md.
# Run tools/dev/prep.sh --adapters --browsers first (locked dependencies only).
# No GitHub access is needed. Logs stay in a new private scratch directory.
# Package journey requires arm64; other-UID checks need the hosted manual workflow.
# Missing coverage exits 2; suite failures exit 1. Neither is a release pass.
set -uo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
if [[ $(uname -s) != Darwin ]]; then
    printf 'macos-release-check: requires macOS exit=2\n' >&2
    exit 2
fi
source tools/dev/env.sh "" || exit 1
export TMP="$TMPDIR" TEMP="$TMPDIR" PYTHONDONTWRITEBYTECODE=1
run_root=$(mktemp -d "$TMPDIR/mrc.XXXXXX") || exit 1
export LANE_PRIVATE_LOG_DIR="$run_root/logs"
summary="$run_root/summary"
: > "$summary"
result=0

# Execute outside a conditional so errexit inside each suite remains effective.
# Each suite has a separate process and private log; later suites always run.
run_suite() {
    local name=$1 code
    shift
    ( set -e; "$@" ) >"$run_root/$name.log" 2>&1
    code=$?
    printf '%s exit=%s\n' "$name" "$code" >> "$summary"
    if [[ $code != 0 ]]; then result=1; fi
}
gap() {
    printf '%s NOT-COVERED exit=2\n' "$1" >> "$summary"
    if [[ $result == 0 ]]; then result=2; fi
}
lane() {
    python3 -B -m tools.qa.lane_run run --out "$run_root/frag" "$@"
}
release_tools() {
    python3 -B -m tools.release.ci_floor summarize-tests \
        --root "$run_root" --repo "$PWD" --source-sha "$(git rev-parse HEAD)" \
        --log-file "$run_root/release-raw.log"
}
node_suite() {
    lane --suite node --step install -- npm ci --prefix adapters/node
    lane --suite node --step generate-check -- npm run generate:check --prefix adapters/node
    lane --suite node --step test --min-passed 85 --max-ignored 0 -- npm test --prefix adapters/node
    npm run build --prefix adapters/node
}
web_suite() {
    lane --suite web --step install -- npm ci --prefix web/app
    (cd web/app && npx --no-install playwright install chromium)
    lane --suite web --step typecheck -- npm run typecheck --prefix web/app
    lane --suite web --step unit-tests --min-passed 75 --max-ignored 0 -- npm test --prefix web/app
    lane --suite web --step check-api -- npm run check:api --prefix web/app
    lane --suite web --step check-embedded -- npm run check:embedded --prefix web/app
}
java_suite() {
    local version=$1 jdk=$2
    export JAVA_HOME="$jdk"
    export PATH="$JAVA_HOME/bin:$PATH"
    lane --suite java --variant "$version" --step gradle --cwd adapters/java \
        --junit-glob '*/build/test-results/test/*.xml' --min-passed 190 --max-ignored 0 -- \
        ./gradlew --no-daemon --dependency-verification strict \
        -Dorg.gradle.java.installations.auto-download=false \
        -I "$run_root/jdk.gradle" -PxtraceReleaseJdk="$version" \
        clean test installDist agentDist fixtureBootJar
}
rust_suite() {
    lane --suite rust --step build -- cargo build --locked --workspace --all-features --message-format=json
    lane --suite rust --step test --min-passed 1030 --max-ignored 0 -- \
        cargo test --locked --workspace --all-features --no-fail-fast
}
diagnostic_guard() {
    local features assertions code
    for assertions in false true; do
        for features in ci-diagnostics __all__; do
            local flags=(--features "$features")
            if [[ $features == __all__ ]]; then flags=(--all-features); fi
            set +e
            CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=$assertions cargo check --release --locked \
                -p xtrace-private-storage "${flags[@]}" > "$run_root/diagnostic.log" 2>&1
            code=$?
            set -e
            [[ $code != 0 ]]
            if [[ $assertions == true ]]; then
                grep -F 'ci-diagnostics is forbidden in release profiles even with debug assertions' "$run_root/diagnostic.log"
            else
                grep -F 'ci-diagnostics requires debug_assertions; release/package builds must exclude it' "$run_root/diagnostic.log"
            fi
        done
    done
}
package_suite() {
    python3 -B packaging/build.py --out "$run_root/dist" --platform macos-arm64
    sh packaging/install.sh verify-dist "$run_root/dist/macos-arm64"
    sh packaging/test/install_test.sh "$run_root/dist/macos-arm64"
    sh packaging/test/install_scratch_test.sh
}
# Compilation keeps the repository's JDK 17 toolchain. Test JVMs (and their
# launched agent/client processes) use each locally available JDK explicitly.
cat > "$run_root/jdk.gradle" <<'GRADLE'
allprojects {
    plugins.withId('java') {
        tasks.withType(Test).configureEach {
            javaLauncher = javaToolchains.launcherFor {
                languageVersion = JavaLanguageVersion.of(project.property('xtraceReleaseJdk').toString().toInteger())
            }
        }
    }
}
GRADLE
run_suite release-tools release_tools
run_suite node node_suite
run_suite web web_suite
jdk_count=0
for version in 17 21 25; do
    jdk=$(/usr/libexec/java_home -F -v "$version" 2>/dev/null)
    if [[ -n $jdk && -x $jdk/bin/java ]]; then
        run_suite "java-$version" java_suite "$version" "$jdk"
        jdk_count=$((jdk_count + 1))
    else
        gap "java-$version-unavailable"
    fi
done
if [[ $jdk_count == 0 ]]; then gap java-no-local-jdk; fi
run_suite release-diagnostic-guard diagnostic_guard
run_suite rust rust_suite
if [[ $(uname -m) == arm64 ]]; then
    run_suite package package_suite
else
    gap package-requires-arm64
fi
gap other-uid-hosted-only
printf '\n'
cat "$summary"
printf 'macos-release-check exit=%s\nPrivate logs: %s\n' "$result" "$run_root"
exit "$result"
