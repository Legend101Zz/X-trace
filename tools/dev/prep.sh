#!/usr/bin/env bash
set -euo pipefail

adapters=0
browsers=0
for arg in "$@"; do
    case "$arg" in
        --adapters) adapters=1 ;;
        --browsers) browsers=1 ;;
        *) printf 'Usage: tools/dev/prep.sh [--adapters] [--browsers]\n' >&2; exit 2 ;;
    esac
done

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source tools/dev/env.sh ""
# Prep deliberately permits downloads, even after an offline check in this shell.
export CARGO_NET_OFFLINE=false
export NPM_CONFIG_OFFLINE=false

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

run cargo fetch --locked
run npm ci --prefix adapters/node
run npm ci --prefix web/app
# A dependency report fetches metadata, but not every artifact an offline build needs.
init_script=$(mktemp "$TMPDIR/xtrace-dependencies.XXXXXX")
trap 'rm -f -- "$init_script"' EXIT
cat > "$init_script" <<'GRADLE'
gradle.projectsEvaluated {
    gradle.rootProject.tasks.register('xtraceDevResolveDependencies') {
        doLast {
            gradle.rootProject.allprojects.each { project ->
                project.configurations.findAll { it.canBeResolved }.each { it.resolve() }
            }
        }
    }
}
GRADLE
run adapters/java/gradlew -p adapters/java --dependency-verification strict \
    --init-script "$init_script" xtraceDevResolveDependencies
if [[ $adapters == 1 ]]; then
    run npm run build --prefix adapters/node
    run adapters/java/gradlew -p adapters/java --dependency-verification strict \
        testClasses installDist agentDist fixtureBootJar
    # Assets are checked in; check:embedded builds the viewer and verifies them.
    run npm run check:embedded --prefix web/app
fi
if [[ $browsers == 1 ]]; then
    run npx --prefix web/app playwright install chromium
fi
