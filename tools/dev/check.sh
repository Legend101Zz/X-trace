#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: tools/dev/check.sh <part> [extra args]' \
        'Compile-only parts: rust:<crate>[:<testname>], java[:<module>],' \
        '       node, web, py:<module>, fmt, diff, help' \
        'web:<file> is not supported; use web.'
}

part=${1:-help}
if [[ $# -gt 0 ]]; then shift; fi
case "$part" in
    help) usage; exit 0 ;;
    rust:*|java|java:*|node|web|web:*|py:*|fmt|diff) ;;
    *) usage >&2; exit 2 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source tools/dev/env.sh ""

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

case "$part" in
    rust:*)
        crate=${part#rust:}
        if [[ $crate == *:* ]]; then
            testname=${crate#*:}
            crate=${crate%%:*}
            [[ -n $crate && -n $testname && $testname != *:* ]] || { usage >&2; exit 2; }
            run cargo test -p "$crate" --test "$testname" --no-run --locked "$@"
        else
            [[ -n $crate ]] || { usage >&2; exit 2; }
            run cargo check -p "$crate" --all-targets --all-features --locked "$@"
            run cargo clippy -p "$crate" --all-targets --all-features --locked "$@" -- -D warnings
        fi
        ;;
    java|java:*)
        tasks=(compileJava compileTestJava)
        if [[ $part == java:* ]]; then
            module=${part#java:}
            [[ -n $module && $module != *:* ]] || { usage >&2; exit 2; }
            tasks=(":$module:compileJava" ":$module:compileTestJava")
        fi
        [[ $# == 0 ]] || { usage >&2; exit 2; }
        run adapters/java/gradlew -p adapters/java --dependency-verification strict "${tasks[@]}"
        ;;
    node)
        run npm run generate:check --prefix adapters/node
        run npm run typecheck --prefix adapters/node "$@"
        ;;
    web:*) printf '%s\n' 'web:<file> is not supported; use web.' >&2; exit 2 ;;
    web)
        run npm run typecheck --prefix web/app
        run node web/app/scripts/check-contrast.mjs
        ;;
    py:*)
        module=${part#py:}
        [[ -n $module ]] || { usage >&2; exit 2; }
        run python3 -B -m py_compile "${module//./\/}.py" "$@"
        ;;
    fmt) run cargo fmt --all --check "$@" ;;
    diff)
        printf '+ git merge-base origin/main HEAD\n'
        base=$(git merge-base origin/main HEAD)
        run git diff --check "$base" "$@"
        run git diff --check "$@"
        ;;
esac
