#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: tools/dev/check.sh <part> [extra args]' \
        'Parts: rust:<crate>[:<testname>], java[:<module>] [test-pattern],' \
        '       node, web[:<file>], py:<module>, fmt, diff, help'
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
export CARGO_NET_OFFLINE=true
export NPM_CONFIG_OFFLINE=true

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
            run cargo test -p "$crate" --test "$testname" --locked "$@"
        else
            [[ -n $crate ]] || { usage >&2; exit 2; }
            run cargo check -p "$crate" --all-targets --all-features --locked "$@"
            run cargo test -p "$crate" --lib --all-features --locked "$@"
            run cargo clippy -p "$crate" --all-targets --all-features --locked "$@" -- -D warnings
        fi
        ;;
    java|java:*)
        task=test
        if [[ $part == java:* ]]; then
            module=${part#java:}
            [[ -n $module && $module != *:* ]] || { usage >&2; exit 2; }
            task=":$module:test"
        fi
        if [[ $# -gt 1 ]]; then usage >&2; exit 2; fi
        if [[ $# == 1 ]]; then
            run adapters/java/gradlew -p adapters/java --offline --dependency-verification strict \
                "$task" --tests "$1"
        else
            run adapters/java/gradlew -p adapters/java --offline --dependency-verification strict "$task"
        fi
        ;;
    node)
        run npm run generate:check --prefix adapters/node
        run npm test --prefix adapters/node "$@"
        ;;
    web|web:*)
        run npm run typecheck --prefix web/app
        if [[ $part == web:* ]]; then
            file=${part#web:}
            [[ -n $file ]] || { usage >&2; exit 2; }
            run npx --prefix web/app vitest run --root web/app "$file" "$@"
        else
            run npx --prefix web/app vitest run --root web/app "$@"
        fi
        ;;
    py:*)
        module=${part#py:}
        [[ -n $module ]] || { usage >&2; exit 2; }
        run python3 -B -m unittest "$module" "$@"
        ;;
    fmt) run cargo fmt --all --check "$@" ;;
    diff)
        printf '+ git merge-base origin/main HEAD\n'
        base=$(git merge-base origin/main HEAD)
        run git diff --check "$base" "$@"
        run git diff --check "$@"
        ;;
esac
