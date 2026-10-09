#!/bin/sh
# Install / upgrade / uninstall journey for a built archive, in a throwaway HOME (fresh profile).
#   packaging/test/install_test.sh dist/<platform>
# Scratch: $XTRACE_TEST_PRIVATE_SCRATCH (a private 0700 dir) when set, else $TMPDIR; only the self-created, marked work dir is removed.
# Needs only POSIX sh, tar and sha256sum|shasum. Exits non-zero on the first failed assertion (every check is `cmd && ok || fail`; the final count is
# asserted so a silently skipped check also fails).
set -eu
dist=$(cd "${1:?usage: install_test.sh dist/<platform>}" && pwd)
archive=$(ls "$dist"/xtrace-*.tar.gz)
# Private scratch root: product storage refuses a data dir under a world-writable ancestor (Linux /tmp), so CI points
# XTRACE_TEST_PRIVATE_SCRATCH at a 0700 directory it created; otherwise fall back to TMPDIR (user-private on macOS).
scratch_root=${XTRACE_TEST_PRIVATE_SCRATCH:-${TMPDIR:-/tmp}}
[ -d "$scratch_root" ] || { echo "scratch root $scratch_root is not a directory" >&2; exit 1; }
# Product storage refuses group/world-writable ancestors (A-10); refuse early with a pointer instead of dying at `xtrace init`.
scratch_perm=$(ls -ld "$scratch_root" | cut -c1-10)
case $scratch_perm in
  ?????w????|????????w?) echo "scratch root $scratch_root is group- or world-writable; set XTRACE_TEST_PRIVATE_SCRATCH to a private 0700 directory" >&2; exit 1 ;;
esac
start_dir=$(pwd -P)
work=$(mktemp -d "${scratch_root%/}/xt.XXXXXX") || { echo 'mktemp failed' >&2; exit 1; }
# physical path: private storage refuses symlinked components (macOS /var)
work=$(cd "$work" && pwd -P) || { echo 'cannot enter work dir' >&2; exit 1; }
case $work in ""|/|"$PWD"|"$start_dir"|"${HOME:-/nonexistent}") echo 'unsafe work dir' >&2; exit 1 ;; esac
# We only delete a directory this script created: it must have been brand new (empty) when we claimed it, then carries our marker.
[ -z "$(ls -A "$work")" ] || { echo 'work dir not empty (not freshly created)' >&2; exit 1; }
marker=".xtrace-install-test-owned"
: > "$work/$marker" || { echo 'cannot write ownership marker' >&2; exit 1; }
cleanup() {
  # best-effort, PID-identified stop of a daemon we may have left running (no pattern kill)
  if [ -n "${prefix:-}" ] && [ -x "$prefix/bin/xtrace" ] && [ -n "${repo:-}" ]; then "$prefix/bin/xtrace" stop --project-dir "$repo" >/dev/null 2>&1 || :; fi
  if [ -n "${work:-}" ] && [ -f "$work/$marker" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT
export HOME="$work/home"; mkdir -p "$HOME"
unset XTRACE_DATA_HOME XDG_DATA_HOME XTRACE_PREFIX
pass=0
ok() { pass=$((pass+1)); echo "ok $pass - $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
sums() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

sh "$(dirname "$0")/../install.sh" verify-dist "$dist" >/dev/null && ok "release SHA256SUMS verify" || fail "release SHA256SUMS verify"
mkdir "$work/x1" && tar -xzf "$archive" -C "$work/x1"
top=$(ls "$work/x1")
v1="$work/x1/$top"
prefix="$work/prefix"

# --- fresh profile install
case "$(uname -s)" in Darwin) data="$HOME/Library/Application Support/xtrace" ;; *) data="$HOME/.local/share/xtrace" ;; esac
[ ! -e "$data" ] || fail "fresh profile has user data"
"$v1/install.sh" --prefix "$prefix" >"$work/i1.log" 2>&1 || { cat "$work/i1.log"; fail "fresh install"; }
[ -x "$prefix/bin/xtrace" ] && ok "fresh install created bin/xtrace" || fail "fresh install created bin/xtrace"
[ ! -e "$data" ] && ok "installer did not create the user data dir" || fail "installer did not create the user data dir"
"$prefix/bin/xtrace" --version | grep -q xtrace && ok "xtrace --version runs" || fail "xtrace --version runs"
[ "$("$prefix/bin/xtrace" --version | head -n 1)" = "xtrace $(cat "$v1/share/xtrace/VERSION")" ] && ok "xtrace --version equals the package version" || fail "xtrace --version equals the package version"
"$prefix/current/install.sh" verify --prefix "$prefix" >/dev/null && ok "installed payload verifies" || fail "installed payload verifies"
[ -d "$prefix/current/share/xtrace/packs/java/agent" ] && [ -f "$prefix/current/share/xtrace/packs/node/pack.manifest" ] && ok "java and node packs present" || fail "java and node packs present"

# --- lifecycle on the installed binary: init, record, stop (the daemon is stopped before any upgrade)
repo="$work/repo"; mkdir -p "$repo"
"$prefix/bin/xtrace" init --project-dir "$repo" >"$work/init.json" 2>&1 || { cat "$work/init.json"; fail "xtrace init"; }
ok "init created a project in the fresh profile"
"$prefix/bin/xtrace" record --project-dir "$repo" >"$work/rec.json" 2>&1 || { cat "$work/rec.json"; fail "xtrace record"; }
grep -q '"kind": "record_started"' "$work/rec.json" && ok "record started a detached daemon" || fail "record started a detached daemon"
"$prefix/bin/xtrace" stop --project-dir "$repo" >"$work/stop.json" 2>&1 || { cat "$work/stop.json"; fail "xtrace stop"; }
grep -q '"kind": "stopped"' "$work/stop.json" && ok "stop stopped the recorded daemon" || fail "stop stopped the recorded daemon"

# --- user data + upgrade to a synthesized newer version
mkdir -p "$data/projects/p1"; echo "recording-bytes" > "$data/projects/p1/metadata.sqlite3"; echo r1 > "$data/projects/p1/rec-1.xtf"
cp -R "$v1" "$work/v2"
echo 0.0.2 > "$work/v2/share/xtrace/VERSION"
(cd "$work/v2" && find . -type f ! -path ./share/xtrace/payload.sha256 ! -path ./share/xtrace/PACKAGE-MANIFEST.json | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sums "$f"; done > share/xtrace/payload.sha256)
"$work/v2/install.sh" --prefix "$prefix" >"$work/i2.log" 2>&1 || { cat "$work/i2.log"; fail "upgrade"; }
[ "$(cat "$prefix/current/share/xtrace/VERSION")" = 0.0.2 ] && ok "upgrade activated 0.0.2" || fail "upgrade activated 0.0.2"
[ "$(cat "$data/projects/p1/metadata.sqlite3")" = recording-bytes ] && [ -f "$data/projects/p1/rec-1.xtf" ] && ok "upgrade preserved user data in place" || fail "upgrade preserved user data in place"
"$prefix/bin/xtrace" recording list --project-dir "$repo" >"$work/list.json" 2>&1 || { cat "$work/list.json"; fail "store unreadable after upgrade"; }
grep -q '"recordings"' "$work/list.json" && ok "upgraded install opens the existing store" || fail "upgraded install opens the existing store"
"$prefix/bin/xtrace" restart --project-dir "$repo" >"$work/restart.json" 2>&1 || { cat "$work/restart.json"; fail "restart after upgrade"; }
grep -q '"kind": "restarted"' "$work/restart.json" && ok "restart works on the upgraded install" || fail "restart works on the upgraded install"
"$prefix/bin/xtrace" stop --project-dir "$repo" >/dev/null 2>&1 && ok "daemon stopped before uninstall" || fail "daemon stopped before uninstall"
b=$(ls -d "$prefix"/backups/*-pre-0.0.2 2>/dev/null | head -n 1); [ -n "$b" ] && [ "$(cat "$b/data/projects/p1/rec-1.xtf")" = r1 ] && ok "pre-upgrade data backup taken" || fail "pre-upgrade data backup taken"
[ -d "$prefix/versions/0.0.1" ] && ok "previous version kept for rollback" || fail "previous version kept for rollback"

# --- downgrade refused; corrupt payload refused
if "$v1/install.sh" --prefix "$prefix" >/dev/null 2>&1; then fail "downgrade was not refused"; else ok "downgrade refused without --allow-downgrade"; fi
cp -R "$v1" "$work/bad"; echo tamper >> "$work/bad/bin/xtrace"
if "$work/bad/install.sh" --prefix "$work/prefix2" >/dev/null 2>&1; then fail "tampered payload installed"; else ok "tampered payload refused"; fi
[ ! -e "$work/prefix2/current" ] && ok "refused install left no partial prefix state" || fail "refused install left no partial prefix state"
echo tamper >> "$prefix/current/bin/xtrace"
if "$prefix/current/install.sh" verify --prefix "$prefix" >/dev/null 2>&1; then fail "verify missed tampering"; else ok "verify detects modified installed file"; fi

# --- prefix inside data dir refused
if "$v1/install.sh" --prefix "$data/inner" >/dev/null 2>&1; then fail "prefix inside data dir accepted"; else ok "prefix inside user data dir refused"; fi

# --- uninstall leaves data and backups
"$prefix/current/uninstall.sh" --prefix "$prefix" >"$work/u.log" 2>&1 || { cat "$work/u.log"; fail "uninstall"; }
[ ! -e "$prefix/bin/xtrace" ] && [ ! -e "$prefix/versions" ] && ok "uninstall removed program files" || fail "uninstall removed program files"
[ "$(cat "$data/projects/p1/rec-1.xtf")" = r1 ] && ok "uninstall left user data untouched" || fail "uninstall left user data untouched"
[ -d "$prefix/backups" ] && ok "uninstall kept backups" || fail "uninstall kept backups"
EXPECTED=25
[ "$pass" -eq "$EXPECTED" ] || fail "expected $EXPECTED checks, ran $pass"
echo "all $pass checks passed"
