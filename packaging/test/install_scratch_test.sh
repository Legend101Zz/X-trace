#!/bin/sh
# Guard tests for install_test.sh scratch handling (SEC-02): a failing mktemp or a bad scratch root must abort
# non-zero and must never delete the directory the script was started from.
#   packaging/test/install_scratch_test.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd -P)
t=$(mktemp -d "${TMPDIR:-/tmp}/xt-guard.XXXXXX") || { echo 'mktemp failed' >&2; exit 1; }
t=$(cd "$t" && pwd -P)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/cwd" "$t/dist" "$t/shim"
: > "$t/cwd/sentinel"
: > "$t/dist/xtrace-0.0.0.tar.gz"
fails=0
check() { if [ "$1" = ok ]; then echo "ok - $2"; else echo "FAIL - $2" >&2; fails=$((fails+1)); fi; }

# 1. mktemp that fails (exit 1, prints nothing) must abort with status != 0 and leave cwd intact.
printf '#!/bin/sh\nexit 1\n' > "$t/shim/mktemp"; chmod 755 "$t/shim/mktemp"
if (cd "$t/cwd" && PATH="$t/shim:$PATH" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err1"); then r=bad; else r=ok; fi
[ -f "$t/cwd/sentinel" ] || r=bad
grep -q 'mktemp failed' "$t/err1" || r=bad
check "$r" "failing mktemp aborts and keeps the starting directory"

# 2. nonexistent scratch root aborts, nothing deleted.
if (cd "$t/cwd" && XTRACE_TEST_PRIVATE_SCRATCH="$t/nope" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err2"); then r=bad; else r=ok; fi
[ -f "$t/cwd/sentinel" ] || r=bad
grep -q 'is not a directory' "$t/err2" || r=bad
check "$r" "missing scratch root aborts with the not-a-directory message"

# 3. mktemp that returns the current directory (simulated worst case) is refused as unsafe and not deleted.
printf '#!/bin/sh\npwd\n' > "$t/shim/mktemp"
if (cd "$t/cwd" && PATH="$t/shim:$PATH" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err3"); then r=bad; else r=ok; fi
[ -f "$t/cwd/sentinel" ] || r=bad
grep -q 'unsafe work dir' "$t/err3" || r=bad
check "$r" "mktemp returning the cwd is refused and the cwd survives"

# 4. a 0700 XTRACE_TEST_PRIVATE_SCRATCH root is honoured (mktemp asked for <root>/xt.XXXXXX) and left empty after exit.
real_mktemp=$(command -v mktemp)
printf '#!/bin/sh\necho "$*" >> "%s/mktemp.log"\nexec "%s" "$@"\n' "$t" "$real_mktemp" > "$t/shim/mktemp"; chmod 755 "$t/shim/mktemp"
mkdir -m 700 "$t/root"
(cd "$t/cwd" && PATH="$t/shim:$PATH" XTRACE_TEST_PRIVATE_SCRATCH="$t/root" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>&1) || :
r=ok
grep -q -- "-d $t/root/xt.XXXXXX" "$t/mktemp.log" || r=bad
[ -z "$(ls -A "$t/root")" ] || r=bad
check "$r" "private scratch root is used and emptied on exit"

# 5. a mktemp that returns a pre-existing non-empty foreign dir is refused and its contents survive.
mkdir "$t/foreign"; echo keep > "$t/foreign/file"
printf '#!/bin/sh\necho "%s/foreign"\n' "$t" > "$t/shim/mktemp"
if (cd "$t/cwd" && PATH="$t/shim:$PATH" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err5"); then r=bad; else r=ok; fi
[ -f "$t/foreign/file" ] || r=bad
grep -q 'not empty' "$t/err5" || r=bad
check "$r" "foreign non-empty work dir is refused and survives"

# 6. cwd reached through a symlink, mktemp returning its physical path: refused, directory survives.
ln -s "$t/cwd" "$t/link"
printf '#!/bin/sh\ncd "%s" && pwd -P\n' "$t/cwd" > "$t/shim/mktemp"
if (cd "$t/link" && PATH="$t/shim:$PATH" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err6"); then r=bad; else r=ok; fi
[ -f "$t/cwd/sentinel" ] || r=bad
check "$r" "physical cwd via symlink is refused and survives"

# 7. a world-writable scratch root is refused with a pointer to XTRACE_TEST_PRIVATE_SCRATCH.
mkdir "$t/open"; chmod 777 "$t/open"
if (cd "$t/cwd" && XTRACE_TEST_PRIVATE_SCRATCH="$t/open" sh "$here/install_test.sh" "$t/dist" >/dev/null 2>"$t/err7"); then r=bad; else r=ok; fi
grep -q 'XTRACE_TEST_PRIVATE_SCRATCH' "$t/err7" || r=bad
check "$r" "world-writable scratch root is refused"

[ "$fails" -eq 0 ] || exit 1
echo "all install scratch guard checks passed"
