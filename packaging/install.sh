#!/bin/sh
# X-trace installer. Run from the extracted release directory (xtrace-<version>-<platform>/).
#
#   ./install.sh [install] [--prefix DIR] [--data-home DIR] [--no-backup] [--allow-downgrade]
#   ./install.sh verify [--prefix DIR]        re-check the installed payload against payload.sha256
#   ./install.sh verify-dist DIR              re-check DIR/SHA256SUMS (release files next to the archive)
#
# Layout:  <prefix>/versions/<ver>/...   <prefix>/current -> versions/<ver>   <prefix>/bin/xtrace -> ../current/bin/xtrace
# User data (recordings, project stores) lives outside the prefix and is NEVER created, modified or deleted
# by this script. An upgrade copies the data directory to <prefix>/backups/ BEFORE the new version is activated.
set -eu

die() { echo "install.sh: error: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

here=$(cd "$(dirname "$0")" && pwd)

sha_check() { # sha_check <rows-file> <base-dir>
  if command -v sha256sum >/dev/null 2>&1; then (cd "$2" && sha256sum -c "$1" >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then (cd "$2" && shasum -a 256 -c "$1" >/dev/null)
  else die "need sha256sum or shasum"; fi
}

default_data_home() {
  if [ -n "${XTRACE_DATA_HOME:-}" ]; then echo "$XTRACE_DATA_HOME"; return; fi
  case "$(uname -s)" in
    Darwin) echo "$HOME/Library/Application Support/xtrace" ;;
    *) echo "${XDG_DATA_HOME:-$HOME/.local/share}/xtrace" ;;
  esac
}

cmd=install
case "${1:-}" in install|verify|verify-dist) cmd=$1; shift ;; esac

prefix=${XTRACE_PREFIX:-$HOME/.local/xtrace}
data_home=$(default_data_home)
backup=1
downgrade=0
dist_dir=
if [ "$cmd" = verify-dist ]; then dist_dir=${1:-}; [ -n "$dist_dir" ] || die "verify-dist needs a directory"; shift; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; prefix=$2; shift 2 ;;
    --data-home) [ $# -ge 2 ] || die "--data-home needs a value"; data_home=$2; shift 2 ;;
    --no-backup) backup=0; shift ;;
    --allow-downgrade) downgrade=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
case "$prefix" in /*) ;; *) die "--prefix must be an absolute path" ;; esac
case "$prefix$data_home" in *\"*|*\\*) die "paths containing quotes or backslashes are not supported" ;; esac

if [ "$cmd" = verify-dist ]; then
  [ -f "$dist_dir/SHA256SUMS" ] || die "no SHA256SUMS in $dist_dir"
  sha_check SHA256SUMS "$dist_dir" || die "SHA256SUMS verification FAILED"
  say "SHA256SUMS verified in $dist_dir"
  [ -f "$dist_dir/SHA256SUMS.sig" ] && say "a detached signature is present; verify it with openssl/your trust root (not done here)"
  exit 0
fi

if [ "$cmd" = verify ]; then
  cur="$prefix/current"
  [ -d "$cur/share/xtrace" ] || die "no installation at $prefix"
  sha_check share/xtrace/payload.sha256 "$cur" || die "installed payload does not match payload.sha256 (corrupt or modified)"
  say "installed payload verified ($(cat "$cur/share/xtrace/VERSION"))"
  exit 0
fi

# ---- install / upgrade ----
[ -f "$here/share/xtrace/payload.sha256" ] || die "run this script from the extracted release directory"
version=$(cat "$here/share/xtrace/VERSION")
case "$version" in *[!0-9A-Za-z.+-]*|"") die "invalid version string" ;; esac

# The prefix and the data home must be disjoint so removing/replacing one can never touch the other.
case "$prefix/" in "$data_home"/*) die "--prefix is inside the user data directory ($data_home)" ;; esac
case "$data_home/" in "$prefix"/*) die "the user data directory is inside --prefix ($prefix)" ;; esac

say "verifying payload integrity"
sha_check share/xtrace/payload.sha256 "$here" || die "payload does not match payload.sha256; refusing to install"
grep -q '"packTrust": "unsigned"' "$here/share/xtrace/PACKAGE-MANIFEST.json" &&
  say "NOTICE: this package is UNSIGNED (no release signature/notarization); do not treat it as a release"

prev=
if [ -L "$prefix/current" ]; then prev=$(basename "$(readlink "$prefix/current")"); fi
if [ -n "$prev" ] && [ "$prev" != "$version" ] && [ "$downgrade" = 0 ]; then
  newest=$(printf '%s\n%s\n' "$prev" "$version" | sort -V | tail -n 1)
  [ "$newest" = "$version" ] || die "installed $prev is newer than $version (use --allow-downgrade)"
fi

mkdir -p "$prefix/versions" "$prefix/bin"
target="$prefix/versions/$version"
staging="$prefix/versions/.incoming-$$"
trap 'rm -rf "$staging"' EXIT INT TERM
rm -rf "$staging"; mkdir "$staging"
(cd "$here" && tar -cf - bin share install.sh uninstall.sh) | (cd "$staging" && tar -xf -)
sha_check share/xtrace/payload.sha256 "$staging" || die "staged copy failed verification"

# Back up existing user data before anything that could migrate it becomes active.
backup_dir=
if [ -n "$prev" ] && [ -d "$data_home" ] && [ "$backup" = 1 ]; then
  backup_dir="$prefix/backups/$(date -u +%Y%m%dT%H%M%SZ)-pre-$version"
  say "backing up user data ($data_home) to $backup_dir"
  mkdir -p "$backup_dir"
  if ! { cp -Rpc "$data_home" "$backup_dir/data" 2>/dev/null || cp -Rp "$data_home" "$backup_dir/data"; }; then
    rm -rf "$backup_dir"
    die "backup failed; nothing was changed (free space or use --no-backup deliberately)"
  fi
elif [ -d "$data_home" ] && [ "$backup" = 0 ]; then
  say "WARNING: --no-backup given; existing data is not backed up"
fi

if [ -d "$target" ]; then rm -rf "$target.old"; mv "$target" "$target.old"; fi
mv "$staging" "$target"
rm -rf "$target.old"
ln -sfn "versions/$version" "$prefix/current.new"
if [ "$(uname -s)" = Darwin ]; then mv -fh "$prefix/current.new" "$prefix/current"; else mv -fT "$prefix/current.new" "$prefix/current"; fi
ln -sfn ../current/bin/xtrace "$prefix/bin/xtrace.new"
if [ "$(uname -s)" = Darwin ]; then mv -fh "$prefix/bin/xtrace.new" "$prefix/bin/xtrace"; else mv -fT "$prefix/bin/xtrace.new" "$prefix/bin/xtrace"; fi

# Keep exactly one previous version for rollback.
for d in "$prefix"/versions/*; do
  [ -d "$d" ] || continue
  b=$(basename "$d")
  [ "$b" = "$version" ] || [ "$b" = "$prev" ] || rm -rf "$d"
done

{
  printf '{\n  "version": "%s",\n  "previousVersion": "%s",\n  "dataHome": "%s",\n  "backup": "%s"\n}\n' \
    "$version" "$prev" "$data_home" "$backup_dir"
} > "$prefix/install-receipt.json"

"$prefix/bin/xtrace" --version >/dev/null 2>&1 || die "installed binary failed to run"
say "installed X-trace $version into $prefix"
[ -n "$prev" ] && say "upgraded from $prev; user data was left in place ($data_home)"
[ -n "$backup_dir" ] && say "pre-upgrade data backup: $backup_dir"
case ":$PATH:" in *":$prefix/bin:"*) ;; *)
  echo "Add X-trace to your PATH (this script does not edit shell profiles):"
  echo "  export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
