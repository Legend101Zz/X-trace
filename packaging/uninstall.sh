#!/bin/sh
# Remove an X-trace installation. NEVER touches the user data directory (recordings, project stores)
# and never deletes backups; it prints where they are so you can decide.
#   ./uninstall.sh [--prefix DIR]
set -eu
die() { echo "uninstall.sh: error: $*" >&2; exit 1; }
prefix=${XTRACE_PREFIX:-$HOME/.local/xtrace}
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; prefix=$2; shift 2 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
case "$prefix" in /*) ;; *) die "--prefix must be an absolute path" ;; esac
[ -f "$prefix/install-receipt.json" ] || die "$prefix is not an X-trace installation (no install-receipt.json)"
data_home=$(sed -n 's/^  "dataHome": "\(.*\)",$/\1/p' "$prefix/install-receipt.json")
[ -n "$data_home" ] || die "install receipt has no dataHome; refusing to guess"
case "$prefix/" in "$data_home"/*) die "refusing: prefix lies inside the user data directory" ;; esac
rm -f "$prefix/bin/xtrace" "$prefix/current" "$prefix/current.new" "$prefix/install-receipt.json"
rm -rf "$prefix/versions"
rmdir "$prefix/bin" 2>/dev/null || true
rmdir "$prefix" 2>/dev/null || true
echo "uninstall.sh: removed X-trace program files from $prefix"
echo "uninstall.sh: user data was NOT touched: $data_home"
[ -d "$prefix/backups" ] && echo "uninstall.sh: upgrade backups kept in $prefix/backups"
exit 0
