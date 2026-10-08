#!/bin/sh
# Ed25519 detached signature over SHA256SUMS using OpenSSL 3 (same primitive tools/release/check_ledger.py verifies:
# `openssl pkeyutl -verify -pubin -inkey PUB -sigfile SIG -rawin -in SHA256SUMS`).
#
#   sign-detached.sh --key PRIVATE.pem --sums SHA256SUMS [--out SHA256SUMS.sig]       release-mode signing
#   sign-detached.sh --non-release --key TEST.pem --sums SHA256SUMS                  test key, output marked non-release
#   sign-detached.sh --non-release --generate-test-key OUT.pem                       create a throwaway test key
#
# This script never creates or guesses release authority: in release mode the key must be supplied by the owner,
# be an Ed25519 private key, and not be group/other accessible. Exit codes: 2 usage, 3 missing authority/tooling.
set -eu
die() { echo "sign-detached.sh: error: $1" >&2; exit "${2:-2}"; }
OPENSSL=${OPENSSL:-openssl}
key= sums= out= nonrelease=0 gen=
while [ $# -gt 0 ]; do
  case "$1" in
    --key) [ $# -ge 2 ] || die "--key needs a value"; key=$2; shift 2 ;;
    --sums) [ $# -ge 2 ] || die "--sums needs a value"; sums=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --non-release) nonrelease=1; shift ;;
    --generate-test-key) [ $# -ge 2 ] || die "--generate-test-key needs a path"; gen=$2; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found (set OPENSSL=/path/to/openssl3)" 3
case "$("$OPENSSL" version)" in "OpenSSL 3"*) ;; *) die "OpenSSL 3 required for Ed25519 -rawin (found: $("$OPENSSL" version)); macOS LibreSSL will not work, set OPENSSL" 3 ;; esac

if [ -n "$gen" ]; then
  [ "$nonrelease" = 1 ] || die "--generate-test-key is only allowed with --non-release; release keys come from the owner" 3
  [ ! -e "$gen" ] || die "$gen exists; refusing to overwrite"
  (umask 077 && "$OPENSSL" genpkey -algorithm ed25519 -out "$gen")
  "$OPENSSL" pkey -in "$gen" -pubout -out "${gen%.pem}.pub.pem"
  echo "throwaway test key; release-mode signing refuses it" > "$gen.NON-RELEASE-TEST-KEY"
  echo "sign-detached.sh: wrote NON-RELEASE test key $gen and ${gen%.pem}.pub.pem"
  exit 0
fi

[ -n "$key" ] || die "--key is required (an owner-provided Ed25519 private key); none is generated or assumed" 3
[ -n "$sums" ] || die "--sums is required"
[ -f "$key" ] || die "key file not found: $key" 3
[ -f "$sums" ] || die "sums file not found: $sums"
"$OPENSSL" pkey -in "$key" -noout -text 2>/dev/null | head -n 1 | grep -qi 'ED25519' || die "$key is not an Ed25519 private key" 3
mode=$(stat -f '%Lp' "$key" 2>/dev/null || stat -c '%a' "$key")
case "$mode" in 400|600) ;; *) die "private key mode is $mode; must be 0600 or 0400 (not group/other accessible)" 3 ;; esac

if [ "$nonrelease" = 0 ] && [ -e "$key.NON-RELEASE-TEST-KEY" ]; then
  die "$key is a generated test key (marker present); use --non-release" 3
fi
if [ "$nonrelease" = 1 ]; then
  out=${out:-$sums.nonrelease.sig}
else
  out=${out:-$sums.sig}
fi
"$OPENSSL" pkeyutl -sign -inkey "$key" -rawin -in "$sums" -out "$out"
pub=$(mktemp)
trap 'rm -f "$pub"' EXIT
"$OPENSSL" pkey -in "$key" -pubout -out "$pub"
"$OPENSSL" pkeyutl -verify -pubin -inkey "$pub" -sigfile "$out" -rawin -in "$sums" >/dev/null || die "self-verification failed" 3
if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum "$sums" | cut -d' ' -f1); else h=$(shasum -a 256 "$sums" | cut -d' ' -f1); fi
if [ "$nonrelease" = 1 ]; then rel=false; else rel=true; fi
printf '{\n  "algorithm": "Ed25519",\n  "message": "%s",\n  "messageSha256": "%s",\n  "signature": "%s",\n  "nonRelease": %s\n}\n' \
  "$(basename "$sums")" "$h" "$(basename "$out")" "$([ "$rel" = true ] && echo false || echo true)" > "$out.json"
if [ "$nonrelease" = 1 ]; then
  echo "sign-detached.sh: NON-RELEASE signature written to $out (test key; not release evidence)"
else
  echo "sign-detached.sh: signature written to $out (verify with the owner's trusted public key)"
fi
