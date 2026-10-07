#!/bin/sh
# macOS Developer ID codesigning (hardened runtime) + notarization for a built X-trace archive.
#
#   sign-macos.sh --check   --identity "Developer ID Application: ..." --notary-profile PROFILE
#   sign-macos.sh --archive dist/macos-arm64/xtrace-0.0.1-macos-arm64.tar.gz --out-dir signed/
#                 --identity "Developer ID Application: ..." --notary-profile PROFILE
#
# Requires, all owner-provided and never fabricated here: a valid Developer ID Application identity in the
# keychain and a notarytool keychain profile (`xcrun notarytool store-credentials`). With neither, this script
# exits 3 and does nothing. Signs bin/xtrace, notarizes a zip of the payload, assesses with spctl, then repacks a
# deterministic archive marked packTrust=signed-macos-developer-id and refreshes SHA256SUMS.
# Stapling: a bare Mach-O binary/zip cannot be stapled; Gatekeeper checks the notarization ticket online.
set -eu
die() { echo "sign-macos.sh: error: $1" >&2; exit "${2:-2}"; }
here=$(cd "$(dirname "$0")" && pwd)
identity=${XTRACE_MACOS_IDENTITY:-} profile=${XTRACE_NOTARY_PROFILE:-} archive= outdir= check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --identity) [ $# -ge 2 ] || die "--identity needs a value"; identity=$2; shift 2 ;;
    --notary-profile) [ $# -ge 2 ] || die "--notary-profile needs a value"; profile=$2; shift 2 ;;
    --archive) [ $# -ge 2 ] || die "--archive needs a value"; archive=$2; shift 2 ;;
    --out-dir) [ $# -ge 2 ] || die "--out-dir needs a value"; outdir=$2; shift 2 ;;
    --check) check=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(uname -s)" = Darwin ] || die "macOS signing requires a macOS host (found $(uname -s))" 3
[ -n "$identity" ] || die "no signing identity: pass --identity or set XTRACE_MACOS_IDENTITY (owner-provided Developer ID Application identity required; none is invented)" 3
[ -n "$profile" ] || die "no notarytool profile: pass --notary-profile or set XTRACE_NOTARY_PROFILE (owner-provided keychain profile required)" 3
security find-identity -v -p codesigning 2>/dev/null | grep -F -- "$identity" | grep -q 'Developer ID Application' ||
  die "identity '$identity' is not a valid Developer ID Application codesigning identity in the keychain ($(security find-identity -v -p codesigning 2>/dev/null | tail -n 1))" 3
xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 ||
  die "notarytool keychain profile '$profile' is missing or unusable" 3
[ "$check" = 1 ] && { echo "sign-macos.sh: prerequisites present (identity + notary profile)"; exit 0; }
[ -f "$archive" ] || die "--archive is required and must exist"
[ -n "$outdir" ] || die "--out-dir is required"
case "$archive" in *macos-arm64*) ;; *) die "refusing to sign a non-macos-arm64 archive" 3 ;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
top=$(ls "$work")
codesign --force --options runtime --timestamp --sign "$identity" "$work/$top/bin/xtrace"
codesign --verify --strict --verbose=2 "$work/$top/bin/xtrace"
ditto -c -k --keepParent "$work/$top" "$work/notarize.zip"
xcrun notarytool submit "$work/notarize.zip" --keychain-profile "$profile" --wait --output-format json > "$work/notary.json"
status=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("status",""), d.get("id",""))' "$work/notary.json")
case "$status" in "Accepted "*) ;; *) die "notarization not accepted: $status (see: xcrun notarytool log)" 3 ;; esac
spctl --assess --type execute -vv "$work/$top/bin/xtrace" || die "Gatekeeper assessment failed after notarization" 3
python3 "$here/repack.py" --dir "$work/$top" --out-dir "$outdir" --src-dist "$(dirname "$archive")" \
  --pack-trust signed-macos-developer-id --notarization-id "${status#Accepted }"
echo "sign-macos.sh: signed + notarized archive written to $outdir"
