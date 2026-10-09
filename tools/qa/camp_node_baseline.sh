#!/bin/sh
# Pinned UNINSTRUMENTED Node campaign baseline on an x86_64 runner (Docker, XCAMP_PLATFORM=linux/amd64).
#   camp_node_baseline.sh <directus|medusa|vendure>
# Needs XTRACE_CAMP_NODE_ROOT (private root) and, for directus, the pinned upstream already cloned to
# $XTRACE_CAMP_NODE_ROOT/<project>/src (camp_clone.sh). Any failure exits non-zero; nothing is skipped.
set -eu
P="${1:?project}"
: "${XTRACE_CAMP_NODE_ROOT:?}"
export XCAMP_PLATFORM="${XCAMP_PLATFORM:-linux/amd64}"
root="$XTRACE_CAMP_NODE_ROOT/$P"
mkdir -p "$root"
nv=$(python3 -B -c "import json,sys;print(json.load(open('campaigns/node/$P/campaign.json'))['runtime']['nodeImageVersion'])")
docker build --platform "$XCAMP_PLATFORM" --build-arg NODE_VERSION="$nv" -t "xtrace-camp-node:$nv" campaigns/node/lib/docker
run="campaigns/node/$P/harness/run.mjs"
# Containers run as root and leave root-owned files in the bind-mounted workspace; the host harness must read and patch them.
own() { sudo chown -R "$(id -u):$(id -g)" "$root" 2>/dev/null || true; }
case "$P" in
  directus)
    [ -d "$root/upstream" ] || mv "$root/src" "$root/upstream"
    node "$run" prepare; own
    ;;
  medusa)
    url=$(python3 -B -c "import json;print(json.load(open('campaigns/node/medusa/campaign.json'))['starter']['canonicalUrl'])")
    sha=$(python3 -B -c "import json;print(json.load(open('campaigns/node/medusa/campaign.json'))['starter']['sha'])")
    [ -d "$root/starter" ] || sh tools/qa/camp_clone.sh "$url" "$sha" "$root/starter"
    node "$run" prepare; own
    ;;
  vendure)
    node "$run" create; own
    # The seed step reads the create package's assets (initial-data.json, products.csv, images): take them from the pinned,
    # hash-verified npm tarball, exactly the artifact campaign.json pins.
    ver=$(python3 -B -c "import json;print(json.load(open('campaigns/node/vendure/campaign.json'))['starter']['package']['version'])")
    want=$(python3 -B -c "import json;print(json.load(open('campaigns/node/vendure/campaign.json'))['starter']['package']['tarballSha256'])")
    tmp=$(mktemp -d)
    (cd "$tmp" && npm pack "@vendure/create@$ver" --silent >/dev/null)
    got=$(sha256sum "$tmp"/vendure-create-*.tgz | cut -d' ' -f1)
    [ "$got" = "$want" ] || { echo "vendure create tarball sha256 does not match the pin"; exit 1; }
    mkdir -p "$tmp/x" && tar -xzf "$tmp"/vendure-create-*.tgz -C "$tmp/x"
    rm -rf "$root/create-assets" && cp -R "$tmp/x/package/assets" "$root/create-assets"
    node "$run" build; own
    node "$run" seed; own
    ;;
  *) echo "unknown node project"; exit 2 ;;
esac
node "$run" baseline 1
own
