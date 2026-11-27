#!/bin/sh
# Fetch one upstream commit by SHA (shallow) into DEST and verify HEAD equals the pin.
# usage: camp_clone.sh <https-url> <40-hex-sha> <dest> [stable-tag]
set -eu
url="$1"; sha="$2"; dest="$3"; tag="${4:-}"
case "$url" in https://github.com/*) ;; *) echo "refusing non-github url"; exit 2 ;; esac
printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$' || { echo "bad sha"; exit 2; }
if [ -n "$tag" ]; then
  printf '%s' "$tag" | grep -Eq '^[A-Za-z0-9._-]+$' || { echo "bad tag"; exit 2; }
fi
mkdir -p "$dest"
git -C "$dest" init -q
git -C "$dest" remote add origin "$url"
git -C "$dest" fetch -q --depth 1 origin "$sha"
git -C "$dest" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
head=$(git -C "$dest" rev-parse HEAD)
[ "$head" = "$sha" ] || { echo "checkout HEAD does not equal pin"; exit 1; }
if [ -n "$tag" ]; then
  git -C "$dest" fetch -q --no-tags --depth 1 origin "refs/tags/${tag}:refs/tags/${tag}"
  peeled=$(git -C "$dest" rev-parse "refs/tags/${tag}^{commit}")
  [ "$peeled" = "$sha" ] || { echo "tag does not peel to pin"; exit 1; }
fi
echo "upstream checkout at pin ${sha}"
