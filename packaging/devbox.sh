#!/usr/bin/env bash
# DEV-FEEDBACK ONLY (never acceptance evidence): run a command in the ephemeral xtrace-dev:1 Docker image
# (linux/arm64). Only volumes prefixed xtrace-pkg- are used. The worktree is mounted read-only and copied inside;
# OUT_DIR (host) is mounted at /out for results.
#   packaging/devbox.sh <worktree> <out-dir> <command...>      e.g. python3 packaging/build.py --out /out/dist ...
set -euo pipefail
WT=$(cd "$1" && pwd); OUT=$(mkdir -p "$2" && cd "$2" && pwd); shift 2
[ $# -ge 1 ] || { echo "usage: $0 <worktree> <out-dir> <command...>" >&2; exit 2; }
# Fresh named volumes are root-owned; hand them to the non-root dev user (uid 1000) once.
docker run --rm -u root -v xtrace-pkg-cargo:/v/cargo -v xtrace-pkg-gradle:/v/gradle -v xtrace-pkg-npm:/v/npm \
  -v xtrace-pkg-scratch:/v/scratch xtrace-dev:1 chown 1000:1000 /v/cargo /v/gradle /v/npm /v/scratch
exec docker run --rm --init --cpus 4 --platform linux/arm64 \
  -v "$WT":/src:ro -v "$OUT":/out \
  -v xtrace-pkg-cargo:/usr/local/cargo/registry \
  -v xtrace-pkg-gradle:/cache/gradle \
  -v xtrace-pkg-npm:/cache/npm \
  -v xtrace-pkg-scratch:/scratch \
  -e GRADLE_USER_HOME=/cache/gradle -e NPM_CONFIG_CACHE=/cache/npm -e CARGO_TERM_COLOR=never \
  xtrace-dev:1 bash -c '
    set -e
    rm -rf /scratch/tree && mkdir -p /scratch/tree
    rsync -a --exclude .git --exclude target/ --exclude node_modules/ --exclude build/ --exclude .gradle/ /src/ /scratch/tree/
    cd /scratch/tree
    '"$*"
