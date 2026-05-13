#!/usr/bin/env bash
# Same directory as simple_remote.sh — run Seth inside the current environment
# (e.g. Ubuntu in a Docker container) without invoking Docker.
#
# Argument mapping matches simple_remote_docker.sh (see that file).
# Env SETH_PKG_DIR, SETH_STAGING, USE_PKG_TAR, etc. pass through (see docker/arm64/README.md).
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
IPS="${2:-host.docker.internal}"
PUB="${IPS%%,*}"

if [ -n "${5:-}" ]; then
  TARGET="$5"
elif [ "${4:-}" = "Debug" ] || [ "${4:-}" = "Release" ]; then
  TARGET="$4"
else
  TARGET=Release
fi
FIRST="${6:-$1}"

exec bash "$ROOT/docker/arm64/simple_remote_in_container.sh" \
  "${1:?each_nodes_count}" \
  "$PUB" \
  "${3:-3}" \
  "$TARGET" \
  "$FIRST"
