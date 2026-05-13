#!/usr/bin/env bash
# Build linux/arm64 seth + txcli inside Docker (Mac-friendly). Mounts repo at /root/seth.
# Usage: from repo root — bash docker/arm64/build_linux_arm64.sh [Debug|Release]
set -euo pipefail

TARGET="${1:-Release}"
if [[ "$TARGET" != "Debug" && "$TARGET" != "Release" ]]; then
  echo "Usage: $0 [Debug|Release]"
  exit 1
fi

SETH_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$SETH_ROOT"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running or not installed."
  exit 1
fi

echo "Building in container: platform=linux/arm64, TARGET=$TARGET"

docker run --rm --platform linux/arm64 \
  -e "TARGET=${TARGET}" \
  -v "${SETH_ROOT}:/root/seth" \
  -w /root/seth \
  ubuntu:22.04 \
  bash -lc "set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config git curl ca-certificates xxd python3 \
      libssl-dev zlib1g-dev liblz4-dev libzstd-dev \
      libgmp-dev flex bison
    cd /root/seth
    bash build.sh seth \"\${TARGET}\"
    cd \"/root/seth/cbuild_\${TARGET}\"
    make -j\"\$(nproc)\" txcli
    echo OK: /root/seth/cbuild_\${TARGET}/seth
  "

echo "Done. Binaries: ${SETH_ROOT}/cbuild_${TARGET}/seth , txcli"
