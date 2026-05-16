#!/usr/bin/env bash
# Rebuild libuSockets.a without LTO (fixes "LTO version 15.1 instead of 13.1" at link time).
set -euo pipefail
SETH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SETH_ROOT/third_party/uWebSockets"
git submodule update --init --recursive 2>/dev/null || true
cd uSockets
make clean || true
WITH_OPENSSL=1 make -j"$(nproc)" CFLAGS="-O3 -fPIC -fno-lto" CXXFLAGS="-fno-lto" LDFLAGS="-fno-lto"
mkdir -p "$SETH_ROOT/third_party/lib"
cp -f uSockets.a "$SETH_ROOT/third_party/lib/libuSockets.a"
echo "OK: $SETH_ROOT/third_party/lib/libuSockets.a (no LTO)"
echo "Reconfigure seth build without LTO, e.g.:"
echo "  cd cbuild_Release && cmake .. -DSETH_ENABLE_LTO=OFF && make -j\$(nproc) seth"
