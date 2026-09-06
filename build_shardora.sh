#!/bin/bash
set -e
cd /root/shardora

echo "=== Wiping stale CMakeCache ==="
rm -f cbuild_Release/CMakeCache.txt

echo "=== Building shardora Release ==="
bash build.sh shardora Release 2>&1
echo "=== Binary ==="
ls -lh cbuild_Release/shardora
echo BUILD_DONE
