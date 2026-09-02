#!/bin/bash
set -e
cd /root/seth

echo "=== Wiping stale CMakeCache ==="
rm -f cbuild_Release/CMakeCache.txt

echo "=== Building seth Release ==="
bash build.sh seth Release 2>&1
echo "=== Binary ==="
ls -lh cbuild_Release/seth
echo BUILD_DONE
