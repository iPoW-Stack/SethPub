#!/bin/bash

# Manual installation script for uWebSockets and uSockets
# Run this from the project root directory

set -e  # Exit on error

SRC_PATH=$(pwd)
echo "Installing uWebSockets and uSockets to: $SRC_PATH/third_party"

# Create directories
mkdir -p third_party/include
mkdir -p third_party/lib

# Install uSockets
echo "=== Installing uSockets ==="
if [ ! -d "third_party/uSockets" ]; then
    cd third_party
    git clone https://github.com/uNetworking/uSockets.git
    cd uSockets
    git checkout v0.8.8
else
    cd third_party/uSockets
    git checkout v0.8.8
fi

# Clean and build uSockets with SSL support
make clean || true
WITH_OPENSSL=1 make -j$(nproc)

# Install uSockets headers directly to include/ (not in subdirectory)
echo "Installing uSockets headers..."
cp src/*.h $SRC_PATH/third_party/include/
cp uSockets.a $SRC_PATH/third_party/lib/libuSockets.a

echo "uSockets installed successfully!"

# Install uWebSockets
echo "=== Installing uWebSockets ==="
cd $SRC_PATH
if [ ! -d "third_party/uWebSockets" ]; then
    cd third_party
    git clone https://github.com/uNetworking/uWebSockets.git
    cd uWebSockets
    git checkout v20.64.0
else
    cd third_party/uWebSockets
    git checkout v20.64.0
fi

# Install uWebSockets headers
echo "Installing uWebSockets headers..."
mkdir -p $SRC_PATH/third_party/include/uWebSockets
cp src/*.h $SRC_PATH/third_party/include/uWebSockets/

echo ""
echo "=== Installation Complete ==="
echo "uSockets library: $SRC_PATH/third_party/lib/libuSockets.a"
echo "uSockets headers: $SRC_PATH/third_party/include/libusockets.h (and others)"
echo "uWebSockets headers: $SRC_PATH/third_party/include/uWebSockets/"
echo ""
echo "You can now build your project with:"
echo "  mkdir -p build && cd build"
echo "  cmake -DCMAKE_BUILD_TYPE=Release .."
echo "  make seth -j\$(nproc)"
