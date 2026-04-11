# Quick Fix for uWebSockets Compilation Error

## Error
```
fatal error: libusockets.h: No such file or directory
```

## Root Cause
The `libusockets.h` file is in `third_party/uWebSockets/uSockets/src/` but needs to be in `third_party/include/` for the compiler to find it.

## Quick Fix (Run on Server)

### Option 1: Use the Fix Script (Fastest)

```bash
# From project root directory
chmod +x fix_uwebsockets_headers.sh
./fix_uwebsockets_headers.sh
```

### Option 2: Manual Commands

```bash
# From project root directory
cd third_party/uWebSockets

# Initialize uSockets submodule if needed
git submodule update --init --recursive

# Copy uSockets headers to main include directory
cp uSockets/src/*.h ../include/

# Copy uWebSockets headers
mkdir -p ../include/uWebSockets
cp src/*.h ../include/uWebSockets/

# Build uSockets library
cd uSockets
WITH_OPENSSL=1 make -j$(nproc)
mkdir -p ../../lib
cp uSockets.a ../../lib/libuSockets.a

cd ../../..
```

### Option 3: Rebuild Everything

```bash
# From project root directory
bash build_third.sh
```

## Verify Installation

```bash
# Check if headers are in the right place
ls -lh third_party/include/libusockets.h
ls -lh third_party/include/uWebSockets/App.h
ls -lh third_party/lib/libuSockets.a
```

All three files should exist.

## Build Your Project

```bash
cd build
make clean
make seth -j$(nproc)
```

## Why This Happens

uWebSockets includes uSockets as a git submodule. The headers are in:
- `third_party/uWebSockets/uSockets/src/libusockets.h`

But the compiler looks for them in:
- `third_party/include/libusockets.h`

The fix copies the headers from the submodule to the expected location.

## Key Points

1. **uSockets headers** must be directly in `third_party/include/` (not in a subdirectory)
2. **uWebSockets headers** go in `third_party/include/uWebSockets/`
3. **uSockets library** goes in `third_party/lib/libuSockets.a`

## If You Still Get Errors

Make sure OpenSSL is installed:
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel
```

Then rebuild uSockets with SSL support:
```bash
cd third_party/uWebSockets/uSockets
make clean
WITH_OPENSSL=1 make -j$(nproc)
cp uSockets.a ../../lib/libuSockets.a
```
