# uWebSockets Setup Guide

## Problem
The compilation fails with:
```
fatal error: libusockets.h: No such file or directory
```

This happens because uWebSockets depends on uSockets (libusockets), and the headers need to be installed in the correct location.

## Solution

### Option 1: Run the Manual Installation Script (Recommended)

```bash
# From the project root directory
chmod +x install_uwebsockets_manual.sh
./install_uwebsockets_manual.sh
```

This script will:
1. Clone and build uSockets v0.8.8 with SSL support
2. Install uSockets headers to `third_party/include/` (directly, not in subdirectory)
3. Install uSockets library to `third_party/lib/libuSockets.a`
4. Clone uWebSockets v20.64.0 (header-only library)
5. Install uWebSockets headers to `third_party/include/uWebSockets/`

### Option 2: Manual Installation

If the script doesn't work, follow these steps:

#### Step 1: Install uSockets

```bash
cd third_party

# Clone uSockets if not present
git clone https://github.com/uNetworking/uSockets.git
cd uSockets
git checkout v0.8.8

# Build with SSL support
WITH_OPENSSL=1 make -j$(nproc)

# Install headers (directly to include/, NOT in a subdirectory)
cp src/*.h ../include/

# Install library
cp uSockets.a ../lib/libuSockets.a

cd ..
```

#### Step 2: Install uWebSockets

```bash
# Still in third_party directory

# Clone uWebSockets if not present
git clone https://github.com/uNetworking/uWebSockets.git
cd uWebSockets
git checkout v20.64.0

# Install headers (in uWebSockets subdirectory)
mkdir -p ../include/uWebSockets
cp src/*.h ../include/uWebSockets/

cd ../..
```

### Option 3: Update build_third.sh

The `build_third.sh` script has been updated to include uWebSockets installation. Run:

```bash
bash build_third.sh
```

## Verification

After installation, verify the files are in place:

```bash
# Check uSockets headers (should be directly in include/)
ls -la third_party/include/libusockets.h

# Check uWebSockets headers
ls -la third_party/include/uWebSockets/App.h

# Check uSockets library
ls -la third_party/lib/libuSockets.a
```

## Build the Project

Once uWebSockets is installed:

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make seth -j$(nproc)
```

## Key Points

1. **uSockets headers must be in `third_party/include/` directly** (not in a subdirectory)
   - This is because uWebSockets includes them as `#include <libusockets.h>`

2. **uWebSockets headers go in `third_party/include/uWebSockets/`**
   - Your code includes them as `#include <uWebSockets/App.h>`

3. **CMakeLists.txt is already configured correctly** with:
   - Include path: `${DEP_DIR}/include/uWebSockets`
   - Link libraries: `uSockets`, `ssl`, `crypto`, `z`

## Troubleshooting

### Error: "libusockets.h: No such file or directory"
- **Cause**: uSockets headers not installed or in wrong location
- **Fix**: Ensure `libusockets.h` is in `third_party/include/` (not in a subdirectory)

### Error: "undefined reference to uSockets functions"
- **Cause**: uSockets library not linked
- **Fix**: Verify `libuSockets.a` exists in `third_party/lib/`

### Error: SSL-related errors
- **Cause**: uSockets not built with SSL support
- **Fix**: Rebuild uSockets with `WITH_OPENSSL=1 make`

## Dependencies

uWebSockets requires:
- OpenSSL (for HTTPS support)
- zlib (for compression)
- C++17 or later

These are already configured in your CMakeLists.txt.
