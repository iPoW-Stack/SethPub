#!/bin/bash

# --- 1. System Dependencies ---
# Check OS and install only if necessary
if [ -f /etc/debian_version ]; then
    sudo apt update
    sudo apt install -y autoconf automake libtool texinfo libgnutls28-dev \
                        liblzma-dev pkg-config yasm zlib1g-dev libssh2-1-dev cmake
elif [ -f /etc/redhat-release ]; then
    sudo dnf install -y gnutls-devel perl procps-ng-devel texinfo xz-devel cmake
fi

git submodule init
git submodule update

export nproc=$(nproc 2>/dev/null || echo 8)
SRC_PATH=`pwd`
TP_PATH="$SRC_PATH/third_party"
mkdir -p $TP_PATH/lib $TP_PATH/include

# --- Function to check and build ---
# Usage: check_and_build "sentinel_file" "directory" "build_commands"
build_lib() {
    if [ ! -f "$1" ] && [ ! -d "$1" ]; then
        echo "Building $2..."
        cd $SRC_PATH/$2
        eval "$3"
    else
        echo "Skipping $2 (already built)."
    fi
    cd $SRC_PATH
}

# --- 2. Build Components ---

# Evmone
build_lib "$TP_PATH/lib/libevmone.a" "third_party/evmone" \
    "git checkout master && git submodule update --init && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install"

# EVMC
build_lib "$TP_PATH/include/evmc/evmc.h" "third_party/evmone/evmc" \
    "git submodule update --init && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install"

# Libsodium
build_lib "$TP_PATH/include/sodium.h" "third_party/libsodium" \
    "git checkout 9511c98 && git submodule update --init && ./autogen.sh && ./configure --prefix=$TP_PATH && make -j${nproc} install"

# Maxmind
build_lib "$TP_PATH/lib/libmaxminddb.a" "third_party/maxmind" \
    "git submodule update --init && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} && \
     cp -rnf libmaxminddb.a $TP_PATH/lib/ && mkdir -p $TP_PATH/include/maxmind && cp -rnf ../include/* $TP_PATH/include/maxmind/ && \
     cp -rnf build_release/generated/maxminddb_config.h $TP_PATH/include/maxmind/"

# Libuv
build_lib "$TP_PATH/include/libuv/uv.h" "third_party/libuv" \
    "git checkout 5152db2 && git submodule update --init && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install && \
     mv $TP_PATH/include/uv $TP_PATH/include/libuv && sed -i 's/\"uv\//\"libuv\//g' $TP_PATH/include/uv.h"

# Libbls
build_lib "$TP_PATH/lib/libdkgbls.a" "third_party/libbls" \
    "cd deps && PARALLEL_COUNT=1 bash build.sh && cd .. && cmake -S . -B build_release -DUSE_ASM=False -DWITH_PROCPS=OFF -DLIBBLS_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install && \
     mkdir -p $TP_PATH/include/libbls && cp -rnf ../third_party ../tools ../dkg ../bls $TP_PATH/include/libbls && cp -rnf ./libbls.a $TP_PATH/lib/libdkgbls.a"

# Protobuf
build_lib "$TP_PATH/bin/protoc" "third_party/protobuf" \
    "git checkout 48cb18e && ./autogen.sh && ./configure --disable-shared --enable-static CXXFLAGS='-fPIC -O3' --prefix=$TP_PATH && make -j${nproc} install"

# Spdlog
build_lib "$TP_PATH/lib/libspdlog.a" "third_party/spdlog" \
    "git checkout . && git submodule update --init && cmake -S . -B build_release -DSPDLOG_ENABLE_SOURCE_LOC=ON -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install"

# RocksDB
build_lib "$TP_PATH/lib/librocksdb.a" "third_party/rocksdb" \
    "git checkout . && sed -i 's/-march=native//g' ./CMakeLists.txt && git submodule update --init && cmake -S . -B build_release -DWITH_TESTS=OFF -DPORTABLE=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install"

# GmSSL
build_lib "$TP_PATH/lib/libgmssl.a" "third_party/gmssl" \
    "git checkout d655c06 && sed -i 's/-march=native//g' ./CMakeLists.txt && cmake -S . -B build_release -DBUILD_SHARED_LIBS=OFF -DENABLE_SM2_EXTS=on -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install && \
     objcopy --localize-symbol=OPENSSL_hexchar2int --localize-symbol=OPENSSL_hexstr2buf $TP_PATH/lib/libgmssl.a"

# Secp256k1
build_lib "$TP_PATH/lib/libsecp256k1.a" "third_party/secp256k1" \
    "git checkout a660a49 && bash ./autogen.sh && ./configure --enable-module-ecdh --enable-module-recovery --enable-module-schnorrsig --prefix=$TP_PATH && make -j${nproc} install"

# Clickhouse (Abseil/LZ4/Zstd)
build_lib "$TP_PATH/include/absl" "third_party/clickhouse" \
    "git submodule update --init && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install && \
     cp -rnf ../contrib/absl/absl $TP_PATH/include/ && cp -rnf ../contrib/lz4/lz4 $TP_PATH/include/"

# OpenSSL
build_lib "$TP_PATH/lib/libssl.a" "third_party/openssl" \
    "git checkout 7b371d8 && ./Configure --prefix=$TP_PATH && make -j${nproc} install"

# OQS
build_lib "$TP_PATH/lib/liboqs.a" "third_party/oqs" \
    "git checkout 94b421e && cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$TP_PATH && cd build_release && make -j${nproc} install"

# --- 3. Cleanup Shared Libs ---
# Final step to ensure only static libs are used
cd $SRC_PATH
rm -rf third_party/lib/lib*.so* third_party/lib64/lib*.so*

echo "All third_party dependencies are ready."