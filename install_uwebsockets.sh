#!/bin/bash

# uWebSockets 安装脚本
# 用于将 uWebSockets 和 uSockets 安装到 third_party 目录

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THIRD_PARTY_DIR="${SCRIPT_DIR}/third_party"
INCLUDE_DIR="${THIRD_PARTY_DIR}/include"
LIB_DIR="${THIRD_PARTY_DIR}/lib"

echo "=== uWebSockets 安装脚本 ==="
echo "目标目录: ${THIRD_PARTY_DIR}"

# 创建必要的目录
mkdir -p "${INCLUDE_DIR}"
mkdir -p "${LIB_DIR}"
mkdir -p /tmp/uws_build

cd /tmp/uws_build

# 1. 安装 uSockets (uWebSockets 的依赖)
echo ""
echo "步骤 1/2: 安装 uSockets..."
if [ ! -d "uSockets" ]; then
    git clone https://github.com/uNetworking/uSockets.git
fi

cd uSockets

# 编译 uSockets with SSL support
make clean || true
WITH_OPENSSL=1 make

# 复制库文件
if [ -f "uSockets.a" ]; then
    cp uSockets.a "${LIB_DIR}/libuSockets.a"
    echo "✓ uSockets 库已安装到 ${LIB_DIR}/libuSockets.a"
else
    echo "✗ 错误: uSockets 编译失败"
    exit 1
fi

# 复制头文件
mkdir -p "${INCLUDE_DIR}/uSockets"
cp src/*.h "${INCLUDE_DIR}/uSockets/" 2>/dev/null || true
echo "✓ uSockets 头文件已安装"

cd /tmp/uws_build

# 2. 安装 uWebSockets
echo ""
echo "步骤 2/2: 安装 uWebSockets..."
if [ ! -d "uWebSockets" ]; then
    git clone https://github.com/uNetworking/uWebSockets.git
fi

cd uWebSockets

# 复制头文件 (uWebSockets 是 header-only 库)
mkdir -p "${INCLUDE_DIR}/uWebSockets"
cp -r src/* "${INCLUDE_DIR}/uWebSockets/"
echo "✓ uWebSockets 头文件已安装"

# 清理
cd "${SCRIPT_DIR}"
rm -rf /tmp/uws_build

echo ""
echo "=== 安装完成 ==="
echo "头文件位置: ${INCLUDE_DIR}/uWebSockets"
echo "库文件位置: ${LIB_DIR}/libuSockets.a"
echo ""
echo "请确保 CMakeLists.txt 中包含以下配置:"
echo "  include_directories(\${DEP_DIR}/include/uWebSockets)"
echo "  link_libraries(uSockets ssl crypto z)"
echo ""
echo "如果遇到 OpenSSL 相关问题，请确保已安装 OpenSSL 开发库:"
echo "  macOS:   brew install openssl"
echo "  Ubuntu:  sudo apt-get install libssl-dev"
echo "  CentOS:  sudo yum install openssl-devel"
