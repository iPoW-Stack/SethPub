# configure
TARGET=Debug

if test "$2" = "Debug"
then
	TARGET=Debug
fi

if test "$2" = "Release"
then
        TARGET=Release
fi

mkdir -p cbuild_$TARGET
cd cbuild_$TARGET
# CMAKE_BUILD_TYPE:
#   None:
#   Debug:              -g
#   Release:            -O3 -DNDEBUG
#   RelWithDebInfo:     -O2 -g -DNDEBUG
#   MinSizeRel:         -Os -DNDEBUG

# 1. Generate a Curve25519 Private Key (PEM format)
openssl genpkey -algorithm x25519 -out private_key.pem

# 2. Extract RAW Hex for Private Key (SK)
# OpenSSL 'outform DER' includes headers; we use 'pubout' and 'asn1parse' 
# or direct offset to get the raw 32 bytes.
RAW_SK=$(openssl pkey -in private_key.pem -outform DER | tail -c 32 | xxd -p -c 32)

# 3. Extract RAW Hex for Public Key (PK)
RAW_PK=$(openssl pkey -in private_key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32)

# 4. Helper function to format hex string to C-array {0xAA,0xBB,...}
format_to_c_array() {
    local hex_str=$1
    # Use sed to insert '0x' and ',' every 2 characters
    local formatted=$(echo "$hex_str" | sed 's/../0x&,/g' | sed 's/,$//')
    echo "{$formatted}"
}

# 5. Format the keys for CMake
PK_ARRAY=$(format_to_c_array "$RAW_PK")
SK_ARRAY=$(format_to_c_array "$RAW_SK")

rm -rf ../third_party/lib/lib*.so*
rm -rf ../third_party/lib64/lib*.so*

cmake ..  -DCMAKE_BUILD_TYPE=$TARGET -DOPENSSL_ROOT_DIR=./third_party/depends/include/ -DCMAKE_INSTALL_PREFIX=~/seth -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DREPLACE_WHITEBOX_PK="$PK_ARRAY" \
  -DREPLACE_WHITEBOX_SK="$SK_ARRAY" \
  -DENABLE_ASAN=OFF
if [[ $1 == "" ]];
then
    make -j3
    ./http_test/http_test
    ./common_test/common_test
    ./broadcast_test/broadcast_test
    ./security_test/security_test
    ./websocket_test/websocket_test
    ./transport_test/transport_test
    exit 0
fi
nproc=8
make -j${nproc} seth
echo $1
if [[ $1 == "test" ]];
then
    make -j3 common_test
    make -j3 http_test
    make -j3 broadcast_test
    make -j3 security_test
    make -j3 websocket_test
    make -j3 transport_test
    ./http_test/http_test
    ./common_test/common_test
    ./broadcast_test/broadcast_test
    ./security_test/security_test
    ./websocket_test/websocket_test
    ./transport_test/transport_test
fi

if [[ $1 == "tcp" ]];
then
    make -j3 tnets
    make -j3 tnetc
fi

if [[ $1 == "http" ]];
then
    make -j3 https
    make -j3 httpc
fi

if [[ $1 == "ws" ]];
then
    make -j3 wss
    make -j3 wsc
fi
