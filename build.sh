#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# build.sh  —  Build and optionally run all module tests
#
# Usage:
#   bash build.sh                   # build seth (Release) + run all tests
#   bash build.sh test [Debug]      # build all tests + run them
#   bash build.sh test Release      # same, Release mode
#   bash build.sh seth [Debug]      # build only the main seth binary
#   bash build.sh tcp  [Debug]      # build tnets / tnetc
#   bash build.sh http [Debug]      # build https / httpc
#   bash build.sh ws   [Debug]      # build wss / wsc
# ---------------------------------------------------------------------------

# ---- 1. Determine build type -----------------------------------------------
TARGET="${2:-Release}"
if [[ "$TARGET" != "Debug" && "$TARGET" != "Release" ]]; then
    echo "Unknown build type '$TARGET'. Use Debug or Release."
    exit 1
fi

BUILD_DIR="cbuild_${TARGET}"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ---- 2. Generate ephemeral Curve25519 key pair for whitebox crypto ---------
openssl genpkey -algorithm x25519 -out private_key.pem 2>/dev/null

RAW_SK=$(openssl pkey -in private_key.pem -outform DER | tail -c 32 | xxd -p -c 32)
RAW_PK=$(openssl pkey -in private_key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32)

format_to_c_array() {
    echo "{$(echo "$1" | sed 's/../0x&,/g' | sed 's/,$//')}"
}

PK_ARRAY=$(format_to_c_array "$RAW_PK")
SK_ARRAY=$(format_to_c_array "$RAW_SK")

# ---- 3. Remove stale shared libs (force static linking) --------------------
rm -rf ../third_party/lib/lib*.so*
rm -rf ../third_party/lib64/lib*.so*

# ---- 4. CMake configure ----------------------------------------------------
cmake .. \
    -DCMAKE_BUILD_TYPE="$TARGET" \
    -DOPENSSL_ROOT_DIR=./third_party/depends/include/ \
    -DCMAKE_INSTALL_PREFIX=~/seth \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DREPLACE_WHITEBOX_PK="$PK_ARRAY" \
    -DREPLACE_WHITEBOX_SK="$SK_ARRAY" \
    -DENABLE_ASAN=OFF

# ---- 5. Determine parallelism ----------------------------------------------
NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

# ---- 6. All test targets (executable name → subdirectory path) -------------
# Format: "executable_name:subdir_in_build"
declare -a ALL_TESTS=(
    "common_test:common_test"
    "broadcast_test:broadcast_test"
    "security_test:security_test"
    "transport_test:transport_test"
    "bls_test:bls_test"
    "db_test:db_test"
    "dht_test:dht_test"
    "pools_test:pools_test"
    "sethvm_test:sethvm_test"
    "bignum_test:bignum_test"
    "contract_test:contract_test"
    "elect_test:elect_test"
    "consensus_test:consensus_test"
    "hotstuff_test:hotstuff_test"
    "ck_test:ck_test"
    "vss_test:vss_test"
    "sync_test:sync_test"
    "protos_test:protos_test"
    "block_test:block_test"
    "tmblock_test:tmblock_test"
)

# ---- 7. Helper: build + run a single test ----------------------------------
run_test() {
    local entry="$1"
    local exe="${entry%%:*}"
    local subdir="${entry##*:}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Building: $exe"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if ! make -j"$NPROC" "$exe" 2>&1; then
        echo "  [SKIP] Build failed for $exe — skipping run"
        return 0
    fi

    local bin="./${subdir}/${exe}"
    if [[ ! -x "$bin" ]]; then
        echo "  [SKIP] Binary not found: $bin"
        return 0
    fi

    echo ""
    echo "  Running: $bin"
    echo "────────────────────────────────────────────────────────────────"
    if "$bin" --gtest_color=yes 2>&1; then
        echo "  [PASS] $exe"
    else
        echo "  [FAIL] $exe (exit code $?)"
        FAILED_TESTS+=("$exe")
    fi
}

# ---- 8. Dispatch on first argument -----------------------------------------
CMD="${1:-}"

case "$CMD" in

    # ---- Run all tests -------------------------------------------------------
    "" | "test")
        FAILED_TESTS=()

        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo "  Building + Running ALL module tests  [${TARGET}]"
        echo "════════════════════════════════════════════════════════════════"

        for entry in "${ALL_TESTS[@]}"; do
            run_test "$entry"
        done

        echo ""
        echo "════════════════════════════════════════════════════════════════"
        if [[ ${#FAILED_TESTS[@]} -eq 0 ]]; then
            echo "  ✅  All tests passed"
        else
            echo "  ❌  Failed tests:"
            for t in "${FAILED_TESTS[@]}"; do
                echo "       - $t"
            done
            exit 1
        fi
        echo "════════════════════════════════════════════════════════════════"
        ;;

    # ---- Build main binary only ---------------------------------------------
    "seth")
        echo "Building seth [${TARGET}] with ${NPROC} jobs..."
        make -j"$NPROC" seth
        ;;

    # ---- TCP test binaries --------------------------------------------------
    "tcp")
        make -j"$NPROC" tnets tnetc
        ;;

    # ---- HTTP test binaries -------------------------------------------------
    "http")
        make -j"$NPROC" https httpc
        ;;

    # ---- WebSocket test binaries --------------------------------------------
    "ws")
        make -j"$NPROC" wss wsc
        ;;

    # ---- Build a specific named test ----------------------------------------
    *)
        # Allow: bash build.sh common_test
        echo "Building target: $CMD [${TARGET}]"
        make -j"$NPROC" "$CMD"
        bin=$(find . -name "$CMD" -type f -perm /111 | head -1)
        if [[ -n "$bin" ]]; then
            echo "Running: $bin"
            "$bin" --gtest_color=yes
        fi
        ;;
esac
