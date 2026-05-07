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
#
# After a coverage run, optional per-module branch gate (gcovr):
#   COVERAGE_FAIL_UNDER_BRANCH=80 bash build.sh coverage Debug
# ---------------------------------------------------------------------------

# ---- 1. Parse command + determine build type --------------------------------
CMD="${1:-}"
TARGET="${2:-Release}"
if [[ "$TARGET" != "Debug" && "$TARGET" != "Release" ]]; then
    echo "Unknown build type '$TARGET'. Use Debug or Release."
    exit 1
fi

ENABLE_COVERAGE=0
if [[ "$CMD" == "coverage" || "${3:-}" == "coverage" ]]; then
    ENABLE_COVERAGE=1
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
if [[ "$ENABLE_COVERAGE" -eq 1 ]]; then
    cmake .. \
        -DCMAKE_BUILD_TYPE="$TARGET" \
        -DOPENSSL_ROOT_DIR=./third_party/depends/include/ \
        -DCMAKE_INSTALL_PREFIX=~/seth \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DREPLACE_WHITEBOX_PK="$PK_ARRAY" \
        -DREPLACE_WHITEBOX_SK="$SK_ARRAY" \
        -DENABLE_ASAN=OFF \
        -DXENABLE_CODE_COVERAGE=ON \
        -DCMAKE_C_FLAGS="--coverage -O0" \
        -DCMAKE_CXX_FLAGS="--coverage -O0" \
        -DCMAKE_EXE_LINKER_FLAGS="--coverage" \
        -DCMAKE_SHARED_LINKER_FLAGS="--coverage"
else
    cmake .. \
        -DCMAKE_BUILD_TYPE="$TARGET" \
        -DOPENSSL_ROOT_DIR=./third_party/depends/include/ \
        -DCMAKE_INSTALL_PREFIX=~/seth \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DREPLACE_WHITEBOX_PK="$PK_ARRAY" \
        -DREPLACE_WHITEBOX_SK="$SK_ARRAY" \
        -DENABLE_ASAN=OFF
fi

# ---- 5. Determine parallelism ----------------------------------------------
NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

# ---- 6. All test targets (executable name → subdirectory path) -------------
# Format: "executable_name:subdir_in_build"
declare -a ALL_TESTS=(
    "common_test:common_test"
    "network_test:network_test"
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
    "vss_test:vss_test"
    "sync_test:sync_test"
    "protos_test:protos_test"
    "block_test:block_test"
    "tmblock_test:tmblock_test"
    "pki_test:pki_test"
    "init_test:init_test"
    "websocket_test:websocket_test"
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
    if env -u GTEST_OUTPUT "$bin" --gtest_color=yes 2>&1; then
        echo "  [PASS] $exe"
    else
        echo "  [FAIL] $exe (exit code $?)"
        FAILED_TESTS+=("$exe")
    fi
}

# ---- 8. Coverage helpers ----------------------------------------------------
map_module_dir() {
    local exe="$1"
    case "$exe" in
        bignum_test) echo "big_num" ;;
        tmblock_test) echo "timeblock" ;;
        hotstuff_test) echo "consensus/hotstuff" ;;
        *) echo "${exe%_test}" ;;
    esac
}

print_module_coverage() {
    local gcovr_cmd="gcovr"
    if [[ -x "/root/.venvs/gcovr/bin/gcovr" ]]; then
        gcovr_cmd="/root/.venvs/gcovr/bin/gcovr"
    elif ! command -v gcovr >/dev/null 2>&1; then
        echo "  [WARN] gcovr not found (install it first)."
        return 0
    fi

    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Module Coverage (lines)"
    echo "════════════════════════════════════════════════════════════════"
    for entry in "${ALL_TESTS[@]}"; do
        local exe="${entry%%:*}"
        local module_dir
        module_dir="$(map_module_dir "$exe")"
        echo ""
        echo "[$module_dir]"
        "$gcovr_cmd" \
            --root .. \
            --object-directory . \
            --exclude-directories "../cbuild_.*" \
            --filter "../src/${module_dir}" \
            --exclude "../src/${module_dir}/tests" \
            --exclude ".*\\.h$" \
            --gcov-ignore-errors no_working_dir_found \
            --gcov-ignore-errors source_not_found \
            --merge-mode-functions merge-use-line-min \
            --print-summary | awk '/^lines:/ { print "  " $0 }'
        "$gcovr_cmd" \
            --root .. \
            --object-directory . \
            --exclude-directories "../cbuild_.*" \
            --filter "../src/${module_dir}" \
            --exclude "../src/${module_dir}/tests" \
            --exclude ".*\\.h$" \
            --gcov-ignore-errors no_working_dir_found \
            --gcov-ignore-errors source_not_found \
            --merge-mode-functions merge-use-line-min \
            --txt-metric branch \
            --print-summary | awk '/^branches:/ { print "  " $0 }'
    done
}

# Optional gate: set COVERAGE_FAIL_UNDER_BRANCH=80 (or export before running) to fail the build if any
# mapped module is below the branch threshold (requires gcovr and prior `bash build.sh coverage ...`).
enforce_branch_minimum() {
    local min_pct="${1:-80}"
    local gcovr_cmd="gcovr"
    if [[ -x "/root/.venvs/gcovr/bin/gcovr" ]]; then
        gcovr_cmd="/root/.venvs/gcovr/bin/gcovr"
    elif ! command -v gcovr >/dev/null 2>&1; then
        echo "  [WARN] gcovr not found; skip branch gate."
        return 0
    fi

    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Branch coverage gate: each module must be >= ${min_pct}%"
    echo "════════════════════════════════════════════════════════════════"

    local failed=0
    for entry in "${ALL_TESTS[@]}"; do
        local exe="${entry%%:*}"
        local module_dir
        module_dir="$(map_module_dir "$exe")"
        echo ""
        echo "[check ${module_dir}]"
        local gate_status=0
        set -o pipefail
        if "$gcovr_cmd" \
            --root .. \
            --object-directory . \
            --exclude-directories "../cbuild_.*" \
            --filter "../src/${module_dir}" \
            --exclude "../src/${module_dir}/tests" \
            --exclude ".*\\.h$" \
            --gcov-ignore-errors no_working_dir_found \
            --gcov-ignore-errors source_not_found \
            --merge-mode-functions merge-use-line-min \
            --txt-metric branch \
            --fail-under-branch "$min_pct" \
            --print-summary | awk '/^(lines:|branches:)/ { print "  " $0 }'; then
            gate_status=0
        else
            gate_status=$?
        fi
        set +o pipefail
        if [[ "$gate_status" -eq 0 ]]; then
            echo "  ✅  branch threshold (${min_pct}%) satisfied"
        else
            echo "  ❌  branches below ${min_pct}% (gcovr exit ${gate_status})"
            failed=1
        fi
    done

    if [[ "$failed" -ne 0 ]]; then
        echo ""
        echo "Branch coverage gate FAILED (target ${min_pct}% per module)."
        exit 1
    fi
}

# ---- 9. Dispatch on first argument -----------------------------------------

case "$CMD" in

    # ---- Run all tests -------------------------------------------------------
    "" | "test" | "coverage")
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

        if [[ "$ENABLE_COVERAGE" -eq 1 ]]; then
            print_module_coverage
            if [[ -n "${COVERAGE_FAIL_UNDER_BRANCH:-}" ]]; then
                enforce_branch_minimum "${COVERAGE_FAIL_UNDER_BRANCH}"
            fi
        fi
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
