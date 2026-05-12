#!/usr/bin/env bash
# Seth / p2p — configure, build, run one module's gtests, optional coverage + missing-line log.
#
# Usage (from repo root: p2p/):
#   bash build.sh --module common
#   bash build.sh --module pools --coverage
#   bash build.sh --module network --coverage --gtest_filter='DhtManagerExtraTest.*'
#   bash build.sh --list-modules
#
# Options:
#   --module NAME     Short name (e.g. common, pools) or full target (common_test).
#   --coverage        Debug + --coverage flags; after tests run gcovr (summary + missing lines).
#   --build-dir PATH  Build tree (default: ./build).
#   --no-configure    Skip cmake (reuse existing build dir).
#   -- ...            Extra args passed to the test binary after '--'.
#
# Outputs (with --coverage):
#   ${BUILD_DIR}/coverage/<short>_summary.txt   — line/branch summary
#   ${BUILD_DIR}/coverage/<short>_missing.txt   — files / lines not executed (gcovr ≥ 7)
#   End of run prints an excerpt of the missing report to stdout (“未覆盖”日志).
#
# Requires: cmake, ninja or make, gcc/clang with gcov; gcovr optional (pip install gcovr).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT}/build"
DO_CONFIGURE=1
DO_COVERAGE=0
MODULE=""
GTEST_FILTER=""
EXTRA_GTEST=()

usage() {
	sed -n '1,25p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
}

# short_name -> cmake test target (folder under build/)
declare -A MODULE_TO_TARGET=(
	[common]=common_test
	[network]=network_test
	[broadcast]=broadcast_test
	[security]=security_test
	[transport]=transport_test
	[bls]=bls_test
	[db]=db_test
	[dht]=dht_test
	[pools]=pools_test
	[sethvm]=sethvm_test
	[bignum]=bignum_test
	[contract]=contract_test
	[elect]=elect_test
	[consensus]=consensus_test
	[hotstuff]=hotstuff_test
	[vss]=vss_test
	[sync]=sync_test
	[protos]=protos_test
	[block]=block_test
	[timeblock]=tmblock_test
	[tmblock]=tmblock_test
	[init]=init_test
	[websocket]=websocket_test
)

# gcov --filter regex (repeatable); keep under src/ for product code
module_coverage_filters() {
	local m="$1"
	case "$m" in
	common) echo "src/common/" ;;
	network) echo "src/network/" ;;
	pools) echo "src/pools/" ;;
	broadcast) echo "src/broadcast/" ;;
	dht) echo "src/dht/" ;;
	transport) echo "src/transport/" ;;
	security) echo "src/security/" ;;
	bls) echo "src/bls/" ;;
	db) echo "src/db/" ;;
	sethvm) echo "src/sethvm/" ;;
	bignum) echo "src/big_num/" ;;
	contract) echo "src/contract/" ;;
	elect) echo "src/elect/" ;;
	consensus) echo "src/consensus/" ;;
	hotstuff) echo "src/consensus/hotstuff/" ;;
	vss) echo "src/vss/" ;;
	sync) echo "src/sync/" ;;
	protos) echo "src/protos/" ;;
	block) echo "src/block/" ;;
	timeblock|tmblock) echo "src/timeblock/" ;;
	init) echo "src/init/" ;;
	websocket) echo "src/websocket/" ;;
	*) echo "src/${m}/" ;;
	esac
}

list_modules() {
	printf '%s\n' "Known --module short names (and ${BUILD_DIR}/<target>/<target> binary):"
	for k in "${!MODULE_TO_TARGET[@]}"; do
		printf '  %-12s -> %s\n' "$k" "${MODULE_TO_TARGET[$k]}"
	done | sort
}

resolve_target() {
	local in="$1"
	if [[ -n "${MODULE_TO_TARGET[$in]+x}" ]]; then
		echo "${MODULE_TO_TARGET[$in]}"
		return
	fi
	if [[ "$in" == *_test ]]; then
		echo "$in"
		return
	fi
	echo "${in}_test"
}

resolve_short() {
	local tgt="$1"
	for k in "${!MODULE_TO_TARGET[@]}"; do
		if [[ "${MODULE_TO_TARGET[$k]}" == "$tgt" ]]; then
			echo "$k"
			return
		fi
	done
	echo "$tgt"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help) usage ;;
	--list-modules) list_modules; exit 0 ;;
	--module) MODULE="${2:?}"; shift 2 ;;
	--coverage) DO_COVERAGE=1; shift ;;
	--build-dir) BUILD_DIR="${2:?}"; shift 2 ;;
	--no-configure) DO_CONFIGURE=0; shift ;;
	--gtest_filter) GTEST_FILTER="${2:?}"; shift 2 ;;
	--) shift; EXTRA_GTEST=("$@"); break ;;
	*)
		if [[ -z "$MODULE" && "$1" != -* ]]; then
			MODULE="$1"
			shift
		else
			echo "Unknown option: $1" >&2
			exit 2
		fi
		;;
	esac
done

if [[ -z "$MODULE" ]]; then
	echo "Error: pass --module <name> (see --list-modules)" >&2
	exit 2
fi

TARGET="$(resolve_target "$MODULE")"
SHORT="$(resolve_short "$TARGET")"
TEST_BIN="${BUILD_DIR}/${TARGET}/${TARGET}"
if [[ ! -x "$TEST_BIN" && -f "${BUILD_DIR}/${TARGET}/${TARGET}.exe" ]]; then
	TEST_BIN="${BUILD_DIR}/${TARGET}/${TARGET}.exe"
fi
if [[ ! -x "$TEST_BIN" ]]; then
	found="$(find "$BUILD_DIR" -maxdepth 5 -type f \( -name "${TARGET}" -o -name "${TARGET}.exe" \) 2>/dev/null | head -1)" || true
	if [[ -n "${found}" && -x "${found}" ]]; then
		TEST_BIN="${found}"
	fi
fi

CMAKE_TYPE=RelWithDebInfo
CMAKE_EXTRA=()
if [[ "$DO_COVERAGE" -eq 1 ]]; then
	CMAKE_TYPE=Debug
	CMAKE_EXTRA+=(
		"-DCMAKE_CXX_FLAGS=--coverage -O0 -g"
		"-DCMAKE_C_FLAGS=--coverage -O0 -g"
		"-DCMAKE_EXE_LINKER_FLAGS=--coverage"
	)
fi

if [[ "$DO_CONFIGURE" -eq 1 ]]; then
	mkdir -p "$BUILD_DIR"
	(
		cd "$BUILD_DIR"
		cmake "$ROOT" -G "Unix Makefiles" \
			-DCMAKE_BUILD_TYPE="$CMAKE_TYPE" \
			"${CMAKE_EXTRA[@]}"
	)
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building: $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cmake --build "$BUILD_DIR" --target "$TARGET" -j"$(nproc 2>/dev/null || echo 4)"

if [[ ! -x "$TEST_BIN" && ! -f "$TEST_BIN" ]]; then
	echo "Error: test binary not found: $TEST_BIN" >&2
	exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running: $TEST_BIN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
GTEST_ARGS=(--gtest_color=yes)
if [[ -n "$GTEST_FILTER" ]]; then
	GTEST_ARGS+=(--gtest_filter="$GTEST_FILTER")
fi
env -u GTEST_OUTPUT "$TEST_BIN" "${GTEST_ARGS[@]}" "${EXTRA_GTEST[@]}"

if [[ "$DO_COVERAGE" -eq 1 ]]; then
	if ! command -v gcovr >/dev/null 2>&1; then
		echo "[WARN] gcovr not in PATH; install: pip install gcovr" >&2
		exit 0
	fi
	COV_DIR="${BUILD_DIR}/coverage"
	mkdir -p "$COV_DIR"
	SUMMARY="${COV_DIR}/${SHORT}_summary.txt"
	MISSING="${COV_DIR}/${SHORT}_missing.txt"
	FILTER_ARG=()
	while IFS= read -r pat; do
		[[ -z "$pat" ]] && continue
		FILTER_ARG+=(--filter "${pat}.*")
	done < <(module_coverage_filters "$SHORT")
	if [[ ${#FILTER_ARG[@]} -eq 0 ]]; then
		FILTER_ARG=(--filter 'src/.+')
	fi

	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  gcovr summary -> $SUMMARY"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	# shellcheck disable=SC2068
	gcovr -r "$ROOT" \
		--object-directory="$BUILD_DIR" \
		"${FILTER_ARG[@]}" \
		--exclude-unreachable-branches \
		--print-summary \
		--txt "$SUMMARY"

	if gcovr --help 2>/dev/null | grep -q -- '--txt-missing'; then
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		echo "  Uncovered lines log -> $MISSING"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		gcovr -r "$ROOT" \
			--object-directory="$BUILD_DIR" \
			"${FILTER_ARG[@]}" \
			--exclude-unreachable-branches \
			--txt-missing "$MISSING"
		echo "(Full log: $MISSING)"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		echo "  Uncovered lines (first 200 lines)"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		head -n 200 "$MISSING" || true
	else
		echo "[WARN] gcovr has no --txt-missing; upgrade gcovr (>=7) for uncovered-line listing." >&2
		gcovr -r "$ROOT" \
			--object-directory="$BUILD_DIR" \
			"${FILTER_ARG[@]}" \
			--exclude-unreachable-branches \
			--txt - | tail -n 80 >"${COV_DIR}/${SHORT}_tail.txt" || true
		echo "Wrote last lines of text report to ${COV_DIR}/${SHORT}_tail.txt"
	fi
fi
