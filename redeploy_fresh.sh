#!/bin/bash
# 完整重建分片集群：编译 → 清理旧数据 → genesis → 打包 → 部署容器（数据目录 /data）
#
# 用法:
#   bash redeploy_fresh.sh [Debug|Release]
#
# 环境变量:
#   HOST_IP          默认 192.168.25.129
#   NODES_DATA_DIR   默认 /data
#   COMPILE          默认 1（先编译 shardora）
#   SHARD_COUNT      默认 5（shards 2~6）
#
set -euo pipefail

TARGET="${1:-Release}"
HOST_IP="${HOST_IP:-192.168.25.129}"
NODES_PER_HOST="${NODES_PER_HOST:-4}"
START_SHARD="${START_SHARD:-2}"
SHARD_COUNT="${SHARD_COUNT:-5}"
NODES_DATA_DIR="${NODES_DATA_DIR:-/data}"
COMPILE="${COMPILE:-1}"
SHARDORA_ROOT="${SHARDORA_ROOT:-/root/shardora}"
SHARDORA_BIN="${SHARDORA_BIN:-${SHARDORA_ROOT}/cbuild_${TARGET}/shardora}"
DEPLOY_SCRIPT="${DEPLOY_SCRIPT:-${SHARDORA_ROOT}/shardora_docker_deploy.sh}"

END_SHARD=$(( START_SHARD + SHARD_COUNT - 1 ))

echo "============================================================"
echo "  Shardora 分片集群完整重建"
echo "  Host           : $HOST_IP"
echo "  Shards         : $START_SHARD ~ $END_SHARD"
echo "  Nodes/host     : $NODES_PER_HOST"
echo "  NODES_DATA_DIR : $NODES_DATA_DIR"
echo "  Binary         : $SHARDORA_BIN"
echo "  COMPILE        : $COMPILE"
echo "============================================================"

# ── 0. 编译 shardora ──────────────────────────────────────────────
if [ "$COMPILE" = "1" ]; then
    echo ""
    echo "[0/5] 编译 shardora ${TARGET} ..."
    cd "$SHARDORA_ROOT"
    bash build.sh shardora "$TARGET"
fi

[ -x "$SHARDORA_BIN" ] || { echo "FATAL: shardora 不存在: $SHARDORA_BIN"; exit 1; }

# ── 1. 停止并删除所有 shardora 容器 ─────────────────────────────
echo ""
echo "[1/5] 停止旧容器 ..."
for cid in $(docker ps -a --format '{{.Names}}' | grep -E '^shardora-[0-9]+-[0-9]+$' || true); do
    docker stop "$cid" 2>/dev/null || true
    docker rm   "$cid" 2>/dev/null || true
    echo "  removed $cid"
done

# ── 2. 清理数据盘旧节点数据 ───────────────────────────────────
echo ""
echo "[2/5] 清理 ${NODES_DATA_DIR} 旧 nodes / pkg ..."
mkdir -p "$NODES_DATA_DIR"
rm -rf "${NODES_DATA_DIR}/nodes" "${NODES_DATA_DIR}/shardoras" "${NODES_DATA_DIR}/pkg"
rm -rf /root/nodes /root/shardoras /root/pkg /root/pkg.tar.gz
rm -rf "${SHARDORA_ROOT}"/shards* "${SHARDORA_ROOT}"/init_accounts* "${SHARDORA_ROOT}"/root_nodes
rm -rf "${SHARDORA_ROOT}"/pkgs "${SHARDORA_ROOT}"/cbuild_*/shards* 2>/dev/null || true
rm -rf /tmp/shardora_pkg_work_* 2>/dev/null || true

# ── 3. genesis + 打包 + 部署 ────────────────────────────────
echo ""
echo "[3/5] 执行 shardora_docker_deploy.sh (genesis + pkg + deploy -> ${NODES_DATA_DIR}) ..."
cd "$SHARDORA_ROOT"
bash "$DEPLOY_SCRIPT" \
    -H "$HOST_IP" \
    -n "$NODES_PER_HOST" \
    -s "$START_SHARD" \
    -N "$SHARD_COUNT" \
    -b "$SHARDORA_BIN" \
    -d "$NODES_DATA_DIR" \
    -R 0

# ── 4. 等待节点启动 ───────────────────────────────────────────
echo ""
echo "[4/5] 等待节点启动 (45s) ..."
sleep 45

running=$(docker ps --filter name=shardora- --format '{{.Names}}' | wc -l)
echo "  运行中容器: $running / $(( SHARD_COUNT * NODES_PER_HOST ))"

echo "检查 shard2 节点 (VerifyQC) ..."
for i in 1 2 3 4; do
    c="shardora-2-${i}"
    if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        err=$(docker logs "$c" 2>&1 | grep -c 'verify qc failed\|verify thresh sign failed' || true)
        view=$(docker logs "$c" 2>&1 | grep -c 'view block' || true)
        echo "  $c: qc_errors=$err view_blocks=$view"
    else
        echo "  $c: NOT RUNNING"
    fi
done

FUNDER_FILE="${NODES_DATA_DIR}/nodes/s3_1/init_accounts3"
echo ""
echo "============================================================"
echo "  重建完成。Funder 密钥 (${FUNDER_FILE} 第1行):"
head -1 "$FUNDER_FILE" 2>/dev/null | awk -F'\t' '{print "  privkey="$1}'
echo ""
echo "  合约测试:"
echo "  cd ${SHARDORA_ROOT}/clipy && NODES_DATA_DIR=${NODES_DATA_DIR} bash run_full_contract_test.sh"
echo "============================================================"
