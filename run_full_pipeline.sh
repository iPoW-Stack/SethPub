#!/bin/bash
# 一键：编译 → 部署分片（/data）→ 合约全量测试
#
# 在 VM 宿主机执行:
#   bash /root/shardora/run_full_pipeline.sh [Debug|Release]
#
set -euo pipefail

TARGET="${1:-Release}"
SHARDORA_ROOT="${SHARDORA_ROOT:-/root/shardora}"
NODES_DATA_DIR="${NODES_DATA_DIR:-/data}"
LOG="/tmp/shardora_full_pipeline.log"

exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo "  Shardora 全流程: 编译 + 部署(/data) + 合约测试"
echo "  $(date)"
echo "  TARGET=$TARGET  DATA=$NODES_DATA_DIR"
echo "============================================================"

# 1. 编译 + 部署
bash "${SHARDORA_ROOT}/redeploy_fresh.sh" "$TARGET"

# 2. 合约测试（在 shardora-builder 内跑，funder 从宿主机 /data 读取）
echo ""
echo "[5/5] 运行 Exchange 合约全量测试 ..."
FUNDER_FILE="${NODES_DATA_DIR}/nodes/s3_1/init_accounts3"
FUNDER=$(head -1 "$FUNDER_FILE" | cut -f1)
[ -n "$FUNDER" ] || { echo "FATAL: no funder in $FUNDER_FILE"; exit 1; }

docker cp "${SHARDORA_ROOT}/clipy/test_exchange_contract.py" shardora-builder:/root/shardora/clipy/

docker exec \
  -e PYTHONUNBUFFERED=1 \
  -w /root/shardora/clipy \
  shardora-builder \
  python3 test_exchange_contract.py \
    --host "${HOST_IP:-192.168.25.129}" \
    --shards 3,4,5,6 \
    --contracts 10 \
    --accounts 100 \
    --funder-key "$FUNDER" \
  2>&1 | tee /tmp/test_exchange_contract.log
RC=${PIPESTATUS[0]}
echo "=== Contract test exit=$RC $(date) ==="
[ "$RC" -eq 0 ] || exit "$RC"

echo ""
echo "============================================================"
echo "  全流程完成 $(date)"
echo "  日志: $LOG"
echo "  测试: /tmp/test_exchange_contract.log"
echo "============================================================"
