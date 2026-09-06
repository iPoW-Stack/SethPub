#!/bin/bash
set -e
cd "$(dirname "$0")"
export PYTHONUTF8=1
export PYTHONUNBUFFERED=1

NODES_DATA_DIR="${NODES_DATA_DIR:-/data}"
HOST="${SHARDORA_HOST:-192.168.25.129}"
FUNDER_FILE="${NODES_DATA_DIR}/nodes/s3_1/init_accounts3"

python3 -c "import solcx; solcx.install_solc('0.8.34')" 2>/dev/null || true
FUNDER=$(head -1 "$FUNDER_FILE" | cut -f1)
[ -n "$FUNDER" ] || { echo "FATAL: cannot read funder from $FUNDER_FILE"; exit 1; }

echo "=== Contract Test Start $(date) ==="
echo "Host: $HOST  Data: $NODES_DATA_DIR"
echo "Funder: ${FUNDER:0:16}..."
python3 test_exchange_contract.py \
  --host "$HOST" \
  --shards 3,4,5,6 \
  --contracts 10 \
  --accounts 100 \
  --funder-key "$FUNDER" \
  2>&1 | tee /tmp/test_exchange_contract.log
RC=${PIPESTATUS[0]}
echo "=== Done exit=$RC $(date) ==="
exit $RC
