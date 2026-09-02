#!/bin/bash
set -e
SETH=/root/seth/cbuild_Release/seth
NODES=12
END_SHARD=4
END_SHARD_IDX=$((END_SHARD + 1))

echo "=== Preparing /root/nodes/seth ==="
rm -rf /root/nodes/seth
mkdir -p /root/nodes/seth/conf /root/nodes/seth/log

cp $SETH /root/nodes/seth/seth
chmod +x /root/nodes/seth/seth
cp /root/seth/nodes_local/seth/conf/GeoLite2-City.mmdb /root/nodes/seth/conf/ 2>/dev/null || true
cp /root/seth/nodes_local/seth/conf/log4cpp.properties /root/nodes/seth/conf/ 2>/dev/null || true

cat > /root/nodes/seth/conf/seth.conf << 'CONF'
[db]
path = ./db
[log]
path = log/seth.log
[seth]
bootstrap =
net_id = 3
prikey = 0000000000000000000000000000000000000000000000000000000000000001
local_ip = 127.0.0.1
public_ip = 127.0.0.1
http_port = 23001
local_port = 13001
tx_ws_port = 33001
CONF

cd /root/nodes/seth
rm -rf shards* shard_db_* root_db root_blocks latest_blocks init_accounts* pkg

echo "=== genesis -U -N $NODES -E $END_SHARD_IDX ==="
./seth -U -N $NODES -E $END_SHARD_IDX 2>&1 | tail -5

echo "=== genesis -S 3 -N $NODES -E $END_SHARD_IDX ==="
./seth -S 3 -N $NODES -E $END_SHARD_IDX 2>&1 | tail -5

echo "=== genesis -C ==="
./seth -C 2>&1 | tail -5

echo "=== shards created ==="
for s in 2 3 4; do
  if [ -f shards$s ]; then
    echo "shards$s: $(wc -l < shards$s) lines"
  fi
done
ls -la shard_db_* 2>&1 | head -10
echo GENESIS_DONE
