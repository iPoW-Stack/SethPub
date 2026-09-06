#!/bin/bash
set -e
SHARDORA=/root/shardora/cbuild_Release/shardora
NODES=12
END_SHARD=4
END_SHARD_IDX=$((END_SHARD + 1))

echo "=== Preparing /root/nodes/shardora ==="
rm -rf /root/nodes/shardora
mkdir -p /root/nodes/shardora/conf /root/nodes/shardora/log

cp $SHARDORA /root/nodes/shardora/shardora
chmod +x /root/nodes/shardora/shardora
cp /root/shardora/nodes_local/shardora/conf/GeoLite2-City.mmdb /root/nodes/shardora/conf/ 2>/dev/null || true
cp /root/shardora/nodes_local/shardora/conf/log4cpp.properties /root/nodes/shardora/conf/ 2>/dev/null || true

cat > /root/nodes/shardora/conf/shardora.conf << 'CONF'
[db]
path = ./db
[log]
path = log/shardora.log
[shardora]
bootstrap =
net_id = 3
prikey = 0000000000000000000000000000000000000000000000000000000000000001
local_ip = 127.0.0.1
public_ip = 127.0.0.1
http_port = 23001
local_port = 13001
tx_ws_port = 33001
CONF

cd /root/nodes/shardora
rm -rf shards* shard_db_* root_db root_blocks latest_blocks init_accounts* pkg

echo "=== genesis -U -N $NODES -E $END_SHARD_IDX ==="
./shardora -U -N $NODES -E $END_SHARD_IDX 2>&1 | tail -5

echo "=== genesis -S 3 -N $NODES -E $END_SHARD_IDX ==="
./shardora -S 3 -N $NODES -E $END_SHARD_IDX 2>&1 | tail -5

echo "=== genesis -C ==="
./shardora -C 2>&1 | tail -5

echo "=== shards created ==="
for s in 2 3 4; do
  if [ -f shards$s ]; then
    echo "shards$s: $(wc -l < shards$s) lines"
  fi
done
ls -la shard_db_* 2>&1 | head -10
echo GENESIS_DONE
