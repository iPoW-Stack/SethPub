#!/bin/bash
set -e
PUBLIC_IP=127.0.0.1
START_POS=1
NODE_COUNT=4
START_SHARD=2
END_SHARD=4
LEADER_INIT_TM=$(date -u -d "+240 days" +%s)

# 解包到 /root/pkg
rm -rf /root/pkg
mkdir -p /root
cd /root && tar -xzf /root/shardora/pkg.tar.gz
echo "pkg unpacked: $(ls /root/pkg/)"

echo "=== temp_cmd.sh: configuring nodes ==="
cd /root/pkg
bash temp_cmd.sh $PUBLIC_IP $START_POS $NODE_COUNT 0 $START_SHARD $END_SHARD $LEADER_INIT_TM

echo "=== start_cmd.sh: starting nodes ==="
export SHARDORA_SKIP_SYSCTL=1
bash start_cmd.sh $PUBLIC_IP $START_POS $NODE_COUNT 0 $START_SHARD $END_SHARD

sleep 5
echo "=== Process check ==="
COUNT=$(ps aux | grep '\./shardora ' | grep -v grep | wc -l)
echo "Running shardora processes: $COUNT"
ps aux | grep '\./shardora ' | grep -v grep | awk '{print $11, $12}'
