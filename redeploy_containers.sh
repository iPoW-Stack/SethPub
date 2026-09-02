#!/bin/bash
set -e

echo "=== Removing old seth containers ==="
docker ps -a --format '{{.Names}}' | grep '^seth-[0-9]' | while read -r name; do
    docker stop "$name" 2>/dev/null || true
    docker rm "$name" 2>/dev/null || true
done

echo "=== Starting 12 seth containers ==="
for shard_id in 2 3 4; do
    for i in 1 2 3 4; do
        instance="s${shard_id}_${i}"
        node_dir="/root/seths/${instance}"
        container_name="seth-${shard_id}-${i}"

        echo "Starting $container_name (instance=$instance)"

        docker run \
            --detach \
            --name "$container_name" \
            --restart unless-stopped \
            --network host \
            --volume "${node_dir}:/node" \
            --volume "/root/pkg:/root/pkg:ro" \
            --workdir /node \
            --env INSTANCE_NAME="${instance}" \
            --ulimit nofile=1000000:1000000 \
            seth-runtime:latest \
            bash -c './seth -f 0 -g 0 '"${instance}"

        sleep 0.3
    done
done

echo ""
sleep 5
echo "=== Container status ==="
docker ps --filter 'name=seth-[0-9]' --format 'table {{.Names}}\t{{.Status}}'

echo ""
echo "=== seth process check ==="
for shard_id in 2 3 4; do
    for i in 1 2 3 4; do
        name="seth-${shard_id}-${i}"
        pid=$(docker exec "$name" pgrep seth 2>/dev/null || echo "")
        status=$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null)
        if [ -n "$pid" ]; then
            echo "  $name: RUNNING (pid=$pid)"
        else
            echo "  $name: NOT RUNNING (status=$status)"
            docker logs --tail 3 "$name" 2>&1 | sed 's/^/    LOG: /'
        fi
    done
done
