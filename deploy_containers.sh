#!/bin/bash
set -e

# 停止所有现有 shardora systemd 服务
echo "=== Stopping systemd shardora services ==="
systemctl list-units --type=service --all 'shardora@*' --no-legend 2>/dev/null \
    | awk '{print $1}' | while read -r unit; do
    [ -z "$unit" ] && continue
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
done
pkill -9 shardora 2>/dev/null || true
sleep 2
echo "systemd services stopped"

# 停止并删除已有 shardora 容器
echo "=== Removing old shardora containers ==="
docker ps -a --format '{{.Names}}' | grep '^shardora-s' | while read -r name; do
    docker stop "$name" 2>/dev/null || true
    docker rm "$name" 2>/dev/null || true
done

# 构建 shardora 运行时镜像（只需基础 ubuntu + libstdc++ 依赖）
echo "=== Building shardora-runtime image ==="
cat > /tmp/Dockerfile.shardora << 'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /node
CMD ["bash", "-c", "./shardora -f 0 -g 0 ${INSTANCE_NAME}"]
DOCKERFILE

docker build --quiet -f /tmp/Dockerfile.shardora -t shardora-runtime:latest /tmp
echo "Image built: shardora-runtime:latest"

# 为每个节点启动容器
echo "=== Starting 12 shardora containers ==="
for shard_id in 2 3 4; do
    for i in 1 2 3 4; do
        instance="s${shard_id}_${i}"
        node_dir="/root/shardoras/${instance}"
        container_name="shardora-${shard_id}-${i}"

        # 计算端口
        tcp_port="1${shard_id}00${i}"
        http_port="2${shard_id}00${i}"
        ws_port="3${shard_id}00${i}"

        echo "Starting $container_name (shard=$shard_id node=$i) ports: tcp=$tcp_port http=$http_port ws=$ws_port"

        docker run \
            --detach \
            --name "$container_name" \
            --restart unless-stopped \
            --network host \
            --volume "${node_dir}:/node" \
            --env INSTANCE_NAME="${instance}" \
            --ulimit nofile=1000000:1000000 \
            shardora-runtime:latest

        sleep 0.3
    done
done

echo ""
echo "=== Container status ==="
docker ps --filter 'name=shardora-' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo ""
echo "=== Open firewall ports ==="
for shard_id in 2 3 4; do
    for i in 1 2 3 4; do
        for port in "1${shard_id}00${i}" "2${shard_id}00${i}" "3${shard_id}00${i}"; do
            ufw allow "$port/tcp" 2>/dev/null || true
            iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        done
    done
done
echo "Ports opened."
echo ""
echo "=== Verifying shardora processes in containers ==="
sleep 3
docker ps --filter 'name=shardora-' --format '{{.Names}}' | while read -r name; do
    pid=$(docker exec "$name" pgrep shardora 2>/dev/null || echo "")
    if [ -n "$pid" ]; then
        echo "  $name: shardora running (pid $pid)"
    else
        echo "  $name: WARNING - shardora not running"
        docker logs --tail 5 "$name" 2>&1 | sed 's/^/    /'
    fi
done
