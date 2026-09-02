#!/bin/bash
set -e

# 停止所有现有 seth systemd 服务
echo "=== Stopping systemd seth services ==="
systemctl list-units --type=service --all 'seth@*' --no-legend 2>/dev/null \
    | awk '{print $1}' | while read -r unit; do
    [ -z "$unit" ] && continue
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
done
pkill -9 seth 2>/dev/null || true
sleep 2
echo "systemd services stopped"

# 停止并删除已有 seth 容器
echo "=== Removing old seth containers ==="
docker ps -a --format '{{.Names}}' | grep '^seth-s' | while read -r name; do
    docker stop "$name" 2>/dev/null || true
    docker rm "$name" 2>/dev/null || true
done

# 构建 seth 运行时镜像（只需基础 ubuntu + libstdc++ 依赖）
echo "=== Building seth-runtime image ==="
cat > /tmp/Dockerfile.seth << 'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /node
CMD ["bash", "-c", "./seth -f 0 -g 0 ${INSTANCE_NAME}"]
DOCKERFILE

docker build --quiet -f /tmp/Dockerfile.seth -t seth-runtime:latest /tmp
echo "Image built: seth-runtime:latest"

# 为每个节点启动容器
echo "=== Starting 12 seth containers ==="
for shard_id in 2 3 4; do
    for i in 1 2 3 4; do
        instance="s${shard_id}_${i}"
        node_dir="/root/seths/${instance}"
        container_name="seth-${shard_id}-${i}"

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
            seth-runtime:latest

        sleep 0.3
    done
done

echo ""
echo "=== Container status ==="
docker ps --filter 'name=seth-' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
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
echo "=== Verifying seth processes in containers ==="
sleep 3
docker ps --filter 'name=seth-' --format '{{.Names}}' | while read -r name; do
    pid=$(docker exec "$name" pgrep seth 2>/dev/null || echo "")
    if [ -n "$pid" ]; then
        echo "  $name: seth running (pid $pid)"
    else
        echo "  $name: WARNING - seth not running"
        docker logs --tail 5 "$name" 2>&1 | sed 's/^/    /'
    fi
done
