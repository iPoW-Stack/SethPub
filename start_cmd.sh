#!/bin/bash

local_ip=$1
start_pos=$2
node_count=$3
bootstrap=$4
start_shard=$5
end_shard=$6

echo "Deployment info: IP:$local_ip Pos:$start_pos Count:$node_count Shard:$start_shard-$end_shard"

# ==========================================
# 1. 系统参数优化 (幂等化处理，避免重复追加)
# ==========================================

echo ">>> Configuring system limits..."

# 使用独立文件管理 limits，避免污染主文件
cat > /etc/security/limits.d/99-seth.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 32768
* hard nproc 32768
root soft nofile 1000000
root hard nofile 1000000
EOF

# 临时生效 limit
ulimit -n 1000000

# 使用独立文件管理 sysctl
cat > /etc/sysctl.d/99-seth-tuning.conf <<EOF
# --- P2P & High Concurrency Optimization ---
fs.file-max = 1000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_slow_start_after_idle = 0
EOF

# 应用更改
sysctl --system > /dev/null 2>&1

# ==========================================
# 2. 配置 Systemd 服务模板
# ==========================================

echo ">>> Configuring systemd service template..."

# 创建服务模板，%i 代表实例名称 (例如 s1_0)
cat > /etc/systemd/system/seth@.service <<EOF
[Unit]
Description=Seth Blockchain Node %i
After=network.target

[Service]
Type=simple
# 设置工作目录，对应 /root/seths/s1_0
WorkingDirectory=/root/seths/%i
# 启动命令，对应原脚本逻辑
ExecStart=/root/seths/%i/seth -f 0 -g 0 %i
# 进程挂掉后自动重启
Restart=always
# 重启间隔 5秒
RestartSec=5
# 资源限制
LimitNOFILE=1000000
LimitCORE=infinity
# 这里的环境设置可以根据需要添加
# Environment=

[Install]
WantedBy=multi-user.target
EOF

# 重载 systemd 配置
systemctl daemon-reload

# ==========================================
# 3. 停止旧服务逻辑
# ==========================================

stop_services() {
    echo ">>> Stopping existing services..."
    end_pos=$(($start_pos + $node_count - 1))
    
    for ((shard_id=$start_shard; shard_id<=$end_shard; shard_id++)); do
        # 检查配置文件是否存在，防止报错
        if [ -f "/root/pkg/shards$shard_id" ]; then
            shard_node_count=`wc -l /root/pkg/shards$shard_id | awk -F' ' '{print $1}'`
            
            for ((i=$start_pos; i<=$end_pos;i++)); do
                if (($i > $shard_node_count));then
                    break
                fi
                
                instance_name="s${shard_id}_${i}"
                # 停止并禁用服务，防止冲突
                systemctl stop seth@${instance_name} 2>/dev/null
                systemctl disable seth@${instance_name} 2>/dev/null
            done
        fi
    done
    
    # 双重保险：强制杀死残留的 seth 进程 (如果不是由 systemd 管理的旧进程)
    killall -9 seth 2>/dev/null
    echo ">>> All services stopped."
}

# ==========================================
# 4. 启动新服务逻辑
# ==========================================

start_nodes() {
    echo ">>> Starting nodes via systemctl..."
    end_pos=$(($start_pos + $node_count - 1))
    
    for ((shard_id=$start_shard; shard_id<=$end_shard; shard_id++)); do
        # 检查分片配置是否存在
        if [ ! -f "/root/pkg/shards$shard_id" ]; then
            echo "Warning: Config file /root/pkg/shards$shard_id not found, skipping shard $shard_id"
            continue
        fi

        shard_node_count=`wc -l /root/pkg/shards$shard_id | awk -F' ' '{print $1}'`
        echo "Shard $shard_id total nodes: $shard_node_count"
        
        for ((i=$start_pos; i<=$end_pos;i++)); do
            if (($i > $shard_node_count));then
                break
            fi

            instance_name="s${shard_id}_${i}"
            echo "Enable and Starting: seth@${instance_name}"
            
            # 使用 systemctl 启动并设置开机自启
            # 这里的 instance_name 会自动替换 service 文件中的 %i
            systemctl enable --now seth@${instance_name}

            # 保持原有的启动间隔逻辑
            if ((shard_id==2 && i==start_pos)); then
                sleep 3
            fi
            sleep 0.5
        done
    done
}

# ==========================================
# 5. 执行流程
# ==========================================

# 第一步：停止现有服务
stop_services

# 第二步：(在此处可以插入你的部署/拷贝文件逻辑，如果需要的话)
# echo ">>> Deploying binaries..." 

# 第三步：启动服务
start_nodes

echo ">>> Deployment finished."
# 可以通过 systemctl status seth@s1_0 查看特定节点状态