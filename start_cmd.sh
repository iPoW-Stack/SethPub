#!/bin/bash

local_ip=$1
start_pos=$2
node_count=$3
bootstrap=$4
start_shard=$5
end_shard=$6

echo "Deployment info: IP:$local_ip Pos:$start_pos Count:$node_count Shard:$start_shard-$end_shard"

# ==========================================
# 1. 系统参数优化 (保持不变)
# ==========================================
echo ">>> Configuring system limits..."
cat > /etc/security/limits.d/99-seth.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 32768
* hard nproc 32768
root soft nofile 1000000
root hard nofile 1000000
EOF

ulimit -n 1000000

cat > /etc/sysctl.d/99-seth-tuning.conf <<EOF
fs.file-max = 1000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.somaxconn = 8192
net.ipv4.tcp_syncookies = 1
EOF
sysctl --system > /dev/null 2>&1

# ==========================================
# 2. 配置 Systemd 服务模板 (保持不变)
# ==========================================
echo ">>> Configuring systemd service template..."
cat > /etc/systemd/system/seth@.service <<EOF
[Unit]
Description=Seth Blockchain Node %i
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/seths/%i
ExecStart=/root/seths/%i/seth -f 0 -g 0 %i
Restart=always
RestartSec=5
LimitNOFILE=1000000
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ==========================================
# 3. 停止服务逻辑 (已修改：不按个数，全量清理)
# ==========================================

stop_services() {
    echo ">>> Cleaning up ALL existing seth services and processes..."
    
    # 1. 停止所有以 seth@ 开头的 Systemd 实例
    # 使用通配符，无需知道具体的实例名称或个数
    systemctl stop "seth@*" 2>/dev/null
    
    # 2. 禁用所有相关服务，清理 /etc/systemd/system 下的符号链接
    systemctl disable "seth@*" 2>/dev/null
    
    # 3. 强制杀死名为 seth 的所有残留进程
    # pkill 比 killall 更可靠，grep 匹配进程名
    pkill -9 -f seth 2>/dev/null
    
    # 4. 清理可能残留的失效 unit 文件
    systemctl reset-failed 2>/dev/null
    
    echo ">>> All seth-related daemons and processes cleared."
}

# ==========================================
# 4. 启动新服务逻辑 (保持不变)
# ==========================================

start_nodes() {
    echo ">>> Starting nodes via systemctl..."
    end_pos=$(($start_pos + $node_count - 1))
    
    for ((shard_id=$start_shard; shard_id<=$end_shard; shard_id++)); do
        if [ ! -f "/root/pkg/shards$shard_id" ]; then
            echo "Warning: Config file /root/pkg/shards$shard_id not found"
            continue
        fi

        shard_node_count=`wc -l /root/pkg/shards$shard_id | awk -F' ' '{print $1}'`
        
        for ((i=$start_pos; i<=$end_pos;i++)); do
            if (($i > $shard_node_count));then
                break
            fi

            instance_name="s${shard_id}_${i}"
            echo "Enable and Starting: seth@${instance_name}"
            
            # 启动并激活
            systemctl enable --now seth@${instance_name}

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

stop_services
start_nodes

echo ">>> Deployment finished."