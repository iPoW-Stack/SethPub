#!/bin/bash

local_ip=$1
start_pos=$2
node_count=$3
bootstrap=$4
start_shard=$5
end_shard=$6

echo "Deployment info: IP:$local_ip Pos:$start_pos Count:$node_count Shard:$start_shard-$end_shard"

# ==========================================
# 0. 环境检测：是否支持 systemd
# ==========================================
USE_SYSTEMD=true
if [ ! -d /run/systemd/system ] || [ "$(id -u)" != "0" ] || ! systemctl --version >/dev/null 2>&1; then
    echo "!!! Systemd not detected or not supported. Falling back to nohup mode."
    USE_SYSTEMD=false
fi

# ==========================================
# 1. 系统参数优化
# ==========================================
echo ">>> Configuring system limits..."
ulimit -n 1000000 2>/dev/null

# 仅在非容器环境或特权模式下尝试 sysctl
if [ -w /proc/sys/net/ipv4/tcp_congestion_control ]; then
    sysctl -w net.core.somaxconn=8192 >/dev/null 2>&1
    sysctl -w fs.file-max=1000000 >/dev/null 2>&1
fi

# ==========================================
# 2. 配置 Systemd 服务模板 (仅在支持时执行)
# ==========================================
if [ "$USE_SYSTEMD" = true ]; then
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
Environment=ASAN_OPTIONS=log_path=/tmp/asan.log:abort_on_error=1:detect_leaks=0:disable_coredump=0

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi

# ==========================================
# 3. 停止服务逻辑 (兼容模式)
# ==========================================
stop_services() {
    echo ">>> Cleaning up ALL existing seth services and processes..."
    
    if [ "$USE_SYSTEMD" = true ]; then
        systemctl stop "seth@*" 2>/dev/null
        systemctl disable "seth@*" 2>/dev/null
        systemctl reset-failed 2>/dev/null
    fi
    
    # 强制杀死名为 seth 的所有残留进程 (无论是否由 systemd 启动)
    pkill -9 -f seth 2>/dev/null
    echo ">>> All seth-related daemons and processes cleared."
}

ulimit -n 1000000

 # 优化TCP缓冲区
sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
echo "✓ TCP缓冲区已优化 (128MB)"

# 优化TCP参数
sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728" > /dev/null 2>&1
sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728" > /dev/null 2>&1
echo "✓ TCP读写缓冲已优化"

# 优化TCP连接
sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
echo "✓ TCP连接复用已启用"

# 写入配置
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/apt/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/apt/sysctl.conf

# 刷新配置使其生效
sudo sysctl -p

# ==========================================
# 4. 启动新服务逻辑 (兼容模式)
# ==========================================
start_nodes() {
    # ========== 应用层网络延迟注入参数 ==========
    # 模拟公网: 1G带宽, 点对点50ms延迟(单向25ms), 10ms抖动, 0.01%丢包率
    # 可通过环境变量覆盖这些默认值
    export SETH_NETWORK_ENABLED=${SETH_NETWORK_ENABLED:-1}
    export SETH_NETWORK_DELAY_MS=${SETH_NETWORK_DELAY_MS:-25}
    export SETH_NETWORK_JITTER_MS=${SETH_NETWORK_JITTER_MS:-10}
    export SETH_NETWORK_LOSS_RATE=${SETH_NETWORK_LOSS_RATE:-0.0001}

    # ========== AddressSanitizer 输出配置 ==========
    # ASan 错误报告写入每个节点的 log/asan.log.<pid>
    # 仅在 ASan 编译时生效，普通编译时这些变量无害
    # 注意：log_path 使用绝对路径，因为 systemd 的 WorkingDirectory 可能不生效
    export ASAN_OPTIONS="log_path=/tmp/asan.log:abort_on_error=1:detect_leaks=0:disable_coredump=0"
    
    echo ">>> Network simulation parameters:"
    echo "    SETH_NETWORK_ENABLED=$SETH_NETWORK_ENABLED"
    echo "    SETH_NETWORK_DELAY_MS=$SETH_NETWORK_DELAY_MS ms"
    echo "    SETH_NETWORK_JITTER_MS=$SETH_NETWORK_JITTER_MS ms"
    echo "    SETH_NETWORK_LOSS_RATE=$SETH_NETWORK_LOSS_RATE"
    # ========== 应用层网络延迟注入参数结束 ==========
    
    end_pos=$(($start_pos + $node_count - 1))
    
    for ((shard_id=$start_shard; shard_id<=$end_shard; shard_id++)); do
        SHARD_FILE="/root/pkg/shards$shard_id"
        if [ ! -f "$SHARD_FILE" ]; then
            echo "Warning: Config file $SHARD_FILE not found"
            continue
        fi

        shard_node_count=$(wc -l "$SHARD_FILE" | awk '{print $1}')
        
        for ((i=$start_pos; i<=$end_pos; i++)); do
            if (($i > $shard_node_count)); then
                break
            fi

            instance_name="s${shard_id}_${i}"
            work_dir="/root/seths/${instance_name}"
            
            # 确保工作目录存在
            mkdir -p "$work_dir"

            if [ "$USE_SYSTEMD" = true ]; then
                echo "Starting via Systemd: seth@${instance_name}"
                systemctl enable --now seth@${instance_name}
            else
                echo "Starting via Nohup: ${instance_name}"
                # 进入目录执行，确保相对路径正确
                cd "$work_dir" || continue
                # 使用 setsid 确保进程不会因为父 shell 退出而关闭
                # 模拟 systemd 的 WorkingDirectory 和 ExecStart
                setsid nohup ./seth -f 0 -g 0 "${instance_name}" >> "${work_dir}/seth.log" 2>&1 &
            fi

            # 启动间隔逻辑
            if ((shard_id==2 && i==start_pos)); then
                sleep 3
            fi
            sleep 0.2
        done
    done
}

# ==========================================
# 5. 执行流程
# ==========================================
stop_services
start_nodes

echo ">>> Deployment finished."
# 如果是 nohup 模式，最后显示一下进程状态
if [ "$USE_SYSTEMD" = false ]; then
    echo ">>> Current running seth processes:"
    ps -ef | grep seth | grep -v grep | wc -l
fi