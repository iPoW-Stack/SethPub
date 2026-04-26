public_ip=$1
start_pos=$2
node_count=$3
bootstrap=$4
start_shard=$5
end_shard=$6
leader_init_tm=$7
TEST_TX_TPS=5000
TEST_TX_MAX_POOL_INDEX=1

echo "new node: $public_ip $start_pos $node_count $start_shard $end_shard"
rm -rf /root/seths/
mkdir -p /root/seths/

local_ip=`hostname -I | awk '{print $1}'`

# ========== 网络模拟配置 ==========
# 模拟公网: 1G带宽, 点对点50ms延迟(单向25ms), 10ms抖动, 1/10000丢包率
setup_network_simulation() {
    local interface=$1
    
    if [ -z "$interface" ]; then
        echo "警告: 未指定网络接口，跳过网络模拟配置"
        return
    fi
    
    echo "配置网络模拟: $interface"
    echo "  - 带宽: 1Gbps"
    echo "  - 点对点延迟: 50ms (单向 25ms)"
    echo "  - 抖动: 10ms"
    echo "  - 丢包率: 0.01% (1/10000)"
    
    # 清除旧配置
    tc qdisc del dev "$interface" root 2>/dev/null || true
    
    # 添加根 qdisc (HTB - Hierarchical Token Bucket)
    tc qdisc add dev "$interface" root handle 1: htb default 1
    
    # 创建类限制带宽为 1Gbps
    tc class add dev "$interface" parent 1: classid 1:1 htb rate 1gbit
    
    # 添加 netem qdisc 用于延迟、抖动和丢包
    # 单向延迟 25ms，点对点往返延迟 50ms
    tc qdisc add dev "$interface" parent 1:1 handle 10: netem \
        delay 25ms 10ms \
        loss 0.01%
    
    echo "✓ 网络模拟配置完成"
    
    # 显示配置
    echo "当前 qdisc 配置:"
    tc qdisc show dev "$interface"
}

# 获取主网络接口 (排除 lo)
get_main_interface() {
    ip route | grep default | awk '{print $5}' | head -1
}

# 如果指定了网络接口参数，则进行网络模拟配置
# 使用方式: ./temp_cmd.sh <public_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard> <leader_init_tm> [network_interface]
if [ ! -z "$8" ]; then
    setup_network_simulation "$8"
else
    # 自动检测主网络接口
    main_interface=$(get_main_interface)
    if [ ! -z "$main_interface" ]; then
        echo "自动检测到网络接口: $main_interface"
        read -p "是否配置网络模拟? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            setup_network_simulation "$main_interface"
        fi
    fi
fi
# ========== 网络模拟配置结束 ==========
deploy_nodes() {
    end_pos=$(($start_pos + $node_count - 1))
    for ((shard_id=$start_shard; shard_id<=$end_shard; shard_id++)); do
        shard_node_count=`wc -l /root/pkg/shards$shard_id | awk -F' ' '{print $1}'`
        ls /root/pkg/shards$shard_id
        echo /root/pkg/shards$shard_id $shard_node_count
        for ((i=$start_pos; i<=$end_pos;i++)); do
            if (($i > $shard_node_count)); then
                break
            fi

            prikey=`sed -n "$i""p" /root/pkg/shards$shard_id | awk -F'\t' '{print $1}'`
            pubkey=`sed -n "$i""p" /root/pkg/shards$shard_id | awk -F'\t' '{print $2}'`
            cp -rf /root/pkg/temp /root/seths/s$shard_id'_'$i
            sed -i 's/PRIVATE_KEY/'$prikey'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/PUBLIC_IP/'$public_ip'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/LOCAL_IP/'$local_ip'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/LEADER_CHANGE_INIT_TM/'$leader_init_tm'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            if ((i<=TEST_TX_MAX_POOL_INDEX)); then
                sed -i 's/TEST_POOL_INDEX/'$(($i-1))'/g' /root/seths/s3_$i/conf/seth.conf
            else
                sed -i 's/TEST_POOL_INDEX/-1/g' /root/seths/s3_$i/conf/seth.conf
            fi

            sed -i 's/TEST_TX_TPS/'$TEST_TX_TPS'/g' /root/seths/s3_$i/conf/seth.conf

            port0=''
            port1=''
            port2=''
            if ((i>=100)); then
                port0='1'$shard_id''$i
                port1='2'$shard_id''$i
                port2='3'$shard_id''$i
            elif ((i>=10)); then
                port0='1'$shard_id'0'$i
                port1='2'$shard_id'0'$i
                port2='3'$shard_id'0'$i
            else
                port0='1'$shard_id'00'$i
                port1='2'$shard_id'00'$i
                port2='3'$shard_id'00'$i
            fi

            if (( port0 > 65535 )); then
                (( port0 = (port0 % 60000) + 1024 ))
            fi

            if (( port1 > 65535 )); then
                (( port1 = (port1 % 60000) + 1024 ))
            fi

            if (( port2 > 65535 )); then
                (( port2 = (port2 % 60000) + 1024 ))
            fi

            sed -i 's/HTTP_PORT/'$port1'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/LOCAL_PORT/'$port0'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/TX_WS_PORT/'$port2'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf

            echo /root/seths/s$shard_id'_'$i/seth
            ln /root/pkg/seth /root/seths/s$shard_id'_'$i/seth
            ln /root/pkg/txcli /root/seths/s$shard_id'_'$i/txcli
            cp -rf /root/pkg/init_accounts* /root/seths/s$shard_id'_'$i/
            ln /root/pkg/GeoLite2-City.mmdb /root/seths/s$shard_id'_'$i/conf/GeoLite2-City.mmdb
            ln /root/pkg/log4cpp.properties /root/seths/s$shard_id'_'$i/conf/log4cpp.properties
            mkdir -p /root/seths/s$shard_id'_'$i/log
            cp -rf /root/pkg/shard_db_$shard_id /root/seths/s$shard_id'_'$i/db
            
            # Generate self-signed SSL certificate for HTTPS server
            echo "Generating SSL certificate for node s$shard_id'_'$i"
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout /root/seths/s$shard_id'_'$i/server-key.pem \
                -out /root/seths/s$shard_id'_'$i/server-cert.pem \
                -days 365 \
                -subj "/C=CN/ST=State/L=City/O=Seth/OU=Node/CN=$local_ip" \
                2>/dev/null
            chmod 600 /root/seths/s$shard_id'_'$i/server-key.pem
            chmod 644 /root/seths/s$shard_id'_'$i/server-cert.pem
        done
    done
}

killall -9 seth

deploy_nodes

# ========== 清除网络模拟配置 ==========
# 如果需要清除网络模拟，可以运行:
# tc qdisc del dev <interface> root
# 或者在脚本中添加参数 "cleanup" 来自动清除
if [ "$9" = "cleanup" ]; then
    main_interface=$(get_main_interface)
    if [ ! -z "$main_interface" ]; then
        echo "清除网络模拟配置: $main_interface"
        tc qdisc del dev "$main_interface" root 2>/dev/null || true
        echo "✓ 网络模拟配置已清除"
    fi
fi
# ========== 清除网络模拟配置结束 ==========
