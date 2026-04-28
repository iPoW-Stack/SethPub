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
# 例外: 192.168.26.141 不限速、不丢包
EXEMPT_IP="192.168.26.141"

setup_network_simulation() {
    # 设定网卡名称，通常为 eth0 或 ens33，请根据 ifconfig 结果修改
    INTERFACE="eth0"

    # 1. 清除旧的配置
    sudo tc qdisc del dev $INTERFACE root 2>/dev/null

    # 2. 使用 prio qdisc 作为根，3 个频段（默认）
    #    band 1 (prio 0): 白名单流量 — 无限制
    #    band 2 (prio 1): 其余流量 — 限速 + 延迟 + 丢包
    #    band 3 (prio 2): 未使用
    sudo tc qdisc add dev $INTERFACE root handle 1: prio bands 3 \
        priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1

    # 3. band 1: 白名单流量直通，不做任何限制
    sudo tc qdisc add dev $INTERFACE parent 1:1 handle 10: pfifo

    # 4. band 2: 限速 1Gbps + 延迟 25ms + 抖动 5ms + 丢包 0.005%
    sudo tc qdisc add dev $INTERFACE parent 1:2 handle 20: tbf \
        rate 1gbit burst 128kb latency 25ms
    sudo tc qdisc add dev $INTERFACE parent 20:1 handle 30: netem \
        delay 25ms 5ms 25%

    # 5. band 3: 默认 pfifo（未使用）
    sudo tc qdisc add dev $INTERFACE parent 1:3 handle 40: pfifo

    # 6. 将 EXEMPT_IP 的流量分到 band 1（白名单）
    sudo tc filter add dev $INTERFACE parent 1:0 protocol ip prio 1 \
        u32 match ip dst $EXEMPT_IP/32 flowid 1:1
    sudo tc filter add dev $INTERFACE parent 1:0 protocol ip prio 1 \
        u32 match ip src $EXEMPT_IP/32 flowid 1:1

    echo "公网模拟环境已就绪:"
    echo "带宽: 1Gbps | 延迟: 25ms | 抖动: 5ms (相关性25%) | 丢包率: 0.005%"
    echo "例外: $EXEMPT_IP 不限速、不丢包"
}

# 获取主网络接口 (排除 lo)
get_main_interface() {
    ip route | grep default | awk '{print $5}' | head -1
}

# 如果指定了网络接口参数，则进行网络模拟配置
# 使用方式: ./temp_cmd.sh <public_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard> <leader_init_tm> [network_interface]
if [ ! -z "$8" ]; then
    setup_network_simulation
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

            # 支持重复执行：如果目录已存在，先删除
            if [ -d "/root/seths/s$shard_id'_'$i" ]; then
                echo "节点 s$shard_id'_'$i 已存在，删除旧配置..."
                rm -rf "/root/seths/s$shard_id'_'$i"
            fi

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

            # 支持重复执行：删除旧的符号链接
            rm -f /root/seths/s$shard_id'_'$i/seth
            rm -f /root/seths/s$shard_id'_'$i/txcli
            rm -f /root/seths/s$shard_id'_'$i/conf/GeoLite2-City.mmdb
            rm -f /root/seths/s$shard_id'_'$i/conf/log4cpp.properties

            ln /root/pkg/seth /root/seths/s$shard_id'_'$i/seth
            ln /root/pkg/txcli /root/seths/s$shard_id'_'$i/txcli
            cp -rf /root/pkg/init_accounts* /root/seths/s$shard_id'_'$i/
            ln /root/pkg/GeoLite2-City.mmdb /root/seths/s$shard_id'_'$i/conf/GeoLite2-City.mmdb
            ln /root/pkg/log4cpp.properties /root/seths/s$shard_id'_'$i/conf/log4cpp.properties
            mkdir -p /root/seths/s$shard_id'_'$i/log

            # 支持重复执行：删除旧的数据库
            rm -rf /root/seths/s$shard_id'_'$i/db
            cp -rf /root/pkg/shard_db_$shard_id /root/seths/s$shard_id'_'$i/db

            # Generate self-signed SSL certificate for HTTPS server
            echo "Generating SSL certificate for node s$shard_id'_'$i"
            # 删除旧证书
            rm -f /root/seths/s$shard_id'_'$i/server-key.pem
            rm -f /root/seths/s$shard_id'_'$i/server-cert.pem

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