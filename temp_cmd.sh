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
# 应用层网络延迟注入方案
# 模拟公网: 1G带宽, 点对点50ms延迟(单向25ms), 10ms抖动, 1/10000丢包率
# 
# 说明: 为避免TCP层报文被破坏，采用应用层延迟注入方式:
# 1. 在应用启动时设置环境变量 SETH_NETWORK_DELAY_MS 和 SETH_NETWORK_JITTER_MS
# 2. 在transport层代码中读取这些环境变量
# 3. 在发送/接收消息时添加相应的延迟
#
# 环境变量说明:
#   SETH_NETWORK_DELAY_MS=25      # 单向延迟 25ms (往返 50ms)
#   SETH_NETWORK_JITTER_MS=10     # 抖动 10ms
#   SETH_NETWORK_LOSS_RATE=0.0001 # 丢包率 0.01% (1/10000)
#   SETH_NETWORK_ENABLED=1        # 启用网络模拟 (0=禁用)

setup_network_simulation() {
    # 应用层延迟注入已在环境变量中配置
    # 无需在此处进行TC层配置，避免TCP报文破坏
    echo "网络模拟配置:"
    echo "  延迟: 25ms (单向) | 抖动: 10ms | 丢包率: 0.01%"
    echo "  方式: 应用层延迟注入 (避免TCP层报文破坏)"
    echo "  启用: 通过环境变量 SETH_NETWORK_ENABLED=1"
}

# 获取主网络接口 (排除 lo)
get_main_interface() {
    ip route | grep default | awk '{print $5}' | head -1
}

# 如果指定了网络接口参数，则进行网络模拟配置
# 使用方式: ./temp_cmd.sh <public_ip> <start_pos> <node_count> <bootstrap> <start_shard> <end_shard> <leader_init_tm> [enable_network_sim]
if [ ! -z "$8" ] && [ "$8" = "1" ]; then
    setup_network_simulation
    # 设置环境变量供应用使用
    export SETH_NETWORK_ENABLED=1
    export SETH_NETWORK_DELAY_MS=25
    export SETH_NETWORK_JITTER_MS=10
    export SETH_NETWORK_LOSS_RATE=0.0001
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
