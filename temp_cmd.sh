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

# ========== 网络控制 ==========
# 清除旧的网络配置
echo "清除旧的网络配置..."
for iface in $(ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//' | grep -v "^lo$"); do
    tc qdisc del dev $iface root 2>/dev/null || true
    tc qdisc del dev $iface ingress 2>/dev/null || true
done
tc qdisc del dev ifb0 root 2>/dev/null || true

echo "✓ 旧配置已清除"

# 获取主网络接口
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$MAIN_IFACE" ]; then
    echo "⚠️  无法检测网络接口，跳过网络模拟"
else
    echo "配置网络模拟..."
    echo "  接口: $MAIN_IFACE"
    echo "  带宽: 1Gbps"
    echo "  点对点延迟: 50ms (单向 25ms)"
    echo "  抖动: 10ms"
    echo "  丢包率: 0.01% (1/10000)"
    
    # 加载必要的内核模块
    modprobe sch_netem 2>/dev/null || true
    modprobe ifb 2>/dev/null || true
    
    # 配置出站流量延迟 (单向 25ms)
    tc qdisc add dev $MAIN_IFACE root handle 1: fq_codel 2>/dev/null
    tc qdisc add dev $MAIN_IFACE parent 1: handle 10: netem \
        delay 25ms 10ms \
        loss 0.01% 2>/dev/null
    
    # 配置入站流量延迟 (通过 ifb0)
    ip link set dev ifb0 down 2>/dev/null || true
    ip link set dev ifb0 up 2>/dev/null || true
    tc qdisc add dev $MAIN_IFACE ingress handle ffff: 2>/dev/null
    tc filter add dev $MAIN_IFACE parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0 2>/dev/null
    tc qdisc add dev ifb0 root handle 1: fq_codel 2>/dev/null
    tc qdisc add dev ifb0 parent 1: handle 10: netem \
        delay 25ms 10ms \
        loss 0.01% 2>/dev/null
    
    echo "✓ 网络模拟配置完成"
fi
# ========== 网络控制结束 ==========

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
