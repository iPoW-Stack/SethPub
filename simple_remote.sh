each_nodes_count=$1
node_ips=$2
bootstrap=""
end_shard=$3
PASSWORD=$4
TARGET=$5
FIRST_NODE_COUNT=$1

CODE_PATH=`pwd`
node_ips_array=(${node_ips//,/ })
nodes_count=0
for ip in "${node_ips_array[@]}"; do
    nodes_count=$(($nodes_count + $each_nodes_count))
done
node_hash=$(printf "%d%d" "$nodes_count" "$each_nodes_count" | md5sum | cut -d ' ' -f1)

bash cmd.sh $2 "sudo tc qdisc del dev eth0 root 2>/dev/null || true;pkill -9 seth;systemctl stop 'seth@*' 2>/dev/null; systemctl list-units --all 'seth@*' --no-legend | cut -d' ' -f1 | xargs -r -n1 sh -c 'systemctl stop \"\$0\"; systemctl disable \"\$0\"' 2>/dev/null; systemctl daemon-reload; systemctl reset-failed"
init() {
    tmp_ips=(${node_ips//-/ })
    tmp_ips_len=(${#tmp_ips[*]})
    ip_max_idx=0
    if (($tmp_ips_len > 1)); then
        for tmp_ip_nodes in "${tmp_ips[@]}"; do
            ips_array=(${tmp_ip_nodes//,/ })
            first_ip=(${ips_array[0]})
            second_ip=(${ips_array[1]})

            start=$(($first_ip + 0))
            end=$(($second_ip + 0))
            for ((i=start; i<=end; i++)); do
                if ((i==end));then
                    new_ips+="192.168.$ip_max_idx.$i"
                else
                    new_ips+="192.168.$ip_max_idx.$i,"
                fi
            done

            new_ips+=","
            ip_max_idx=$(($ip_max_idx+1))
        done

        node_ips=$new_ips
        echo $node_ips
    else
        ips_array=(${node_ips//,/ })
        ips_len=(${#ips_array[*]})
        if (($ips_len == 2)); then
            first_ip=(${ips_array[0]})
            second_ip=(${ips_array[1]})
            first_ip_len=(${#first_ip})
            new_ips=""
            if (($first_ip_len<=6)); then
                start=$(($first_ip + 0))
                end=$(($second_ip + 0))
                for ((i=start; i<=end; i++)); do
                    if ((i==end));then
                        new_ips+="192.168.0.$i"
                    else
                        new_ips+="192.168.0.$i,"
                    fi
                done
                node_ips=$new_ips
                echo $node_ips
            fi
        fi
    fi

    if [ "$node_ips" == "" ]; then
        echo "just use local single node."
        node_ips='127.0.0.1'
    fi

    bash cmd.sh $node_ips "tc qdisc del dev eth0 root"  > /dev/null 2>&1 &
    if [ "$end_shard" == "" ]; then
        end_shard=3
    fi

    if [ "$PASSWORD" == "" ]; then
        PASSWORD="Xf4aGbTaf&"
    fi

    if [ "$TARGET" == "" ]; then
        TARGET=Release
    fi

    killall -9 seth
    killall -9 txcli

    bash build.sh a $TARGET
    sudo rm -rf /root/nodes
    sudo cp -rf ./nodes_local /root/nodes
    rm -rf /root/nodes/*/seth /root/nodes/*/core* /root/nodes/*/log/* /root/nodes/*/*db*

    cp -rf ./nodes_local/seth/conf/GeoLite2-City.mmdb /root/nodes/seth
    cp -rf ./nodes_local/seth/conf/log4cpp.properties /root/nodes/seth/conf
    mkdir -p /root/nodes/seth/log


    sudo cp -rf ./cbuild_$TARGET/seth /root/nodes/seth
    if [[ "$each_nodes_count" -eq "" ]]; then
        each_nodes_count=4
    fi


    nodes_count=$(($nodes_count - $each_nodes_count + $FIRST_NODE_COUNT))
    shard3_node_count=`wc -l /root/seth/shards3 | awk -F' ' '{print $1}'`
    if [ "$shard3_node_count" != "$nodes_count" ]; then
        echo "new shard nodes file will create."
        rm -rf /root/seth/shards*
    fi

    echo "node count: " $nodes_count
    rm -rf /root/nodes/seth/latest_blocks
}

get_bootstrap() {
    node_ips_array=(${node_ips//,/ })
    for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
        i=1
        for ip in "${node_ips_array[@]}"; do
            for ((j=0; j<$each_nodes_count;j++)); do
                tmppubkey=`sed -n "$i""p" /root/nodes/seth/pkg/shards${shard_id} | awk -F'\t' '{print $2}'`
                port=''
                if ((i>=100)); then
                    port='1'$shard_id''$i
                elif ((i>=10)); then
                    port='1'$shard_id'0'$i
                else
                    port='1'$shard_id'00'$i
                fi

                if (( port > 65535 )); then
                    (( port = (port % 60000) + 1024 ))
                fi

                node_info=$tmppubkey":"$ip":"$port":"$shard_id
                bootstrap=$bootstrap","$node_info
                i=$((i+1))
            done
        done
    done
# 1. 先把超长的 bootstrap 变量写入一个临时文件
printf "%s" "$bootstrap" > /tmp/bootstrap_data.tmp

# 2. 让 Python 读取文件进行替换
/root/tools/python3.10/bin/python3 -c "
import os
conf_path = '/root/nodes/seth/pkg/temp/conf/seth.conf'
with open('/tmp/bootstrap_data.tmp', 'r') as f:
    new_val = f.read()
with open(conf_path, 'r') as f:
    content = f.read()
with open(conf_path, 'w') as f:
    f.write(content.replace('BOOTSTRAP', new_val))
"

# 3. 删除临时文件
rm /tmp/bootstrap_data.tmp    
echo $bootstrap
}

make_package() {
    mkdir -p /root/seth/pkgs
    rm -rf /root/nodes/seth/pkg
    if [ -d "/root/seth/pkgs/$node_hash" ]; then
        cd /root/seth/ && bash build.sh a $TARGET
        cd /root/seth/cbuild_$TARGET && make txcli
        cp -rf /root/seth/cbuild_$TARGET/seth /root/seth/pkgs/$node_hash/seth
        cp -rf /root/seth/pkgs/$node_hash /root/nodes/seth/pkg
        rm -rf /root/nodes/seth/pkg/temp
        cp -rf /root/nodes/temp /root/nodes/seth/pkg
        # Always refresh scripts so latest placeholder substitutions take effect.
        cp /root/seth/temp_cmd.sh /root/nodes/seth/pkg
        cp /root/seth/start_cmd.sh /root/nodes/seth/pkg
        for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
            /root/seth/cbuild_$TARGET/seth -A /root/seth/shards${shard_id} -D /root/nodes/seth/pkg/shards${shard_id}
            /root/seth/cbuild_$TARGET/seth -A  /root/seth/init_accounts${shard_id} -D /root/nodes/seth/pkg/init_accounts${shard_id}
        done
    else
        cd /root/nodes/seth && ./seth -U -N $nodes_count -E 4
        cd /root/nodes/seth && ./seth -S 3 -N $nodes_count -E 4
        cd /root/nodes/seth && ./seth -C
        cd /root/seth/cbuild_$TARGET && make txcli

        mkdir /root/nodes/seth/pkg
        cp /root/nodes/seth/seth /root/nodes/seth/pkg
        cp /root/nodes/seth/conf/GeoLite2-City.mmdb /root/nodes/seth/pkg
        cp /root/nodes/seth/conf/log4cpp.properties /root/nodes/seth/pkg
        for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
            /root/seth/cbuild_$TARGET/seth -A /root/seth/shards${shard_id} -D /root/nodes/seth/pkg/shards${shard_id}
            /root/seth/cbuild_$TARGET/seth -A  /root/seth/init_accounts${shard_id} -D /root/nodes/seth/pkg/init_accounts${shard_id}
        done
        cp /root/seth/temp_cmd.sh /root/nodes/seth/pkg
        cp /root/seth/start_cmd.sh /root/nodes/seth/pkg
        cp -rf /root/nodes/seth/shard_db_2 /root/nodes/seth/pkg/shard_db_2
        cp -rf /root/nodes/seth/shard_db_3 /root/nodes/seth/pkg
        cp -rf /root/nodes/temp /root/nodes/seth/pkg
        cp -rf /root/seth/gdb/* /root/nodes/seth/pkg
        cp -rf /root/nodes/seth/pkg /root/seth/pkgs/$node_hash
    fi

    get_bootstrap
    cd /root/nodes/seth/ && tar -zcvf pkg.tar.gz ./pkg > /dev/null 2>&1
}

check_cmd_finished() {
    echo "waiting..."
    sleep 1
    ps -ef | grep sshpass
    while true
    do
        sshpass_count=`ps -ef | grep sshpass | grep ConnectTimeout | wc -l`
        if [ "$sshpass_count" == "0" ]; then
            break
        fi
        sleep 1
    done

    ps -ef | grep sshpass
    echo "waiting ok"
}


clear_command() {
    echo 'run_command start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    start_pos=1
    for ip in "${node_ips_array[@]}"; do
        # 清理延迟限制
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip -p 22 "tc qdisc del dev eth0 root 2>/dev/null || true; tc qdisc del dev eth1 root 2>/dev/null || true; tc qdisc del dev ens0 root 2>/dev/null || true; tc qdisc del dev ens1 root 2>/dev/null || true" &
        
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip -p 22 "cd /root && rm -rf pkg*; killall -9 seth" &
        run_cmd_count=$((run_cmd_count + 1))
        if ((start_pos==1)); then
            sleep 3
        fi

        if (($run_cmd_count >= 250)); then
            check_cmd_finished
            run_cmd_count=0
        fi
        start_pos=$(($start_pos+$each_nodes_count))
    done

    check_cmd_finished
    echo 'run_command over'
}

scp_package() {
    echo 'scp_package start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    for ip in "${node_ips_array[@]}"; do
        sshpass -p $PASSWORD scp -P 22 -o ConnectTimeout=10  -o StrictHostKeyChecking=no /root/nodes/seth/pkg.tar.gz root@$ip:/root &
        run_cmd_count=$((run_cmd_count + 1))
        if (($run_cmd_count >= 100)); then
            check_cmd_finished
            run_cmd_count=0
        fi
    done

    check_cmd_finished
    echo 'scp_package over'
}

run_command() {
    echo 'run_command start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    start_pos=1
    for ip in "${node_ips_array[@]}"; do
        echo "run temp_cmd node: " $ip $each_nodes_count
        start_nodes_count=$(($each_nodes_count + 0))
        if ((start_pos==1)); then
            start_nodes_count=$FIRST_NODE_COUNT
        fi

        leader_init_tm=$(date -u -d "+240 seconds" +%s)
        
        # 应用双向网络延迟配置 (点对点50ms延迟 = 单向25ms)
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip -p 22 "
# 清除旧配置
for iface in \$(ip link show | grep '^[0-9]' | awk '{print \$2}' | sed 's/:$//' | grep -v '^lo$'); do
    tc qdisc del dev \$iface root 2>/dev/null || true
    tc qdisc del dev \$iface ingress 2>/dev/null || true
done

# 获取所有活跃接口并应用双向延迟
for iface in \$(ip link show | grep '^[0-9]' | awk '{print \$2}' | sed 's/:$//' | grep -v '^lo$'); do
    if ip link show \$iface | grep -q 'UP'; then
        # 出站流量延迟
        tc qdisc add dev \$iface root handle 1: fq_codel
        tc qdisc add dev \$iface parent 1: handle 10: netem delay 25ms 10ms loss 0.01%
        
        # 入站流量延迟 (通过 ifb)
        modprobe ifb 2>/dev/null || true
        ip link set dev ifb0 down 2>/dev/null || true
        ip link set dev ifb0 up 2>/dev/null || true
        tc qdisc add dev \$iface ingress handle ffff:
        tc filter add dev \$iface parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0
        tc qdisc add dev ifb0 root handle 1: fq_codel
        tc qdisc add dev ifb0 parent 1: handle 10: netem delay 25ms 10ms loss 0.01%
    fi
done
" > /dev/null 2>&1 &
        
        sleep 2
        
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip -p 22 "cd /root && tar -zxvf pkg.tar.gz && cd ./pkg && bash temp_cmd.sh $ip $start_pos $start_nodes_count 0 2 $end_shard $leader_init_tm 'eth0' "  > /dev/null 2>&1 &
        if ((start_pos==1)); then
            sleep 3
        fi

        run_cmd_count=$(($run_cmd_count + 1))
        if (($run_cmd_count >= 250)); then
            check_cmd_finished
            run_cmd_count=0
        fi
        start_pos=$(($start_pos+$start_nodes_count))
    done

    check_cmd_finished
    echo 'run_command over'
}

start_all_nodes() {
    echo 'start_all_nodes start'
    node_ips_array=(${node_ips//,/ })
    start_pos=1
    for ip in "${node_ips_array[@]}"; do
        echo "run start_cmd node: " $ip $each_nodes_count
        start_nodes_count=$(($each_nodes_count + 0))
        if ((start_pos==1)); then
            start_nodes_count=$FIRST_NODE_COUNT
        fi

        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip -p 22 "cd /root/pkg && bash start_cmd.sh $ip $start_pos $start_nodes_count 0 2 $end_shard "  &
        if ((start_pos==1)); then
            sleep 3
        fi

        sleep 0.1
        start_pos=$(($start_pos+$start_nodes_count))
    done

    check_cmd_finished
    echo 'start_all_nodes over'
}

init_mining_dir() {
    cd $CODE_PATH
    echo "init_mining_dir start..."
    local mining_path="./mining_node"
    rm -rf $mining_path
    mkdir -p $mining_path/conf
    mkdir -p $mining_path/log

    cp -rf /root/nodes/seth/pkg/shard_db_3 $mining_path/db
    cp /root/nodes/seth/pkg/GeoLite2-City.mmdb $mining_path/conf/
    cat <<EOF > $mining_path/conf/seth.conf_temp
[db]
path = "./db"

[log]
path = "log/seth.log"

[seth]
bootstrap = ${bootstrap}
prikey = REPLACE_PRIVATE_KEY
local_ip = REPLACE_LOCAL_IP
public_ip = REPLACE_PUBLIC_IP
http_port = 24009
local_port = 14009
net_id = 3
leader_change_init_tm=0
tx_ws_ip = 0.0.0.0
tx_ws_port = 34009
EOF

    echo "Mining directory initialized at $mining_path"
}


killall -9 sshpass
init
make_package
clear_command
scp_package
# get_bootstrap
run_command
init_mining_dir
start_all_nodes
