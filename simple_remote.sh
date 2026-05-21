each_nodes_count=${1:-}
node_ips=${2:-}
bootstrap=""
end_shard=${3:-}
PASSWORD=${4:-}
TARGET=${5:-}
FIRST_NODE_COUNT="$each_nodes_count"
NODE_SSH_PORT="${SETH_REMOTE_NODE_SSH_PORT:-${SETH_REMOTE_SSH_PORT:-22}}"
REMOTE_FAIL_FILE="/tmp/seth_remote_fail.$$"
export SETH_REMOTE_SSH_PORT="$NODE_SSH_PORT"
export SETH_REMOTE_PASSWORD="${PASSWORD:-${SETH_REMOTE_PASSWORD:-}}"
export REMOTE_FAIL_FILE
REMOTE_PIDS=()

CODE_PATH=`pwd`
node_ips_array=(${node_ips//,/ })
nodes_count=0
for ip in "${node_ips_array[@]}"; do
    nodes_count=$(($nodes_count + $each_nodes_count))
done
node_hash=$(printf "%d%d" "$nodes_count" "$each_nodes_count" | md5sum | cut -d ' ' -f1)

record_remote_failure() {
    echo "$1" >> "$REMOTE_FAIL_FILE"
}

check_remote_failures() {
    if [ -s "$REMOTE_FAIL_FILE" ]; then
        cat "$REMOTE_FAIL_FILE" >&2
        rm -f "$REMOTE_FAIL_FILE"
        exit 1
    fi
}

is_local_ip() {
    local ip="$1"
    if [ "$ip" = "localhost" ] || [ "$ip" = "127.0.0.1" ]; then
        return 0
    fi
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -Fxq "$ip"
}

all_nodes_local() {
    local current_node_ips_array=(${node_ips//,/ })
    local ip
    for ip in "${current_node_ips_array[@]}"; do
        if ! is_local_ip "$ip"; then
            return 1
        fi
    done
    return 0
}

run_on_node() {
    local ip="$1"
    local command="$2"
    if is_local_ip "$ip"; then
        bash -lc "$command"
    else
        sshpass -p "$PASSWORD" ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 \
            root@$ip -p "$NODE_SSH_PORT" "$command"
    fi
}

copy_to_node() {
    local ip="$1"
    local src="$2"
    local dest="$3"
    if is_local_ip "$ip"; then
        cp -f "$src" "$dest"
    else
        sshpass -p "$PASSWORD" scp -P "$NODE_SSH_PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
            "$src" root@$ip:"$dest"
    fi
}

wait_remote_pids() {
    local status=0
    local pid
    for pid in "${REMOTE_PIDS[@]}"; do
        wait "$pid" || status=1
    done
    REMOTE_PIDS=()
    check_remote_failures
    if [ "$status" -ne 0 ]; then
        exit "$status"
    fi
}

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
        node_ips='10.10.1.115'
    fi

    bash cmd.sh $node_ips "tc qdisc del dev eth0 root"  > /dev/null 2>&1 &
    if [ "$end_shard" == "" ]; then
        end_shard=3
    fi

    if [ "$PASSWORD" == "" ] && ! all_nodes_local; then
        echo "remote node password is required when node_host is not local" >&2
        exit 1
    fi
    export SETH_REMOTE_PASSWORD="$PASSWORD"

    if [ "$TARGET" == "" ]; then
        TARGET=Debug
    fi

    killall -9 seth
    killall -9 txcli

    bash build.sh seth $TARGET
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
        cd /root/seth/ && bash build.sh seth $TARGET
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
    wait_remote_pids
    echo "waiting ok"
}


clear_command() {
    echo 'clear_command start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    start_pos=1
    for ip in "${node_ips_array[@]}"; do
        (
            run_on_node "$ip" "cd /root && rm -rf pkg* && (killall -9 seth 2>/dev/null || true)" ||
                record_remote_failure "clear command failed on $ip:$NODE_SSH_PORT"
        ) &
        REMOTE_PIDS+=($!)
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
    echo 'clear_command over'
}

scp_package() {
    echo 'scp_package start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    for ip in "${node_ips_array[@]}"; do
        (
            copy_to_node "$ip" "/root/nodes/seth/pkg.tar.gz" "/root/pkg.tar.gz" ||
                record_remote_failure "scp package failed on $ip:$NODE_SSH_PORT"
        ) &
        REMOTE_PIDS+=($!)
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

        leader_init_tm=$(date -u -d "+240 days" +%s)
        (
            run_on_node "$ip" "cd /root && tar -zxvf pkg.tar.gz && cd ./pkg && bash temp_cmd.sh $ip $start_pos $start_nodes_count 0 2 $end_shard $leader_init_tm " ||
                record_remote_failure "temp command failed on $ip:$NODE_SSH_PORT"
        ) &
        REMOTE_PIDS+=($!)
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

        (
            run_on_node "$ip" "cd /root/pkg && bash start_cmd.sh $ip $start_pos $start_nodes_count 0 2 $end_shard " ||
                record_remote_failure "start command failed on $ip:$NODE_SSH_PORT"
        ) &
        REMOTE_PIDS+=($!)
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
