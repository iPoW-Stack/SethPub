each_nodes_count=$1
node_ips=$2
bootstrap=""
end_shard=3
TARGET=Release
FIRST_NODE_COUNT=$1
if [ "$TARGET" == "" ]; then
    TARGET=Debug
fi

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
    cd /root/seth/ && bash build.sh a Release
    cp -rf /root/seth/temp_cmd.sh /root/seth/cbuild_$TARGET
    cd /root/seth/cbuild_$TARGET && tar -zcvf seth.tar.gz ./seth ./temp_cmd.sh
}

get_bootstrap() {
    rm -rf /root/seth/shards2
    cp -rf /root/seth/root_nodes /root/seth/shards2
    node_ips_array=(${node_ips//,/ })
    for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
        i=1
        for ip in "${node_ips_array[@]}"; do
            tmppubkey=`sed -n "$i""p" /root/seth/shards$shard_id| awk -F'\t' '{print $2}'`
            node_info=$tmppubkey":"$ip":1"$shard_id"00"$i
            bootstrap=$node_info","$bootstrap
            i=$((i+1))
            if ((i>=10)); then
                break
            fi
        done
    done
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
        sshpass  ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root && rm -rf pkg; rm -rf seths; killall -9 seth" &
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
        sshpass  scp -o ConnectTimeout=10  -o StrictHostKeyChecking=no /root/seth/cbuild_$TARGET/seth.tar.gz root@$ip:/root &
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
    nodes_count=0
    for ip in "${node_ips_array[@]}"; do
        nodes_count=$(($nodes_count + $each_nodes_count))
    done

    for ip in "${node_ips_array[@]}"; do
        echo "start node: " $ip $each_nodes_count
        start_nodes_count=$(($each_nodes_count + 0))
        if ((start_pos==1)); then
            start_nodes_count=$FIRST_NODE_COUNT
        fi

        sshpass  ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root && tar -zxvf $nodes_count.tar.gz && tar -zxvf seth.tar.gz && cp -rf ./seth ./pkg && cp -rf ./temp_cmd.sh ./pkg && cd ./pkg && bash temp_cmd.sh $ip $start_pos $start_nodes_count $bootstrap 2 $end_shard"  > /dev/null 2>&1 &
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
        echo "start node: " $ip $each_nodes_count
        start_nodes_count=$(($each_nodes_count + 0))
        if ((start_pos==1)); then
            start_nodes_count=$FIRST_NODE_COUNT
        fi

        sshpass  ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/pkg && bash start_cmd.sh $ip $start_pos $start_nodes_count $bootstrap 2 $end_shard "  &
        if ((start_pos==1)); then
            sleep 3
        fi

        sleep 0.1
        start_pos=$(($start_pos+$start_nodes_count))
    done

    check_cmd_finished
    echo 'start_all_nodes over'
}

killall -9 sshpass
init
clear_command
scp_package
get_bootstrap
echo $bootstrap
run_command
start_all_nodes
