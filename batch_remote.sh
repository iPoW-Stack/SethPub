each_nodes_count=$1
node_ips=$2
bootstrap=""
end_shard=$3
PASSWORD=$4
TARGET=$5

CODE_PATH=`pwd`
node_hash=$(printf "%s%d" "$node_ips" "$each_nodes_count" | md5sum | cut -d ' ' -f1)

bash cmd.sh $2 "systemctl list-units --state=active --no-legend | grep seth@ | awk '{print \$1}' | xargs -r systemctl stop; killall -9 seth"
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
   
    if [ "$PASSWORD" == "" ]; then
        PASSWORD="Xf4aGbTaf&"
    fi

    if [ "$TARGET" == "" ]; then
        TARGET=Debug
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

    if [ "$end_shard" == "" ]; then
        end_shard=3
    fi

    start_shard=2
    total_shards=$((end_shard - start_shard + 1))
    node_ips_array=(${node_ips//,/ })
    total_ips=${#node_ips_array[@]}
    declare -A shard_map
    for ((i=0; i<$total_ips; i++)); do
        shard_idx=$((i % total_shards))
        current_shard=$((shard_idx + start_shard))
        shard_map[$current_shard]+="${node_ips_array[$i]} "
    done

    nodes_count=$(((total_ips / total_shards) * 10))
    echo "node count: " $nodes_count $node_ips $shard_map
    rm -rf /root/nodes/seth/latest_blocks
}

make_package() {
    mkdir -p /root/seth/pkgs
    rm -rf /root/nodes/seth/pkg
    if [ -d "/root/seth/pkgs/$node_hash" ]; then
        cd /root/seth/ && bash build.sh a $TARGET
        cd /root/seth/cbuild_$TARGET && make txcli
        cp -rf /root/seth/cbuild_$TARGET/seth /root/seth/pkgs/$node_hash/seth
        cp -rf /root/seth/pkgs/$node_hash /root/nodes/seth/pkg
        for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
            /root/seth/cbuild_$TARGET/seth -A /root/seth/shards${shard_id} -D /root/nodes/seth/pkg/shards${shard_id}
            /root/seth/cbuild_$TARGET/seth -A  /root/seth/init_accounts${shard_id} -D /root/nodes/seth/pkg/init_accounts${shard_id}
        done
    else
        end_shard_index=$((end_shard + 1))
        echo "./seth -U -N ${nodes_count} -E ${end_shard_index}"
        echo "./seth -S 3 -N ${nodes_count} -E ${end_shard_index}"
        cd /root/nodes/seth && ./seth -U -N ${nodes_count} -E ${end_shard_index}
        cd /root/nodes/seth && ./seth -S 3 -N ${nodes_count} -E ${end_shard_index}
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
        cp -rf /root/nodes/seth/shard_db* /root/nodes/seth/pkg/
        cp -rf /root/nodes/temp /root/nodes/seth/pkg
        cp -rf /root/seth/gdb/* /root/nodes/seth/pkg
        cp -rf /root/nodes/seth/pkg /root/seth/pkgs/$node_hash
    fi

    cd /root/nodes/seth/ && tar -zcvf pkg.tar.gz ./pkg > /dev/null 2>&1
}

get_bootstrap() {
    node_ips_array=(${node_ips//,/ })
    for ((shard_id=2; shard_id<=$end_shard; shard_id++)); do
        i=1
        for ip in "${node_ips_array[@]}"; do
            tmppubkey=`sed -n "$i""p" /root/nodes/seth/pkg/shards${shard_id} | awk -F'\t' '{print $2}'`
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
    for ((shard_id=start_shard; shard_id<=$end_shard; shard_id++)); do
        ips=(${shard_map[$shard_id]})
        for ip in "${ips[@]}"; do
            sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$ip  "cd /root && rm -rf pkg*; killall -9 seth" &
            run_cmd_count=$((run_cmd_count + 1))
            if (($run_cmd_count >= 250)); then
                check_cmd_finished
                run_cmd_count=0
            fi
        done
    done

    check_cmd_finished
    echo 'run_command over'
}

scp_package() {
    echo 'scp_package start'
    run_cmd_count=0
    for ((shard_id=start_shard; shard_id<=$end_shard; shard_id++)); do
        ips=(${shard_map[$shard_id]})
        echo 'run_cstart_ascp_packagell_nodesommand: ' $shard_id $ips
        for ip in "${ips[@]}"; do
            echo "scp_package: " $ip
            sshpass -p $PASSWORD scp -o ConnectTimeout=10  -o StrictHostKeyChecking=no /root/nodes/seth/pkg.tar.gz root@$ip:/root &
            run_cmd_count=$((run_cmd_count + 1))
            if (($run_cmd_count >= 100)); then
                check_cmd_finished
                run_cmd_count=0
            fi
        done
    done

    check_cmd_finished
    echo 'scp_package over'
}

run_command() {
    echo 'run_command start'
    run_cmd_count=0
    for ((shard_id=start_shard; shard_id<=$end_shard; shard_id++)); do
        start_pos=1
        ips=(${shard_map[$shard_id]})
        echo 'run_command: ' $shard_id $ips
        for ip in "${ips[@]}"; do
            echo "config node: " $ip $each_nodes_count
            start_nodes_count=$(($each_nodes_count + 0))
            leader_init_tm=$(date -u -d "+240 seconds" +%s)
            echo 'sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$ip "cd /root && tar -zxvf pkg.tar.gz && cd ./pkg && bash temp_cmd.sh $ip $start_pos $start_nodes_count $bootstrap $shard_id $(($shard_id+1)) $leader_init_tm"'
            sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$ip "cd /root && tar -zxvf pkg.tar.gz && cd ./pkg && bash temp_cmd.sh $ip $start_pos $start_nodes_count $bootstrap $shard_id $(($shard_id+1)) $leader_init_tm"  > /dev/null 2>&1 &
            run_cmd_count=$(($run_cmd_count + 1))
            if (($run_cmd_count >= 250)); then
                check_cmd_finished
                run_cmd_count=0
            fi
            start_pos=$(($start_pos+$start_nodes_count))
        done
    done

    check_cmd_finished
    echo 'run_command over'
}

start_all_nodes() {
    echo 'start_all_nodes start'
    for ((shard_id=start_shard; shard_id<=$end_shard; shard_id++)); do
        start_pos=1
        ips=(${shard_map[$shard_id]})
        echo 'run_cstart_all_nodesommand: ' $shard_id $ips
        for ip in "${ips[@]}"; do
            echo "start node: " $ip $each_nodes_count
            start_nodes_count=$(($each_nodes_count + 0))
            echo 'sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$ip "cd /root/pkg && bash start_cmd.sh $ip $start_pos $start_nodes_count $bootstrap $shard_id $(($shard_id+1)) "'
            sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$ip "cd /root/pkg && bash start_cmd.sh $ip $start_pos $start_nodes_count $bootstrap $shard_id $(($shard_id+1)) "  &
            if ((start_pos==1)); then
                sleep 3
            fi

            sleep 0.1
            start_pos=$(($start_pos+$start_nodes_count))
        done
    done
    
    check_cmd_finished
    echo 'start_all_nodes over'
}

killall -9 sshpass
init
make_package
clear_command
scp_package
get_bootstrap
echo $bootstrap
run_command
start_all_nodes