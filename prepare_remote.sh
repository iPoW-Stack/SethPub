each_nodes_count=$1
node_ips=$2
bootstrap=""
end_shard=$3
PASSWORD=$4
TARGET=$5

init() {
    if [ "$node_ips" == "" ]; then
        echo "just use local single node."
        node_ips='127.0.0.1'
    fi  

    if [ "$end_shard" == "" ]; then
        end_shard=3
    fi  

    if [ "$PASSWORD" == "" ]; then
        PASSWORD="Xf4aGbTaf!"
    fi

    if [ "$TARGET" == "" ]; then
        TARGET=Release
    fi

    killall -9 seth
    killall -9 txcli

    sudo rm -rf /root/seths
    sudo cp -rf ./seths_local /root/seths
    rm -rf /root/seths/*/seth /root/seths/*/core* /root/seths/*/log/* /root/seths/*/*db*

    cp -rf ./seths_local/seth/GeoLite2-City.mmdb /root/seths/seth
    cp -rf ./seths_local/seth/conf/log4cpp.properties /root/seths/seth/conf
    mkdir -p /root/seths/seth/log


    sudo cp -rf ./cbuild_$TARGET/seth /root/seths/seth
    if [[ "$each_nodes_count" -eq "" ]]; then
        each_nodes_count=4 
    fi

    node_ips_array=(${node_ips//,/ })
    nodes_count=0
    for ip in "${node_ips_array[@]}"; do
        nodes_count=$(($nodes_count + $each_nodes_count))
    done

    shard3_node_count=`wc -l /root/seth/shards3 | awk -F' ' '{print $1}'`
    if [ "$shard3_node_count" != "$nodes_count" ]; then
        echo "new shard nodes file will create."
        rm -rf /root/seth/shards*
    fi  

    echo "node count: " $nodes_count
    cd /root/seths/seth && ./seth -U -N $nodes_count
    cd /root/seths/seth && ./seth -S 3 -N $nodes_count

    rm -rf /root/seths/r*
    rm -rf /root/seths/s*
    rm -rf /root/seths/new*
    rm -rf /root/seths/node
    rm -rf /root/seths/param
}

make_package() {
    rm -rf /root/seths/seth/pkg
    mkdir /root/seths/seth/pkg
    cp /root/seths/seth/seth /root/seths/seth/pkg
    cp /root/seths/seth/conf/GeoLite2-City.mmdb /root/seths/seth/pkg
    cp /root/seths/seth/conf/log4cpp.properties /root/seths/seth/pkg
    cp /root/seth/shards3 /root/seths/seth/pkg
    cp /root/seth/root_nodes /root/seths/seth/pkg/shards2
    cp /root/seth/temp_cmd.sh /root/seths/seth/pkg
    cp /root/seth/start_cmd.sh /root/seths/seth/pkg
    cp -rf /root/seths/seth/root_db /root/seths/seth/pkg/shard_db_2
    cp -rf /root/seths/seth/shard_db_3 /root/seths/seth/pkg
    cp -rf /root/seths/temp /root/seths/seth/pkg
    cd /root/seths/seth/ && tar -zcvf pkg.tar.gz ./pkg > /dev/null 2>&1
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

    ps -ef | grep sshpass | grep ConnectTimeout
    echo "waiting ok"
}


clear_command() {
    echo 'run_command start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    start_pos=1
    for ip in "${node_ips_array[@]}"; do 
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root && rm -rf pkg*" &
        run_cmd_count=$((run_cmd_count + 1))
        if ((start_pos==1)); then
            sleep 3
        fi

        if (($run_cmd_count >= 1)); then
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
        sshpass -p $PASSWORD scp -o StrictHostKeyChecking=no /root/seths/seth/pkg.tar.gz root@$ip:/root &
        run_cmd_count=$((run_cmd_count + i))
        if [ $run_cmd_count -ge 10 ]; then
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
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root && tar -zxvf pkg.tar.gz > /dev/null 2>&1 && cd ./pkg && sh temp_cmd.sh $ip $start_pos $each_nodes_count $bootstrap 2 $end_shard" &
        run_cmd_count=$((run_cmd_count + 1))
        if ((start_pos==1)); then
            sleep 3
        fi

        if (($run_cmd_count >= 100)); then
            check_cmd_finished
            run_cmd_count=0
        fi
        start_pos=$(($start_pos+$each_nodes_count))
    done

    check_cmd_finished
    echo 'run_command over'
}

start_all_nodes() {
    echo 'start_all_nodes start'
    node_ips_array=(${node_ips//,/ })
    run_cmd_count=0
    start_pos=1
    for ip in "${node_ips_array[@]}"; do
        echo "start node: " $ip 
        sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root && tar -zxvf pkg.tar.gz > /dev/null 2>&1 && cd ./pkg && sh start_cmd.sh $ip $start_pos $each_nodes_count $bootstrap 2 $end_shard &"  &
        run_cmd_count=$((run_cmd_count + 1))
        if ((start_pos==1)); then
            sleep 3
        fi

        if (($run_cmd_count >= 100)); then
            check_cmd_finished
            run_cmd_count=0
        fi
        start_pos=$(($start_pos+$each_nodes_count))
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
