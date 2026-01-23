local_ip=$1
start_pos=$2
node_count=$3
bootstrap=$4
start_shard=$5
end_shard=$6
TEST_TX_TPS=5000
TEST_TX_MAX_POOL_INDEX=1

echo "new node: $local_ip $start_pos $node_count $start_shard $end_shard"
rm -rf /root/seths/
mkdir -p /root/seths/


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
            sed -i 's/LOCAL_IP/'$local_ip'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            sed -i 's/BOOTSTRAP/'$bootstrap'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            if ((i<=TEST_TX_MAX_POOL_INDEX)); then
                sed -i 's/TEST_POOL_INDEX/'$(($i-1))'/g' /root/seths/s3_$i/conf/seth.conf
            else
                sed -i 's/TEST_POOL_INDEX/-1/g' /root/seths/s3_$i/conf/seth.conf
            fi

            sed -i 's/TEST_TX_TPS/'$TEST_TX_TPS'/g' /root/seths/s3_$i/conf/seth.conf

            if ((i>=100)); then
                sed -i 's/HTTP_PORT/2'$shard_id''$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
                sed -i 's/LOCAL_PORT/1'$shard_id''$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
            elif ((i>=10)); then
                sed -i 's/HTTP_PORT/2'$shard_id'0'$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
                sed -i 's/LOCAL_PORT/1'$shard_id'0'$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf 
            else
                sed -i 's/HTTP_PORT/2'$shard_id'00'$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf
                sed -i 's/LOCAL_PORT/1'$shard_id'00'$i'/g' /root/seths/s$shard_id'_'$i/conf/seth.conf 
            fi

            echo /root/seths/s$shard_id'_'$i/seth
            ln /root/pkg/seth /root/seths/s$shard_id'_'$i/seth
            ln /root/pkg/txcli /root/seths/s$shard_id'_'$i/txcli
            ln /root/pkg/GeoLite2-City.mmdb /root/seths/s$shard_id'_'$i/conf/GeoLite2-City.mmdb
            ln /root/pkg/log4cpp.properties /root/seths/s$shard_id'_'$i/conf/log4cpp.properties
            mkdir -p /root/seths/s$shard_id'_'$i/log
            cp -rf /root/pkg/shard_db_$shard_id /root/seths/s$shard_id'_'$i/db
        done
    done
}


killall -9 seth

deploy_nodes
