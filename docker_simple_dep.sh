killall -9 seth
killall -9 txcli

TARGET=$2
#VALGRIND='valgrind --log-file=./valgrind_report.log --leak-check=full --show-leak-kinds=all --show-reachable=no --track-origins=yes'
VALGRIND=''
local_ip=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
#sh build.sh a $TARGET
rm -rf /root/seths
cp -rf ./seths_local /root/seths
rm -rf /root/seths/*/seth /root/seths/*/core* /root/seths/*/log/* /root/seths/*/*db*

cp -rf ./seths_local/seth/GeoLite2-City.mmdb /root/seths/seth
cp -rf ./seths_local/seth/conf/log4cpp.properties /root/seths/seth/conf
mkdir -p /root/seths/seth/log


cp -rf ./cbuild_$TARGET/seth /root/seths/seth
nodes_count=$1
if [[ "$nodes_count" -eq "" ]]; then
   nodes_count=4 
fi
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

shard3_node_count=`wc -l /root/seth/shards3 | awk -F' ' '{print $1}'`
root_node_count=`wc -l /root/seth/root_nodes | awk -F' ' '{print $1}'`
bootstrap=""
echo $shard3_node_count $root_node_count
for ((i=1; i<=$root_node_count;i++)); do
    tmppubkey=`sed -n "$i""p" /root/seth/root_nodes | awk -F'\t' '{print $2}'`
    node_info=$tmppubkey":"$local_ip":1200"$i
    bootstrap=$node_info","$bootstrap
done

for ((i=1; i<=3;i++)); do
    tmppubkey=`sed -n "$i""p" /root/seth/shards3| awk -F'\t' '{print $2}'`
    node_info=$tmppubkey":"$local_ip":1300"$i
    bootstrap=$node_info","$bootstrap
done

echo $bootstrap
for ((i=1; i<=$root_node_count;i++)); do
    prikey=`sed -n "$i""p" /root/seth/root_nodes | awk -F'\t' '{print $1}'`
    pubkey=`sed -n "$i""p" /root/seth/root_nodes | awk -F'\t' '{print $2}'`
    echo $prikey
    cp -rf /root/seths/temp /root/seths/r$i
    sed -i 's/PRIVATE_KEY/'$prikey'/g' /root/seths/r$i/conf/seth.conf
    sed -i 's/LOCAL_PORT/1200'$i'/g' /root/seths/r$i/conf/seth.conf
    sed -i 's/BOOTSTRAP/'$bootstrap'/g' /root/seths/r$i/conf/seth.conf
    sed -i 's/HTTP_PORT/'0'/g' /root/seths/r$i/conf/seth.conf
    sed -i 's/LOCAL_IP/'$local_ip'/g' /root/seths/r$i/conf/seth.conf
    ln /root/seths/seth/seth /root/seths/r$i/seth
    ln /root/seths/seth/conf/GeoLite2-City.mmdb /root/seths/r$i/conf/GeoLite2-City.mmdb
    ln /root/seths/seth/conf/log4cpp.properties /root/seths/r$i/conf/log4cpp.properties
    cp -rf /root/seths/seth/root_db /root/seths/r$i/db
    mkdir -p /root/seths/r$i/log
    cd /root/seths/r$i/ && nohup ./seth -f 0 -g 0 r$i &
    if [ $i -eq 1 ];then
        echo "first node waiting..."
        sleep 3
    fi
done


for ((i=1; i<=$shard3_node_count;i++)); do
    prikey=`sed -n "$i""p" /root/seth/shards3 | awk -F'\t' '{print $1}'`
    pubkey=`sed -n "$i""p" /root/seth/shards3 | awk -F'\t' '{print $2}'`
    echo $prikey
    cp -rf /root/seths/temp /root/seths/s3_$i
    sed -i 's/PRIVATE_KEY/'$prikey'/g' /root/seths/s3_$i/conf/seth.conf
    sed -i 's/LOCAL_IP/'$local_ip'/g' /root/seths/s3_$i/conf/seth.conf
    sed -i 's/BOOTSTRAP/'$bootstrap'/g' /root/seths/s3_$i/conf/seth.conf
    if ((i>=100)); then
        sed -i 's/HTTP_PORT/23'$i'/g' /root/seths/s3_$i/conf/seth.conf
        sed -i 's/LOCAL_PORT/13'$i'/g' /root/seths/s3_$i/conf/seth.conf
    elif ((i>=10)); then
        sed -i 's/HTTP_PORT/230'$i'/g' /root/seths/s3_$i/conf/seth.conf
        sed -i 's/LOCAL_PORT/130'$i'/g' /root/seths/s3_$i/conf/seth.conf 
    else
        sed -i 's/HTTP_PORT/2300'$i'/g' /root/seths/s3_$i/conf/seth.conf
        sed -i 's/LOCAL_PORT/1300'$i'/g' /root/seths/s3_$i/conf/seth.conf 
    fi

    ln /root/seths/seth/seth /root/seths/s3_$i/seth
    ln /root/seths/seth/conf/GeoLite2-City.mmdb /root/seths/s3_$i/conf/GeoLite2-City.mmdb
    ln /root/seths/seth/conf/log4cpp.properties /root/seths/s3_$i/conf/log4cpp.properties
    mkdir -p /root/seths/s3_$i/log
    cp -rf /root/seths/seth/shard_db_3 /root/seths/s3_$i/db
    cd /root/seths/s3_$i/ && nohup $VALGRIND ./seth -f 0 -g 0 s3_$i &
    sleep 0.3
done
