
#!/bin/bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/gcc-8.3.0/lib64/

# $1 = Debug/Release
TARGET=Release
if test $1 = "Debug"
then
    TARGET=Debug
fi

# nobuild: no build & no genesis block
# noblock: build & no genesis block
NO_BUILD=0
if [ -n $2 ] && [ $2 = "nobuild" ]
then
    NO_BUILD="nobuild"
fi

if [ -n $2 ] && [ $2 = "noblock" ]
then
    NO_BUILD="noblock"
fi

if test $NO_BUILD = 0
then
	sh build.sh a $TARGET	
elif test $NO_BUILD = "noblock"
then
	sh build.sh a $TARGET
	sudo mv -f /root/zjnodes/seth /mnt/
else
	sudo mv -f /root/zjnodes/seth /mnt/
fi

sudo rm -rf /root/zjnodes
sudo cp -rf ./zjnodes /root
sudo cp -rf ./deploy /root
sudo cp ./fetch.sh /root
rm -rf /root/zjnodes/*/seth /root/zjnodes/*/core* /root/zjnodes/*/log/* /root/zjnodes/*/*db*

if [ $NO_BUILD = "nobuild" -o $NO_BUILD = "noblock" ]
then
	sudo rm -rf /root/zjnodes/seth
	sudo mv -f /mnt/seth /root/zjnodes/
fi
root=("r1" "r2" "r3")
shard3=("s3_1" "s3_2" "s3_3" "s3_4")
nodes=("r1" "r2" "r3" "s3_1" "s3_2" "s3_3" "s3_4")

for node in "${nodes[@]}"; do
    mkdir -p "/root/zjnodes/${node}/log"
    # cp -rf ./zjnodes/seth/GeoLite2-City.mmdb /root/zjnodes/${node}/conf
    # cp -rf ./zjnodes/seth/conf/log4cpp.properties /root/zjnodes/${node}/conf
done
cp -rf ./zjnodes/seth/GeoLite2-City.mmdb /root/zjnodes/seth
cp -rf ./zjnodes/seth/conf/log4cpp.properties /root/zjnodes/seth/conf
mkdir -p /root/zjnodes/seth/log


sudo cp -rf ./cbuild_$TARGET/seth /root/zjnodes/seth
sudo cp -f ./conf/genesis.yml /root/zjnodes/seth/genesis.yml

# for node in "${nodes[@]}"; do
    # sudo cp -rf ./cbuild_$TARGET/seth /root/zjnodes/${node}
# done
sudo cp -rf ./cbuild_$TARGET/seth /root/zjnodes/seth


if test $NO_BUILD = 0
then
    cd /root/zjnodes/seth && ./seth -U
    cd /root/zjnodes/seth && ./seth -S 3
    
fi

#for node in "${root[@]}"; do
#	cp -rf /root/zjnodes/seth/root_db /root/zjnodes/${node}/db
#done


#for node in "${shard3[@]}"; do
#	cp -rf /root/zjnodes/seth/shard_db_3 /root/zjnodes/${node}/db
#done


# 压缩 zjnodes/seth，便于网络传输

clickhouse-client -q "drop table zjc_ck_account_key_value_table"
clickhouse-client -q "drop table zjc_ck_account_table"
clickhouse-client -q "drop table zjc_ck_block_table"
clickhouse-client -q "drop table zjc_ck_statistic_table"
clickhouse-client -q "drop table zjc_ck_transaction_table"
clickhouse-client -q "drop table bls_elect_info"
clickhouse-client -q "drop table bls_block_info"

killall -9 txcli
