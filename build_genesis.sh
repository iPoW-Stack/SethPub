
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
	sudo mv -f /root/seths/seth /mnt/
else
	sudo mv -f /root/seths/seth /mnt/
fi

sudo rm -rf /root/seths
sudo cp -rf ./seths /root
sudo cp -rf ./deploy /root
sudo cp ./fetch.sh /root
rm -rf /root/seths/*/seth /root/seths/*/core* /root/seths/*/log/* /root/seths/*/*db*

if [ $NO_BUILD = "nobuild" -o $NO_BUILD = "noblock" ]
then
	sudo rm -rf /root/seths/seth
	sudo mv -f /mnt/seth /root/seths/
fi
root=("r1" "r2" "r3")
shard3=("s3_1" "s3_2" "s3_3" "s3_4")
nodes=("r1" "r2" "r3" "s3_1" "s3_2" "s3_3" "s3_4")

for node in "${nodes[@]}"; do
    mkdir -p "/root/seths/${node}/log"
    # cp -rf ./seths/seth/GeoLite2-City.mmdb /root/seths/${node}/conf
    # cp -rf ./seths/seth/conf/log4cpp.properties /root/seths/${node}/conf
done
cp -rf ./seths/seth/GeoLite2-City.mmdb /root/seths/seth
cp -rf ./seths/seth/conf/log4cpp.properties /root/seths/seth/conf
mkdir -p /root/seths/seth/log


sudo cp -rf ./cbuild_$TARGET/seth /root/seths/seth
sudo cp -f ./conf/genesis.yml /root/seths/seth/genesis.yml

# for node in "${nodes[@]}"; do
    # sudo cp -rf ./cbuild_$TARGET/seth /root/seths/${node}
# done
sudo cp -rf ./cbuild_$TARGET/seth /root/seths/seth


if test $NO_BUILD = 0
then
    cd /root/seths/seth && ./seth -U
    cd /root/seths/seth && ./seth -S 3
    
fi

#for node in "${root[@]}"; do
#	cp -rf /root/seths/seth/root_db /root/seths/${node}/db
#done


#for node in "${shard3[@]}"; do
#	cp -rf /root/seths/seth/shard_db_3 /root/seths/${node}/db
#done


# 压缩 seths/seth，便于网络传输

clickhouse-client -q "drop table zjc_ck_account_key_value_table"
clickhouse-client -q "drop table zjc_ck_account_table"
clickhouse-client -q "drop table zjc_ck_block_table"
clickhouse-client -q "drop table zjc_ck_statistic_table"
clickhouse-client -q "drop table zjc_ck_transaction_table"
clickhouse-client -q "drop table bls_elect_info"
clickhouse-client -q "drop table bls_block_info"

killall -9 txcli
