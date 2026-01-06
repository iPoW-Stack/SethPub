#!/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/gcc-8.3.0/lib64/
ps -ef | grep seth | grep new_node | awk -F' ' '{print $2}' | xargs kill -9

nodes=("new_1" "new_2" "new_3" "new_4" "new_5" "new_6" "new_7" "new_8" "new_9" "new_10")


rm -rf /root/seths/new*
# (python test_accounts.py )&
for n in  "${nodes[@]}"; do

        mkdir -p "/root/seths/${n}/log"
        mkdir -p "/root/seths/${n}/conf"
        ln -s /root/seths/seth/GeoLite2-City.mmdb /root/seths/${n}/conf/
        ln -s /root/seths/seth/conf/log4cpp.properties /root/seths/${n}/conf/
        ln -s /root/seths/seth/seth /root/seths/${n}/
        cp -rf ./seths/${n}/conf/seth.conf /root/seths/${n}/conf/seth.conf
        echo "cp $n"
done

ulimit -c unlimited


for node in "${nodes[@]}"; do
  cd /root/seths/$node/ && nohup ./seth -f 0 -g 0 $node new_node> /dev/null 2>&1 &
  echo "start $node"

done



