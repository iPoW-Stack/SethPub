#!/bin/bash
src_path=`pwd`
cd /root/seths/seth && ./seth -U -1 67dfdd4d49509691369225e9059934675dea440d123aa8514441aa6788354016:127.0.0.1:1,356bcb89a431c911f4a57109460ca071701ec58983ec91781a6bd73bde990efe:127.0.0.1:2,a094b020c107852505385271bf22b4ab4b5211e0c50b7242730ff9a9977a77ee:127.0.0.1:2 -2 e154d5e5fc28b7f715c01ca64058be7466141dc6744c89cbcc5284e228c01269:127.0.0.1:3,b16e3d5523d61f0b0ccdf1586aeada079d02ccf15da9e7f2667cb6c4168bb5f0:127.0.0.1:4,0cbc2bc8f999aa16392d3f8c1c271c522d3a92a4b7074520b37d37a4b38db995:127.0.0.1:5
cd /root/seths/seth && ./seth -S -1 67dfdd4d49509691369225e9059934675dea440d123aa8514441aa6788354016:127.0.0.1:1,356bcb89a431c911f4a57109460ca071701ec58983ec91781a6bd73bde990efe:127.0.0.1:2,a094b020c107852505385271bf22b4ab4b5211e0c50b7242730ff9a9977a77ee:127.0.0.1:2 -2 e154d5e5fc28b7f715c01ca64058be7466141dc6744c89cbcc5284e228c01269:127.0.0.1:3,b16e3d5523d61f0b0ccdf1586aeada079d02ccf15da9e7f2667cb6c4168bb5f0:127.0.0.1:4,0cbc2bc8f999aa16392d3f8c1c271c522d3a92a4b7074520b37d37a4b38db995:127.0.0.1:5

cd $src_path
sh ./cmd.sh "ps -ef | grep seth | awk -F' ' '{print $2}' | xargs kill -9"
sh ./cmd.sh "rm  -rf /root/seths/s*/log/*"
sh ./cmd.sh "rm  -rf /root/seths/r*/log/*"
sh ./cmd.sh "rm  -rf /root/seths/s*/db"
sh ./cmd.sh "rm  -rf /root/seths/r*/db"
sh ./cpr.sh /root/seths/seth/root_db /root/seths/r1/db &
sh ./cpr.sh /root/seths/seth/root_db /root/seths/r2/db &
sh ./cpr.sh /root/seths/seth/root_db /root/seths/r3/db &

sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s1/db &
sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s2/db &
sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s3/db &
sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s4/db &
sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s5/db &
sh ./cpr.sh /root/seths/seth/shard_db /root/seths/s6/db &

exit 0
cd /root/seths/r1/ && nohup ./seth -f 1 -g 0 &
sleep 3

cd /root/seths/r2/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/r3/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/r4/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/r5/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/r6/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/r7/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s1/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s2/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s3/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s4/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s5/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s6/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s7/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s8/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s9/ && nohup ./seth -f 0 -g 0 &
#cd /root/seths/s10/ && nohup ./seth -f 0 -g 0 &

exit 0
cd /root/n2 &&  rm -rf db ./log/* && nohup ./zjc2 -f 0 -g 0 &
cd /root/n3 &&  rm -rf db ./log/* && nohup ./zjc3 -f 0 -g 0 &
cd /root/n4 &&  rm -rf db ./log/* && nohup ./zjc4 -f 0 -g 0 &
sleep 3
cd /root/seths/s11/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s12/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s13/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s14/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s15/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s16/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s17/ && nohup ./seth -f 0 -g 0 &
cd /root/seths/s18/ && nohup ./seth -f 0 -g 0 &
