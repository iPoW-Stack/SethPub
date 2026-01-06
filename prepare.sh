
FIRST_IP=$1
PASSWORD=$2
TARGET=$3
if [ "$TARGET" == "" ]; then
    TARGET=Release
fi

if [ "$PASSWORD" == "" ]; then
    PASSWORD="Xf4aGbTaf!"
fi

killall -9 seth
killall -9 txcli

sh build.sh a $TARGET

rm -rf seth && mkdir seth
mkdir seth
cp -rf ./*.sh ./seth/
mkdir -p ./seth/cbuild_$TARGET
cp -rf cbuild_$TARGET/seth ./seth/cbuild_$TARGET
cp -rf seths_* ./seth/
cp -rf ./shards* ./seth/
cp -rf ./root_nodes ./seth/
cp -rf ./gdb ./seth/
cp -rf ./sshpass ./seth/
cp -rf ./pkg.tar.gz ./seth/
tar -zcvf seth.tar.gz ./seth
        
sshpass -p $PASSWORD scp -o StrictHostKeyChecking=no ./seth.tar.gz root@$FIRST_IP:/root 
sshpass -p $PASSWORD ssh -o ConnectTimeout=3 -o "StrictHostKeyChecking no" -o ServerAliveInterval=5 root@$FIRST_IP "rm -rf /root/seth && cd /root && tar -zxvf ./seth.tar.gz" 
