#!/bin/bash
set -e
SHARDORA=/root/shardora/cbuild_Release/shardora
NODES_DIR=/root/nodes/shardora
END_SHARD=4
PUBLIC_IP=127.0.0.1

echo "=== Building pkg ==="
rm -rf $NODES_DIR/pkg
mkdir -p $NODES_DIR/pkg

cp $SHARDORA $NODES_DIR/pkg/shardora
chmod +x $NODES_DIR/pkg/shardora
cp $NODES_DIR/conf/GeoLite2-City.mmdb $NODES_DIR/pkg/ 2>/dev/null || true
cp $NODES_DIR/conf/log4cpp.properties $NODES_DIR/pkg/ 2>/dev/null || true

# encrypt shards -> pkg/shards*, copy init_accounts
for s in 2 3 4; do
  $SHARDORA -A $NODES_DIR/shards$s -D $NODES_DIR/pkg/shards$s
  cp $NODES_DIR/shards$s $NODES_DIR/pkg/init_accounts$s
  cp -r $NODES_DIR/shard_db_$s $NODES_DIR/pkg/shard_db_$s
done

# copy temp conf template and scripts
cp -rf /root/shardora/nodes_local/temp $NODES_DIR/pkg/temp
cp /root/shardora/temp_cmd.sh $NODES_DIR/pkg/temp_cmd.sh
cp /root/shardora/start_cmd.sh $NODES_DIR/pkg/start_cmd.sh

echo "=== Building bootstrap ==="
bootstrap=""
for s in 2 3 4; do
  for i in $(seq 1 4); do
    pubkey=$(sed -n "${i}p" $NODES_DIR/pkg/shards$s | awk -F'\t' '{print $2}')
    if [ $i -ge 100 ]; then
      port="1${s}${i}"
    elif [ $i -ge 10 ]; then
      port="1${s}0${i}"
    else
      port="1${s}00${i}"
    fi
    node_info="${pubkey}:${PUBLIC_IP}:${port}:${s}"
    if [ -z "$bootstrap" ]; then
      bootstrap="$node_info"
    else
      bootstrap="${bootstrap},${node_info}"
    fi
  done
done
echo "bootstrap built (length=${#bootstrap})"

# substitute into conf template
python3 - "$NODES_DIR/pkg/temp/conf/shardora.conf" "$bootstrap" << 'PY'
import sys
path, bs = sys.argv[1], sys.argv[2]
with open(path) as f: content = f.read()
content = content.replace('BOOTSTRAP', bs)
content = content.replace('FOR_CK_CLIENT', 'false')
with open(path, 'w') as f: f.write(content)
print("conf substituted ok")
PY

# verify no leftover placeholders
if grep -qE 'BOOTSTRAP|FOR_CK_CLIENT' $NODES_DIR/pkg/temp/conf/shardora.conf; then
  echo "ERROR: placeholder remains in shardora.conf" >&2; exit 1
fi

echo "=== pkg ready ==="
ls $NODES_DIR/pkg/
echo PKG_DONE
