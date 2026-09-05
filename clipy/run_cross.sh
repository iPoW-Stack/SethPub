#!/bin/bash
# 用法: bash run_cross.sh [HOST_IP]
# 每次运行自动递增 SALT，强制部署新合约
PY=/root/seth/clipy/test_crossshardbase.py
PYTHON=/root/tools/python3.10/bin/python3

HOST="${1:-192.168.25.129}"

# 读取当前 SALT
CUR=$(grep -oP "SALT = \K[0-9]+" $PY | head -1)
NEW=$((CUR + 1))

# 更新 SALT
$PYTHON -c "
import re
with open(\"$PY\") as f: c = f.read()
c = re.sub(r\"SALT = [0-9]+\", \"SALT = $NEW\", c, count=1)
with open(\"$PY\", \"w\") as f: f.write(c)
"
echo "SALT: $CUR -> $NEW"
echo "HOST: $HOST"
SETH_HOST="$HOST" $PYTHON $PY
