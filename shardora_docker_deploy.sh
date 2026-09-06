#!/bin/bash
# ============================================================
# Shardora 区块链 Docker 分布式一键编译部署脚本
#
# 功能:
#   1. 本地构建 shardora-builder 编译镜像并编译二进制
#   2. 本地 genesis 初始化，生成 shards/shard_db/pkg
#   3. 生成 bootstrap 字符串，填充 shardora.conf 占位符
#   4. 将 pkg 分发到各远端主机
#   5. 各远端主机为每个节点启动独立 Docker 容器
#   6. 放通 HTTP / TCP / WebSocket 端口
#
# 用法:
#   bash shardora_docker_deploy.sh -H <IP列表> [选项]
#
# 选项:
#   -H HOST_IPS         逗号分隔主机 IP 列表（必填）
#                       单机: -H 192.168.25.129
#                       多机: -H 192.168.25.129,192.168.25.130,...
#   -n NODES_PER_HOST   每台主机每个分片部署的节点数（默认: 4）
#   -s START_SHARD      起始分片 ID（默认: 2）
#   -N SHARD_COUNT      分片总数（默认: 3，即 2/3/4）
#   -p PASSWORD         远端 SSH 密码（默认: 1）
#   -P SSH_PORT         SSH 端口（默认: 22）
#   -r REPO_DIR         shardora p2p 源码目录（使用 -b 时可省略）
#   -R REBUILD          强制重建镜像 0/1（默认: 0）
#   -b SHARDORA_BIN         已有 shardora 二进制路径（跳过编译，直接用此文件做 genesis）
#   -d DATA_DIR         节点数据根目录（默认: /data，容器 volume 挂载此路径下 nodes/）
#   -h                  显示帮助
#
# 示例:
#   # 单机: shard 2-6, 每分片 4 节点, 共 20 容器（使用已有二进制）
#   bash shardora_docker_deploy.sh -H 192.168.25.129 -n 4 -s 2 -N 5 -b /root/shardora/cbuild_Release/shardora
#
#   # 单机: shard 2-4, 每分片 4 节点, 共 12 容器（自动编译）
#   bash shardora_docker_deploy.sh -H 192.168.25.129 -n 4 -s 2 -N 3
#
#   # 20 台主机, 4 个分片(2-5), 每台每分片 4 节点
#   # => 每分片 5台*4节点=20节点, 总节点=80
#   bash shardora_docker_deploy.sh \
#     -H 192.168.25.129,...,192.168.25.148 -n 4 -s 2 -N 4
#
# 分片-主机 round-robin 规则:
#   IP[0]->shard2, IP[1]->shard3, IP[2]->shard4, IP[3]->shard2, ...
#   各分片节点数 = 该分片主机数 * NODES_PER_HOST
#
# 端口规则 (节点编号 i, shard s):
#   TCP  p2p : 1s00i | 1s0i | 1si
#   HTTP rpc : 2s00i | 2s0i | 2si
#   WS       : 3s00i | 3s0i | 3si
#   例: shard=2,i=1 -> 12001/22001/32001
# ============================================================
set -euo pipefail

# ── 默认参数 ─────────────────────────────────────────────────
HOST_IPS=""
NODES_PER_HOST=4
START_SHARD=2
SHARD_COUNT=3
PASSWORD="1"
SSH_PORT=22
REBUILD=0
SHARDORA_BIN=""    # -b: 已有二进制，跳过编译
NODES_DATA_DIR="/data"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/../../p2p"
BUILDER_IMAGE="shardora-builder:latest"
RUNTIME_IMAGE="shardora-runtime:latest"

# ── 参数解析 ─────────────────────────────────────────────────
usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while getopts "H:n:s:N:p:P:r:R:b:d:h" opt; do
    case "$opt" in
        H) HOST_IPS="$OPTARG" ;;
        n) NODES_PER_HOST="$OPTARG" ;;
        s) START_SHARD="$OPTARG" ;;
        N) SHARD_COUNT="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        P) SSH_PORT="$OPTARG" ;;
        r) REPO_DIR="$OPTARG" ;;
        R) REBUILD="$OPTARG" ;;
        b) SHARDORA_BIN="$OPTARG" ;;
        d) NODES_DATA_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -n "$HOST_IPS" ] || { echo "错误: 必须指定 -H HOST_IPS" >&2; usage; }

# 若指定了 -b，验证二进制存在，不需要 REPO_DIR
if [ -n "$SHARDORA_BIN" ]; then
    [ -f "$SHARDORA_BIN" ] || { echo "错误: -b 指定的 shardora 二进制不存在: $SHARDORA_BIN" >&2; exit 1; }
    SHARDORA_BIN="$(cd "$(dirname "$SHARDORA_BIN")" && pwd)/$(basename "$SHARDORA_BIN")"
else
    REPO_DIR="$(cd "$REPO_DIR" 2>/dev/null && pwd)" || {
        echo "错误: p2p 源码目录不存在: $REPO_DIR  (若已有二进制请用 -b)" >&2; exit 1
    }
fi

END_SHARD=$(( START_SHARD + SHARD_COUNT - 1 ))

# 解析 IP 列表
IFS=',' read -ra IP_ARRAY <<< "$HOST_IPS"
TOTAL_HOSTS=${#IP_ARRAY[@]}

# 正确的分片→主机分配:
#   对每个分片槽 i (0..SHARD_COUNT-1)，分配 IP[i % TOTAL_HOSTS]
#   当 TOTAL_HOSTS >= SHARD_COUNT 时：每台主机负责部分分片
#   当 TOTAL_HOSTS < SHARD_COUNT 时：每台主机负责多个分片（含单机多分片）
declare -A SHARD_IPS   # SHARD_IPS[shard_id]="ip1 ip2 ..."
for (( i=0; i<SHARD_COUNT; i++ )); do
    shard_id=$(( START_SHARD + i ))
    ip="${IP_ARRAY[$(( i % TOTAL_HOSTS ))]}"
    SHARD_IPS[$shard_id]+="${ip} "
done

# 各分片节点总数 = 该分片主机数 * NODES_PER_HOST
declare -A SHARD_NODE_COUNT
TOTAL_NODES=0
for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
    hosts_in_shard=( ${SHARD_IPS[$shard_id]:-} )
    cnt=$(( ${#hosts_in_shard[@]} * NODES_PER_HOST ))
    SHARD_NODE_COUNT[$shard_id]=$cnt
    TOTAL_NODES=$(( TOTAL_NODES + cnt ))
done

# Genesis -N 表示每个分片的节点数，不是全集群节点总和
GENESIS_NODE_COUNT=0
for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
    if (( SHARD_NODE_COUNT[$shard_id] > GENESIS_NODE_COUNT )); then
        GENESIS_NODE_COUNT=${SHARD_NODE_COUNT[$shard_id]}
    fi
done

# 汇总打印
echo "============================================================"
echo "  Shardora Docker 分布式部署"
echo "  HOST_IPS       : $HOST_IPS"
echo "  TOTAL_HOSTS    : $TOTAL_HOSTS"
echo "  SHARDS         : $START_SHARD ~ $END_SHARD  (共 $SHARD_COUNT 个)"
echo "  NODES_PER_HOST : $NODES_PER_HOST (每台主机每分片)"
echo "  TOTAL_NODES    : $TOTAL_NODES"
echo "  GENESIS -N     : $GENESIS_NODE_COUNT (每分片节点数)"
echo "  SHARDORA_BIN       : ${SHARDORA_BIN:-（编译）}"
echo "  NODES_DATA_DIR : $NODES_DATA_DIR"
echo "  REPO_DIR       : ${REPO_DIR:-（N/A，使用 -b）}"
echo "  REBUILD        : $REBUILD"
echo ""
for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
    hosts=( ${SHARD_IPS[$shard_id]:-} )
    echo "  Shard $shard_id : ${#hosts[@]} 台主机 / ${SHARD_NODE_COUNT[$shard_id]} 节点"
    echo "           IPs : ${hosts[*]:-（无）}"
done
echo "============================================================"


# ── 工具函数 ─────────────────────────────────────────────────
calc_port() {
    local shard=$1 i=$2 prefix=$3 port
    if   (( i >= 100 )); then port="${prefix}${shard}${i}"
    elif (( i >= 10  )); then port="${prefix}${shard}0${i}"
    else                      port="${prefix}${shard}00${i}"
    fi
    (( port > 65535 )) && port=$(( (port % 60000) + 1024 ))
    echo "$port"
}

# 判断是否本机 IP
is_local() {
    local ip="$1"
    [ "$ip" = "127.0.0.1" ] || [ "$ip" = "localhost" ] && return 0
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -Fxq "$ip"
}

ssh_run() {
    local ip="$1"; shift
    if is_local "$ip"; then
        bash -lc "$*"
    else
        sshpass -p "$PASSWORD" ssh \
            -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
            -o ServerAliveInterval=10 -p "$SSH_PORT" \
            root@"$ip" "$*"
    fi
}

scp_to() {
    local ip="$1" src="$2" dst="$3"
    if is_local "$ip"; then
        cp -f "$src" "$dst"
    else
        sshpass -p "$PASSWORD" scp \
            -P "$SSH_PORT" -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
            "$src" root@"$ip":"$dst"
    fi
}

open_port_on() {
    local ip="$1" port="$2"
    ssh_run "$ip" "
        command -v ufw      >/dev/null 2>&1 && ufw allow ${port}/tcp 2>/dev/null || true
        command -v iptables >/dev/null 2>&1 && {
            iptables -C INPUT -p tcp --dport ${port} -j ACCEPT 2>/dev/null ||
            iptables -I INPUT -p tcp --dport ${port} -j ACCEPT 2>/dev/null || true
        }
    " 2>/dev/null || true
}

PIDS=()
wait_all() {
    local rc=0
    for pid in "${PIDS[@]:-}"; do wait "$pid" || rc=1; done
    PIDS=()
    return $rc
}


# ── Step 1: 构建编译镜像（本地执行）─────────────────────────
step1_build_builder_image() {
    [ -z "$SHARDORA_BIN" ] || { echo "[1/5] 跳过编译镜像（已指定 -b $SHARDORA_BIN）"; return 0; }
    echo ""
    echo "[1/5] 构建编译镜像 $BUILDER_IMAGE ..."
    if [ "$REBUILD" = "0" ] && docker image inspect "$BUILDER_IMAGE" &>/dev/null; then
        echo "  镜像已存在，跳过（-R 1 强制重建）"; return 0
    fi
    local ctx_dir tmpdf
    ctx_dir="$(dirname "$REPO_DIR")"
    tmpdf="$(mktemp /tmp/Dockerfile.builder.XXXXXX)"
    cat > "$tmpdf" << 'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config git curl ca-certificates \
    xxd python3 openssl libssl-dev zlib1g-dev libgmp-dev flex bison bzip2 \
    && rm -rf /var/lib/apt/lists/*
COPY p2p /root/shardora
WORKDIR /root/shardora
RUN bash build.sh shardora Release
CMD ["/bin/bash"]
DOCKERFILE
    docker build --progress=plain -f "$tmpdf" -t "$BUILDER_IMAGE" "$ctx_dir"
    rm -f "$tmpdf"
    echo "  shardora-builder 构建完成"
}

# ── Step 2: 构建运行时镜像（本地执行）───────────────────────
step2_build_runtime_image() {
    echo ""
    echo "[2/5] 构建运行时镜像 $RUNTIME_IMAGE ..."
    if [ "$REBUILD" = "0" ] && docker image inspect "$RUNTIME_IMAGE" &>/dev/null; then
        echo "  镜像已存在，跳过"; return 0
    fi
    local tmpdf tmpctx
    tmpdf="$(mktemp /tmp/Dockerfile.runtime.XXXXXX)"
    tmpctx="$(mktemp -d /tmp/ctx.XXXXXX)"
    cat > "$tmpdf" << 'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 openssl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /node
# INSTANCE 由 --env 传入，值为 s<shard>_<i>
CMD ["/bin/bash", "-c", "exec ./shardora -f 0 -g 0 ${INSTANCE}"]
DOCKERFILE
    docker build --quiet -f "$tmpdf" -t "$RUNTIME_IMAGE" "$tmpctx"
    rm -f "$tmpdf"; rm -rf "$tmpctx"
    echo "  shardora-runtime 构建完成"
}


# ── Step 3: Genesis + 打包 ────────────────────────────────────
# 若 -b 指定了二进制，直接在本地运行 genesis（无需容器）
# 否则在 builder 容器内运行
step3_genesis_and_package() {
    echo ""
    echo "[3/5] Genesis 初始化 + 打包 ..."

    PKG_WORK="/tmp/shardora_pkg_work_$$"
    rm -rf "$PKG_WORK" && mkdir -p "$PKG_WORK"

    if [ -n "$SHARDORA_BIN" ]; then
        # ---- 本地直接 genesis（无需容器）----
        local wdir="$PKG_WORK/genesis_work"
        mkdir -p "$wdir"

        # 拷贝 shardora 所需的辅助文件（conf/、log4cpp、mmdb、temp 目录）
        local shardora_dir; shardora_dir="$(dirname "$SHARDORA_BIN")"
        local shardora_root; shardora_root="$(dirname "$shardora_dir")"  # cbuild_Release 的上层即 p2p 根
        mkdir -p "$wdir/conf"
        [ -d "$shardora_root/nodes_local/shardora/conf" ] && \
            cp -r "$shardora_root/nodes_local/shardora/conf/." "$wdir/conf/" 2>/dev/null || true
        [ -d "$shardora_root/nodes_local/temp" ] && \
            cp -r "$shardora_root/nodes_local/temp" "$wdir/temp" 2>/dev/null || true

        ( cd "$wdir"
          echo "--- genesis -U ---"
          "$SHARDORA_BIN" -U -N "$GENESIS_NODE_COUNT" -E $(( END_SHARD + 1 ))
          echo "--- genesis -S ---"
          "$SHARDORA_BIN" -S 3 -N "$GENESIS_NODE_COUNT" -E $(( END_SHARD + 1 ))
          echo "--- genesis -C ---"
          "$SHARDORA_BIN" -C
        )

        PKG_DIR="$PKG_WORK/pkg"
        mkdir -p "$PKG_DIR"
        cp "$SHARDORA_BIN"                              "$PKG_DIR/shardora"
        chmod +x "$PKG_DIR/shardora"
        [ -f "$wdir/conf/GeoLite2-City.mmdb"   ] && cp "$wdir/conf/GeoLite2-City.mmdb"   "$PKG_DIR/" || true
        [ -f "$wdir/conf/log4cpp.properties"    ] && cp "$wdir/conf/log4cpp.properties"    "$PKG_DIR/" || true
        [ -d "$wdir/temp"                       ] && cp -r "$wdir/temp"                    "$PKG_DIR/temp" || true

        for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
            local sf="$wdir/shards${shard_id}"
            [ -f "$sf" ] || { echo "FATAL: $sf 未生成" >&2; exit 1; }
            "$SHARDORA_BIN" -A "$sf" -D "$PKG_DIR/shards${shard_id}"
            cp    "$sf"                               "$PKG_DIR/init_accounts${shard_id}"
            cp -r "$wdir/shard_db_${shard_id}"        "$PKG_DIR/shard_db_${shard_id}"
        done

    else
        # ---- 容器内 genesis（原逻辑）----
        local gscript="$PKG_WORK/genesis.sh"
        python3 - "$gscript" "$START_SHARD" "$END_SHARD" "$GENESIS_NODE_COUNT" << 'PYEOF'
import sys
gscript, start_shard, end_shard, genesis_nodes = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
lines = [
    "#!/bin/bash", "set -euo pipefail",
    "SHARDORA=/root/shardora/cbuild_Release/shardora",
    "NODES_DIR=/tmp/snodes", "PKG_DIR=/tmp/spkg",
    f"START_SHARD={start_shard}", f"END_SHARD={end_shard}",
    f"GENESIS_NODE_COUNT={genesis_nodes}",
    "",
    'rm -rf "$NODES_DIR" "$PKG_DIR"',
    'mkdir -p "$NODES_DIR/conf" "$NODES_DIR/log" "$PKG_DIR"',
    'cp /root/shardora/nodes_local/shardora/conf/log4cpp.properties "$NODES_DIR/conf/" 2>/dev/null || true',
    'cp /root/shardora/nodes_local/shardora/conf/GeoLite2-City.mmdb "$NODES_DIR/conf/" 2>/dev/null || true',
    'cp -r /root/shardora/nodes_local/temp "$NODES_DIR/temp"',
    'ln -sf "$SHARDORA" "$NODES_DIR/shardora"',
    'cd "$NODES_DIR"',
    'echo "--- genesis -U ---"',
    '"$SHARDORA" -U -N "$GENESIS_NODE_COUNT" -E $(( END_SHARD + 1 ))',
    'echo "--- genesis -S ---"',
    '"$SHARDORA" -S 3 -N "$GENESIS_NODE_COUNT" -E $(( END_SHARD + 1 ))',
    'echo "--- genesis -C ---"',
    '"$SHARDORA" -C',
    'cp "$NODES_DIR/shardora"                         "$PKG_DIR/shardora"',
    'cp "$NODES_DIR/conf/GeoLite2-City.mmdb"      "$PKG_DIR/" 2>/dev/null || true',
    'cp "$NODES_DIR/conf/log4cpp.properties"       "$PKG_DIR/" 2>/dev/null || true',
    f'for shard_id in $(seq {start_shard} {end_shard}); do',
    '    sf="$NODES_DIR/shards${shard_id}"',
    '    [ -f "$sf" ] || { echo "FATAL: $sf not found"; exit 1; }',
    '    "$SHARDORA" -A "$sf" -D "$PKG_DIR/shards${shard_id}"',
    '    cp "$sf" "$PKG_DIR/init_accounts${shard_id}"',
    '    cp -r "$NODES_DIR/shard_db_${shard_id}" "$PKG_DIR/shard_db_${shard_id}"',
    'done',
    'cp -r "$NODES_DIR/temp" "$PKG_DIR/temp"',
    'echo "=== PKG ===" && ls -lh "$PKG_DIR/"',
    'echo GENESIS_DONE',
]
open(gscript, 'w').write('\n'.join(lines) + '\n')
PYEOF

        chmod +x "$gscript"

        docker run --rm \
            --name "shardora-genesis-$$" \
            --volume "${REPO_DIR}:/root/shardora" \
            --volume "${PKG_WORK}:/mnt/out" \
            --volume "${gscript}:/tmp/genesis.sh:ro" \
            "$BUILDER_IMAGE" \
            bash -c "bash /tmp/genesis.sh && cp -r /tmp/spkg /mnt/out/pkg"

        PKG_DIR="$PKG_WORK/pkg"
    fi

    [ -d "$PKG_DIR" ] || { echo "FATAL: pkg 目录未生成" >&2; exit 1; }
    echo "  Genesis 完成，pkg -> $PKG_DIR"
    echo "  pkg 内容: $(ls "$PKG_DIR/")"
}


# ── Step 4: 生成 bootstrap + 为每个节点生成配置目录 ──────────
# 结果: $PKG_WORK/nodes/s<shard>_<i>/ 每节点一个完整目录
step4_configure_nodes() {
    echo ""
    echo "[4/5] 生成 bootstrap + 配置节点目录 ..."

    local leader_tm
    leader_tm=$(date -u -d "+240 days" +%s 2>/dev/null || date -u -v+240d +%s)

    # 构建 bootstrap 字符串
    # 按分片遍历，每台主机 NODES_PER_HOST 个节点，节点编号全局递增
    local bootstrap=""
    for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
        local shards_file="$PKG_DIR/shards${shard_id}"
        [ -f "$shards_file" ] || { echo "FATAL: $shards_file 不存在" >&2; exit 1; }
        local hosts=( ${SHARD_IPS[$shard_id]:-} )
        local node_idx=1
        for ip in "${hosts[@]}"; do
            for (( j=0; j<NODES_PER_HOST; j++ )); do
                local pubkey
                pubkey=$(sed -n "${node_idx}p" "$shards_file" | awk -F'\t' '{print $2}')
                [ -n "$pubkey" ] || { echo "FATAL: shards${shard_id} 第${node_idx}行 pubkey 为空" >&2; exit 1; }
                local tcp_port
                tcp_port=$(calc_port "$shard_id" "$node_idx" "1")
                local entry="${pubkey}:${ip}:${tcp_port}:${shard_id}"
                bootstrap="${bootstrap:+${bootstrap},}${entry}"
                node_idx=$(( node_idx + 1 ))
            done
        done
    done
    echo "  Bootstrap 长度: ${#bootstrap} 字节"

    # 生成每节点目录
    NODES_WORK="$PKG_WORK/nodes"
    rm -rf "$NODES_WORK" && mkdir -p "$NODES_WORK"

    for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
        local shards_file="$PKG_DIR/shards${shard_id}"
        local hosts=( ${SHARD_IPS[$shard_id]:-} )
        local total_shard_nodes=${SHARD_NODE_COUNT[$shard_id]}

        for (( i=1; i<=total_shard_nodes; i++ )); do
            local instance="s${shard_id}_${i}"
            local node_dir="${NODES_WORK}/${instance}"
            local tcp_port http_port ws_port
            tcp_port=$(calc_port  "$shard_id" "$i" "1")
            http_port=$(calc_port "$shard_id" "$i" "2")
            ws_port=$(calc_port   "$shard_id" "$i" "3")
            local prikey
            prikey=$(sed -n "${i}p" "$shards_file" | awk -F'\t' '{print $1}')

            # 从 bootstrap 中反推该节点对应的 IP（按节点序号确定所在主机）
            local host_idx=$(( (i - 1) / NODES_PER_HOST ))
            local node_ip="${hosts[$host_idx]}"

            cp -r "$PKG_DIR/temp" "$node_dir"
            mkdir -p "${node_dir}/log"

            local conf="${node_dir}/conf/shardora.conf"
            sed -i "s|BOOTSTRAP|${bootstrap}|g"               "$conf"
            sed -i "s|PRIVATE_KEY|${prikey}|g"                 "$conf"
            sed -i "s|PUBLIC_IP|${node_ip}|g"                  "$conf"
            sed -i "s|LOCAL_IP|${node_ip}|g"                   "$conf"
            sed -i "s|HTTP_PORT|${http_port}|g"                "$conf"
            sed -i "s|LOCAL_PORT|${tcp_port}|g"                "$conf"
            sed -i "s|TX_WS_PORT|${ws_port}|g"                 "$conf"
            sed -i "s|LEADER_CHANGE_INIT_TM|${leader_tm}|g"   "$conf"
            sed -i "s|FOR_CK_CLIENT|false|g"                   "$conf"

            if (( shard_id == 3 )); then
                local pool_idx=$(( i <= 1 ? i - 1 : -1 ))
                sed -i "s|TEST_POOL_INDEX|${pool_idx}|g"       "$conf"
            else
                sed -i "s|TEST_POOL_INDEX|-1|g"                "$conf"
            fi
            sed -i "s|TEST_TX_TPS|5000|g"                      "$conf"

            if grep -qE 'BOOTSTRAP|PRIVATE_KEY|PUBLIC_IP|LOCAL_IP|HTTP_PORT|LOCAL_PORT|TX_WS_PORT|LEADER_CHANGE' "$conf"; then
                echo "FATAL: $conf 中仍有未替换的占位符" >&2; exit 1
            fi

            # 硬链接二进制
            ln "$PKG_DIR/shardora"                              "${node_dir}/shardora"
            [ -f "$PKG_DIR/txcli"               ] && ln "$PKG_DIR/txcli"               "${node_dir}/txcli"               || true
            [ -f "$PKG_DIR/GeoLite2-City.mmdb"  ] && ln "$PKG_DIR/GeoLite2-City.mmdb"  "${node_dir}/conf/GeoLite2-City.mmdb" || true
            [ -f "$PKG_DIR/log4cpp.properties"  ] && ln "$PKG_DIR/log4cpp.properties"  "${node_dir}/conf/log4cpp.properties"  || true
            cp    "$PKG_DIR"/init_accounts*                 "${node_dir}/"
            cp -r "$PKG_DIR/shard_db_${shard_id}"           "${node_dir}/db"

            # SSL 证书（占位，远端会重新生成）
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout  "${node_dir}/server-key.pem" \
                -out     "${node_dir}/server-cert.pem" \
                -days 365 -subj "/C=CN/O=Shardora/CN=node" 2>/dev/null
            chmod 600 "${node_dir}/server-key.pem"
        done
    done

    # 打成一个 tar 供分发
    PKG_TAR="$PKG_WORK/shardora_pkg.tar.gz"
    tar -czf "$PKG_TAR" -C "$PKG_WORK" nodes pkg
    echo "  节点目录配置完成，打包 -> $PKG_TAR ($(du -sh "$PKG_TAR" | cut -f1))"
}


# ── Step 5: 分发 + 在各远端启动容器 ─────────────────────────
step5_deploy_to_hosts() {
    echo ""
    echo "[5/5] 分发 pkg 并启动容器 ..."

    # 确保远端有 shardora-runtime 镜像（导出/导入或 docker pull）
    # 先把本地镜像保存成 tar，再 scp 到远端加载
    local img_tar="$PKG_WORK/shardora_runtime.tar"
    docker save "$RUNTIME_IMAGE" -o "$img_tar"
    echo "  运行时镜像保存 -> $img_tar ($(du -sh "$img_tar" | cut -f1))"

    for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
        local hosts=( ${SHARD_IPS[$shard_id]:-} )
        local node_idx=1   # 该分片内节点编号，从 1 开始

        for ip in "${hosts[@]}"; do
            local host_start=$node_idx
            local host_end=$(( node_idx + NODES_PER_HOST - 1 ))
            echo ""
            echo "  -> $ip  shard=$shard_id  节点 $host_start ~ $host_end"

            (
                # 1. 上传镜像（如不是本机）
                if ! is_local "$ip"; then
                    scp_to "$ip" "$img_tar" "/tmp/shardora_runtime.tar"
                    ssh_run "$ip" "docker load -i /tmp/shardora_runtime.tar && rm -f /tmp/shardora_runtime.tar"
                fi

                # 2. 上传 pkg tar
                scp_to "$ip" "$PKG_TAR" "/tmp/shardora_pkg.tar.gz"

                # 3. 解包到数据盘
                ssh_run "$ip" "
                    mkdir -p ${NODES_DATA_DIR}
                    rm -rf ${NODES_DATA_DIR}/shardoras ${NODES_DATA_DIR}/pkg ${NODES_DATA_DIR}/nodes
                    tar -xzf /tmp/shardora_pkg.tar.gz -C ${NODES_DATA_DIR}/
                    rm -f /tmp/shardora_pkg.tar.gz
                "
                # 解包后: ${NODES_DATA_DIR}/nodes/s<shard>_<i>/  和 ${NODES_DATA_DIR}/pkg/

                # 4. 在远端重新生成 SSL 证书（使用真实 IP）
                ssh_run "$ip" "
                    for d in ${NODES_DATA_DIR}/nodes/s${shard_id}_*; do
                        [ -d \"\$d\" ] || continue
                        openssl req -x509 -newkey rsa:2048 -nodes \
                            -keyout  \"\$d/server-key.pem\" \
                            -out     \"\$d/server-cert.pem\" \
                            -days 365 -subj \"/C=CN/O=Shardora/CN=${ip}\" 2>/dev/null
                        chmod 600 \"\$d/server-key.pem\"
                    done
                "
                # 也用真实 IP 更新 shardora.conf 中的 public_ip / local_ip
                ssh_run "$ip" "
                    for conf in ${NODES_DATA_DIR}/nodes/s${shard_id}_*/conf/shardora.conf; do
                        [ -f \"\$conf\" ] || continue
                        sed -i \"s|^public_ip = .*|public_ip = ${ip}|\" \"\$conf\"
                        sed -i \"s|^local_ip = .*|local_ip = ${ip}|\"  \"\$conf\"
                    done
                "

                # 5. 停并删除同分片旧容器
                ssh_run "$ip" "
                    docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^shardora-${shard_id}-' | while read name; do
                        docker stop \"\$name\" 2>/dev/null || true
                        docker rm   \"\$name\" 2>/dev/null || true
                    done
                "

                # 6. 为每个节点启动容器
                for (( i=host_start; i<=host_end; i++ )); do
                    local instance="s${shard_id}_${i}"
                    local container="shardora-${shard_id}-${i}"
                    local tcp_port http_port ws_port
                    tcp_port=$(calc_port  "$shard_id" "$i" "1")
                    http_port=$(calc_port "$shard_id" "$i" "2")
                    ws_port=$(calc_port   "$shard_id" "$i" "3")

                    ssh_run "$ip" "
                        docker rm --force ${container} 2>/dev/null || true
                        docker run \
                            --detach \
                            --name    ${container} \
                            --restart unless-stopped \
                            --network host \
                            --volume  ${NODES_DATA_DIR}/nodes/${instance}:/node \
                            --workdir /node \
                            --env     INSTANCE=${instance} \
                            --ulimit  nofile=1000000:1000000 \
                            ${RUNTIME_IMAGE}
                    "
                    # 放通端口
                    open_port_on "$ip" "$tcp_port"
                    open_port_on "$ip" "$http_port"
                    open_port_on "$ip" "$ws_port"
                done

            ) &
            PIDS+=($!)

            node_idx=$(( node_idx + NODES_PER_HOST ))
        done
    done

    wait_all
    echo ""
    echo "  所有主机部署完成，等待 5s 后验证..."
    sleep 5
}

# ── 验证 ──────────────────────────────────────────────────────
verify_deployment() {
    echo ""
    echo "============================================================"
    echo "  部署验证"
    echo "============================================================"
    printf "  %-18s %-14s %-8s %-8s %-8s %-10s\n" "主机" "容器" "Shard" "TCP" "HTTP" "WS"
    printf "  %-18s %-14s %-8s %-8s %-8s %-10s\n" "------------------" "--------------" "------" "------" "------" "----------"

    local ok=0 fail=0
    for shard_id in $(seq "$START_SHARD" "$END_SHARD"); do
        local hosts=( ${SHARD_IPS[$shard_id]:-} )
        local node_idx=1
        for ip in "${hosts[@]}"; do
            for (( j=0; j<NODES_PER_HOST; j++ )); do
                local i=$node_idx
                local container="shardora-${shard_id}-${i}"
                local tcp_port http_port ws_port
                tcp_port=$(calc_port  "$shard_id" "$i" "1")
                http_port=$(calc_port "$shard_id" "$i" "2")
                ws_port=$(calc_port   "$shard_id" "$i" "3")

                local status pid
                status=$(ssh_run "$ip" "docker inspect --format '{{.State.Status}}' ${container} 2>/dev/null || echo unknown" 2>/dev/null || echo "ssh-fail")
                pid=$(ssh_run "$ip"    "docker exec ${container} pgrep -x shardora 2>/dev/null || true" 2>/dev/null || true)

                if [ "$status" = "running" ] && [ -n "$pid" ]; then
                    printf "  %-18s %-14s %-8s %-8s %-8s %-10s\n" "$ip" "$container" "$shard_id" "$tcp_port" "$http_port" "$ws_port"
                    (( ok++ )) || true
                else
                    printf "  %-18s %-14s %-8s %-8s %-8s %-10s\n" "$ip" "$container" "$shard_id" "$tcp_port" "$http_port" "$ws_port  [FAIL status=$status]"
                    ssh_run "$ip" "docker logs --tail 5 ${container} 2>&1 | sed 's/^/    /'" 2>/dev/null || true
                    (( fail++ )) || true
                fi
                node_idx=$(( node_idx + 1 ))
            done
        done
    done

    echo "============================================================"
    echo "  结果: 运行 $ok / 失败 $fail / 总计 $TOTAL_NODES"
    echo "============================================================"
}

# ── 主流程 ───────────────────────────────────────────────────
step1_build_builder_image
step2_build_runtime_image
step3_genesis_and_package
step4_configure_nodes
step5_deploy_to_hosts
verify_deployment

