#!/usr/bin/env bash
# Aligns with simple_remote.sh + temp_cmd.sh + start_cmd.sh for a single Docker host (linux/arm64).
#
# Usage (from repo root):
#   bash docker/arm64/simple_remote_docker.sh <each_nodes_count> <public_ip> <end_shard> [Release|Debug] [first_node_count]
#
# Prerequisites:
#   - docker buildx / Docker Desktop (Apple Silicon uses linux/arm64 natively)
#   - Unpack deployment package to docker/arm64/staging/pkg/ (same layout as remote /root/pkg:
#     shards2, shards3, temp/, seth, txcli, init_accounts*, shard_db_*, GeoLite2-City.mmdb, log4cpp.properties, conf/…)
#   OR place pkg.tar.gz next to staging (see README) and set USE_PKG_TAR=1
#
# Optional env:
#   RUN_IMAGE=seth-node:arm64   — runtime image name (default seth-node:arm64)
#   USE_PKG_TAR=1               — extract docker/arm64/staging/pkg.tar.gz into staging/pkg
#   SETH_SKIP_SYSCTL=1          — passed to start (default on)

set -euo pipefail

EACH="${1:?each_nodes_count}"
PUBLIC_IP="${2:?public_ip (e.g. host.docker.internal or LAN IP)}"
END_SHARD="${3:-3}"
TARGET="${4:-Release}"
FIRST_NODE="${5:-$EACH}"

SETH_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGING="${SETH_ROOT}/docker/arm64/staging"
RUN_IMAGE="${RUN_IMAGE:-seth-node:arm64}"

mkdir -p "${STAGING}/seths"

if [[ "${USE_PKG_TAR:-0}" == "1" && -f "${STAGING}/pkg.tar.gz" ]]; then
  rm -rf "${STAGING}/pkg"
  mkdir -p "${STAGING}"
  tar -xzf "${STAGING}/pkg.tar.gz" -C "${STAGING}"
fi

if [[ ! -d "${STAGING}/pkg" || ! -f "${STAGING}/pkg/seth" ]]; then
  echo "Missing ${STAGING}/pkg (need unpacked pkg like on remote under /root/pkg)."
  echo "Set USE_PKG_TAR=1 and place pkg.tar.gz at ${STAGING}/pkg.tar.gz, or unpack manually."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running."
  exit 1
fi

echo "Building runtime image ${RUN_IMAGE} (linux/arm64)..."
docker buildx build --platform linux/arm64 \
  -f "${SETH_ROOT}/docker/arm64/Dockerfile.runtime" \
  -t "${RUN_IMAGE}" \
  "${SETH_ROOT}"

rm -rf "${STAGING}/seths"/*
mkdir -p "${STAGING}/seths"

if date -u -v+240d +%s >/dev/null 2>&1; then
  leader_init_tm=$(date -u -v+240d +%s)
else
  leader_init_tm=$(date -u -d "+240 days" +%s)
fi

echo "Running temp_cmd_docker + start_cmd_docker in container..."
echo "  public_ip=${PUBLIC_IP} start=1 first_count=${FIRST_NODE} each=${EACH} end_shard=${END_SHARD}"

docker run --rm --platform linux/arm64 \
  --add-host=host.docker.internal:host-gateway \
  -v "${STAGING}/pkg:/root/pkg:ro" \
  -v "${STAGING}/seths:/root/seths" \
  -v "${SETH_ROOT}/start_cmd.sh:/root/start_cmd.sh:ro" \
  -v "${SETH_ROOT}/docker/arm64/temp_cmd_docker.sh:/usr/local/bin/temp_cmd_docker.sh:ro" \
  -v "${SETH_ROOT}/docker/arm64/start_cmd_docker.sh:/usr/local/bin/start_cmd_docker.sh:ro" \
  "${RUN_IMAGE}" \
  bash -lc "set -euo pipefail; \
    chmod +x /usr/local/bin/temp_cmd_docker.sh /usr/local/bin/start_cmd_docker.sh; \
    bash /usr/local/bin/temp_cmd_docker.sh '${PUBLIC_IP}' 1 '${FIRST_NODE}' 0 2 '${END_SHARD}' '${leader_init_tm}'; \
    export SETH_SKIP_SYSCTL=\${SETH_SKIP_SYSCTL:-1}; \
    bash /usr/local/bin/start_cmd_docker.sh '${PUBLIC_IP}' 1 '${FIRST_NODE}' 0 2 '${END_SHARD}'"

echo "Done. Node data under: ${STAGING}/seths"
echo "Tip: publish ports with docker run -p ... or use docker compose (see docker/arm64/README.md)."
