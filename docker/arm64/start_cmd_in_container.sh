#!/usr/bin/env bash
# Run start_cmd.sh from the repo checkout (no /root/start_cmd.sh bind mount).
# Use inside an Ubuntu container where temp_cmd_docker.sh already prepared /root/seths.
set -euo pipefail
SETH_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export SETH_SKIP_SYSCTL="${SETH_SKIP_SYSCTL:-1}"
exec bash "${SETH_ROOT}/start_cmd.sh" "$@"
