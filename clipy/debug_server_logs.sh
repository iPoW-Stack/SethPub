#!/bin/bash
# Script to monitor Seth server logs for EIP-1559 transaction debugging

echo "Monitoring Seth server logs for EIP-1559 transactions..."
echo "Press Ctrl+C to stop"
echo ""

# Find the log file (adjust path if needed)
LOG_FILE="/root/seth/logs/seth.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file not found at $LOG_FILE"
    echo "Please update LOG_FILE variable in this script"
    exit 1
fi

# Tail the log and filter for relevant lines
tail -f "$LOG_FILE" | grep -E "EIP-1559|eth_sendRawTransaction|signing_rlp|signing_hash|pubkey_hex|sender="
