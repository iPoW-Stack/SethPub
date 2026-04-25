#!/usr/bin/env python3
"""
Monitor block production on Seth node
"""

import sys
import time
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = "127.0.0.1"
PORT = 23001

def get_block_number():
    """Get current block number"""
    url = f"https://{HOST}:{PORT}/eth"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    }
    
    try:
        response = requests.post(url, json=payload, verify=False, timeout=5)
        result = response.json()
        block_hex = result.get("result", "0x0")
        return int(block_hex, 16)
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():
    print("=" * 70)
    print("Seth Block Production Monitor")
    print("=" * 70)
    print(f"Node: {HOST}:{PORT}")
    print()
    
    prev_block = None
    no_change_count = 0
    
    for i in range(30):
        block_num = get_block_number()
        
        if block_num is None:
            print(f"[{i*2}s] ❌ Failed to get block number")
        else:
            if prev_block is None:
                print(f"[{i*2}s] Current block: {block_num}")
            elif block_num > prev_block:
                diff = block_num - prev_block
                print(f"[{i*2}s] Block: {block_num} (+{diff}) ✅ BLOCKS BEING PRODUCED")
                no_change_count = 0
            else:
                no_change_count += 1
                print(f"[{i*2}s] Block: {block_num} (no change for {no_change_count*2}s)")
        
        prev_block = block_num
        
        if i < 29:
            time.sleep(2)
    
    print()
    print("=" * 70)
    
    if no_change_count > 10:
        print("⚠️  WARNING: No new blocks produced in 20+ seconds")
        print()
        print("Possible issues:")
        print("1. Single-node setup not configured for automatic block production")
        print("2. Consensus mechanism requires multiple nodes")
        print("3. Block production interval is very long")
        print()
        print("Suggestions:")
        print("- Check node startup flags (-g -f -s)")
        print("- Check configuration files for block interval")
        print("- Consider starting multiple nodes for consensus")
    else:
        print("✅ Blocks are being produced normally")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
